import hashlib
from collections import defaultdict, deque
from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, InvalidTransition, NotFoundError, PermissionDenied, ValidationError
from .repository import utcnow
from .rules import RuleEngine


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind, payload)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        if entity["kind"] == "linkage_order" and action == "cancel":
            return self.cancel_linkage(actor, entity_id, dict(data or {}).get("reason"))
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)
        updated = self.repository.update_entity(entity_id, expected, next_status, merged)
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        return updated

    def trigger_gas_linkage(self, actor, incident_id, contaminated_area=None, sensor_id=None, alarm_id=None):
        """Create or return the single linkage sheet for one incident/area."""
        self._ensure_role(actor, ("admin", "safety", "dispatcher"))
        incident = self.repository.get_entity(incident_id)
        if not incident or incident["kind"] != "incident":
            raise NotFoundError("incident not found: " + incident_id)
        area = str(contaminated_area or incident["data"].get("area_code", "")).strip()
        if not area:
            raise ValidationError("contaminated_area is required")
        if incident["status"] == "closed":
            raise ConflictError("cannot create linkage order for a closed incident")
        sensor = self.repository.get_entity(sensor_id) if sensor_id else None
        if sensor_id and (not sensor or sensor["kind"] != "sensor"):
            raise NotFoundError("sensor not found: " + sensor_id)

        order_id = "linkage-%s-%s" % (incident_id, area)
        existing = self.repository.get_entity(order_id)
        if existing:
            return existing

        data = self._build_linkage_data(incident, area, sensor_id, alarm_id)
        order, created = self.repository.create_entity_if_absent(
            order_id,
            "linkage_order",
            "active",
            data,
            actor.user_id,
        )
        if not created:
            return order
        self.audit.record(order_id, actor, "trigger_gas_alarm", None, "active", {
            "incident_id": incident_id,
            "contaminated_area": area,
            "affected_areas": data["affected_areas"],
        })
        return self._execute_linkage(order, actor)

    def retry_linkage(self, actor, order_id):
        """Run only pending steps; completed side effects are never repeated."""
        self._ensure_role(actor, ("admin", "safety", "dispatcher"))
        order = self._get_linkage_order(order_id)
        if order["status"] != "active":
            raise InvalidTransition("only active linkage orders can be retried")
        self.audit.record(order_id, actor, "linkage_retry", "active", "active", {})
        return self._execute_linkage(order, actor, refresh=True)

    def cancel_linkage(self, actor, order_id, reason):
        self._ensure_role(actor, ("admin", "safety", "dispatcher"))
        reason = str(reason or "").strip()
        if not reason:
            raise ValidationError("reason is required")
        order = self._get_linkage_order(order_id)
        if order["status"] != "active":
            raise InvalidTransition("only active linkage orders can be cancelled")
        data = dict(order["data"])
        data["cancel_reason"] = reason
        data["cancelled_by"] = actor.user_id
        data["cancelled_at"] = utcnow()
        for step in data["steps"]:
            if step["status"] == "pending":
                step["status"] = "cancelled"
                step["cancelled_by"] = actor.user_id
                step["cancelled_at"] = data["cancelled_at"]
                step["result_reason"] = reason
        updated = self.repository.update_entity(order_id, order["version"], "cancelled", data)
        self.audit.record(order_id, actor, "linkage_cancel", "active", "cancelled", {"reason": reason})
        return updated

    @staticmethod
    def _ensure_role(actor, allowed):
        if actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    def _get_linkage_order(self, order_id):
        order = self.repository.get_entity(order_id)
        if not order or order["kind"] != "linkage_order":
            raise NotFoundError("linkage order not found: " + order_id)
        return order

    def _build_linkage_data(self, incident, area, sensor_id, alarm_id):
        passages = self.repository.list_entities(kind="passage")
        graph = defaultdict(list)
        for passage in passages:
            if passage["status"] not in ("open", "restricted"):
                continue
            start = passage["data"].get("from_location")
            end = passage["data"].get("to_location")
            if start and end:
                graph[start].append((end, passage["id"]))
                graph[end].append((start, passage["id"]))

        affected = {area}
        queue = deque([area])
        while queue:
            current = queue.popleft()
            for neighbour, _passage_id in graph[current]:
                if neighbour not in affected:
                    affected.add(neighbour)
                    queue.append(neighbour)
        affected_areas = sorted(affected)

        passage_steps = []
        for passage in passages:
            start = passage["data"].get("from_location")
            end = passage["data"].get("to_location")
            if start not in affected and end not in affected:
                continue
            if passage["status"] == "blocked":
                passage_steps.append({
                    "id": "isolate-%s" % passage["id"],
                    "phase": 10,
                    "type": "isolate_passage",
                    "target_id": passage["id"],
                    "target_name": "%s <-> %s" % (start, end),
                    "status": "completed",
                    "result_reason": "already blocked",
                    "executed_by": passage["created_by"],
                    "executed_at": passage["created_at"],
                })
            else:
                passage_steps.append({
                    "id": "isolate-%s" % passage["id"],
                    "phase": 10,
                    "type": "isolate_passage",
                    "target_id": passage["id"],
                    "target_name": "%s <-> %s" % (start, end),
                    "status": "pending",
                    "reason": None,
                    "result_reason": None,
                    "executed_by": None,
                    "executed_at": None,
                    "attempts": 0,
                })

        workers = self.repository.list_entities(kind="worker")
        affected_workers = [
            worker for worker in workers
            if worker["data"].get("location_code") in affected
            and worker["status"] in ("active", "missing", "located")
        ]
        fans = self.repository.list_entities(kind="ventilation")
        affected_fans = [fan for fan in fans if fan["data"].get("area_code") in affected]
        steps = list(passage_steps)
        steps.append({
            "id": "verify-fan-capacity",
            "phase": 25,
            "type": "verify_emergency_capacity",
            "target_id": None,
            "target_name": ",".join(affected_areas),
            "status": "pending",
            "reason": None,
            "result_reason": None,
            "executed_by": None,
            "executed_at": None,
            "attempts": 0,
        })
        steps.append({
            "id": "reserve-refuges",
            "phase": 30,
            "type": "reserve_refuges",
            "target_id": None,
            "target_name": ",".join(affected_areas),
            "status": "pending",
            "reason": None,
            "result_reason": None,
            "executed_by": None,
            "executed_at": None,
            "attempts": 0,
        })

        return {
            "incident_id": incident["id"],
            "contaminated_area": area,
            "affected_areas": affected_areas,
            "affected_fan_ids": sorted(fan["id"] for fan in affected_fans),
            "required_capacity": len(affected_workers),
            "sensor_id": sensor_id,
            "alarm_id": alarm_id,
            "reserved_refuge_ids": [],
            "reservations": [],
            "created_from_upgrade": False,
            "steps": steps,
        }

    def _execute_linkage(self, order, actor, refresh=False):
        data = dict(order["data"])
        data["steps"] = [dict(step) for step in data.get("steps", [])]
        for step in data["steps"]:
            step.setdefault("order_id", order["id"])
        before_refresh = {step["id"]: step for step in data["steps"]}
        self._refresh_linkage_steps(order, data)
        added_steps = any(step["id"] not in before_refresh for step in data["steps"])
        if refresh or added_steps:
            order = self.repository.update_entity(order["id"], order["version"], order["status"], data)
            data = dict(order["data"])
            data["steps"] = [dict(step) for step in data["steps"]]
            for step in data["steps"]:
                step.setdefault("order_id", order["id"])
        else:
            added_steps = False

        cache = {}

        def entity(entity_id):
            if entity_id not in cache:
                cache[entity_id] = self.repository.get_entity(entity_id)
            return cache[entity_id]

        pending = sorted(
            (step for step in data["steps"] if step["status"] == "pending"),
            key=lambda item: (item["phase"], item["id"]),
        )
        changed = refresh
        for step in pending:
            step["attempts"] = int(step.get("attempts", 0)) + 1
            try:
                if step["type"] == "isolate_passage":
                    self._execute_passage_step(step, actor, entity, cache)
                elif step["type"] == "start_emergency_fan":
                    self._execute_fan_step(step, actor, entity, cache)
                elif step["type"] == "verify_emergency_capacity":
                    self._execute_capacity_step(step, data, actor, entity, cache)
                elif step["type"] == "reserve_refuges":
                    self._execute_refuge_step(step, data, actor, entity, cache)
                elif step["type"] == "dispatch_missing_worker":
                    self._execute_worker_step(step, data, actor, entity, cache)
                step["status"] = "completed"
                step["executed_by"] = actor.user_id
                step["executed_at"] = utcnow()
                changed = True
            except (ConflictError, InvalidTransition, NotFoundError, PermissionDenied, ValidationError) as exc:
                step["status"] = "pending"
                step["reason"] = str(exc)
                changed = True

            self._save_linkage_progress(order, data, cache, changed=changed)
            if order["status"] != "active":
                return order
            changed = False

        if not [step for step in data["steps"] if step["status"] == "pending"]:
            data["completed_by"] = actor.user_id
            data["completed_at"] = utcnow()
            updated = self.repository.update_entity(order["id"], order["version"], "completed", data)
            self.audit.record(order["id"], actor, "linkage_complete", "active", "completed", {})
            return updated
        return self.repository.update_entity(order["id"], order["version"], "active", data)

    def _refresh_linkage_steps(self, order, data):
        """Add targets that became relevant after the first alarm attempt."""
        affected = set(data["affected_areas"])
        steps_by_id = {step["id"]: step for step in data["steps"]}
        fans = self.repository.list_entities(kind="ventilation")
        affected_fans = [fan for fan in fans if fan["data"].get("area_code") in affected]
        data["affected_fan_ids"] = sorted(fan["id"] for fan in affected_fans)
        for fan in affected_fans:
            if str(fan["data"].get("fan_type", "")).lower() != "emergency":
                continue
            step_id = "start-fan-%s" % fan["id"]
            if step_id not in steps_by_id:
                data["steps"].append({
                    "id": step_id,
                    "phase": 20,
                    "type": "start_emergency_fan",
                    "target_id": fan["id"],
                    "target_name": fan["data"].get("name", fan["id"]),
                    "status": "pending",
                    "reason": None,
                    "result_reason": None,
                    "executed_by": None,
                    "executed_at": None,
                    "attempts": 0,
                })

        workers = self.repository.list_entities(kind="worker")
        for worker in workers:
            if worker["data"].get("location_code") not in affected or worker["status"] != "missing":
                continue
            step_id = "dispatch-missing-%s" % worker["id"]
            completed_without_step = step_id not in steps_by_id and any(
                task["data"].get("dedupe_key") == "linkage-%s-missing-%s" % (data["incident_id"], worker["id"])
                for task in self.repository.list_entities(kind="task")
            )
            if step_id not in steps_by_id and not completed_without_step:
                data["steps"].append({
                    "id": step_id,
                    "phase": 40,
                    "type": "dispatch_missing_worker",
                    "target_id": worker["id"],
                    "target_name": worker["data"].get("name", worker["id"]),
                    "status": "pending",
                    "reason": None,
                    "result_reason": None,
                    "executed_by": None,
                    "executed_at": None,
                    "attempts": 0,
                })
        data["steps"].sort(key=lambda item: (item.get("phase", 999), item["id"]))

    def _execute_passage_step(self, step, actor, get_entity, cache):
        passage = get_entity(step["target_id"])
        if passage["status"] == "blocked":
            step["result_reason"] = "already blocked"
            return
        before_status = passage["status"]
        if before_status not in ("open", "restricted"):
            raise ConflictError("passage status %s cannot be blocked" % before_status)
        payload = dict(passage["data"])
        payload["blocked_by"] = actor.user_id
        payload["linkage_order_id"] = step.get("order_id")
        updated = self.repository.update_entity(passage["id"], passage["version"], "blocked", payload)
        cache[passage["id"]] = updated
        self.audit.record(passage["id"], actor, "block", before_status, "blocked", {"linkage": True})
        step["result_reason"] = "blocked"

    def _execute_fan_step(self, step, actor, get_entity, cache):
        fan = get_entity(step["target_id"])
        if fan["status"] not in ("running", "degraded", "stopped"):
            raise ConflictError("emergency fan status %s cannot start" % fan["status"])
        if fan["status"] == "running" and fan["data"].get("mode") == "emergency":
            step["result_reason"] = "already running in emergency mode"
            return
        before_status = fan["status"]
        payload = dict(fan["data"])
        payload["mode"] = "emergency"
        payload["emergency_started_by"] = actor.user_id
        updated = self.repository.update_entity(fan["id"], fan["version"], "running", payload)
        cache[fan["id"]] = updated
        self.audit.record(fan["id"], actor, "emergency_start", before_status, "running", {"linkage": True})
        step["result_reason"] = "emergency fan running"

    def _execute_capacity_step(self, step, data, actor, get_entity, cache):
        affected = set(data["affected_areas"])
        emergency = []
        for fan_id in data["affected_fan_ids"]:
            fan = get_entity(fan_id)
            if not fan or fan["data"].get("area_code") not in affected:
                continue
            if str(fan["data"].get("fan_type", "")).lower() != "emergency":
                continue
            if fan["status"] not in ("running", "degraded", "stopped"):
                raise ConflictError("emergency fan %s is %s" % (fan["id"], fan["status"]))
            emergency.append(fan)
        if not emergency:
            raise ConflictError("no emergency fan available in affected areas")
        total = sum(float(fan["data"].get("capacity", 0) or 0) for fan in emergency if fan["status"] == "running")
        if total < float(data.get("required_capacity", 0) or 0):
            raise ConflictError("emergency fan capacity %s is below required %s" % (total, data.get("required_capacity", 0)))
        step["result_reason"] = "capacity %s meets %s personnel" % (int(total), data["required_capacity"])

    def _execute_refuge_step(self, step, data, actor, get_entity, cache):
        affected = set(data["affected_areas"])
        at_risk = [
            worker for worker in self.repository.list_entities(kind="worker")
            if worker["data"].get("location_code") in affected
            and worker["status"] in ("active", "missing", "located")
        ]
        data["required_capacity"] = len(at_risk)
        existing_reserved = set(data.get("reserved_refuge_ids", []))
        if existing_reserved:
            step["result_reason"] = "already reserved"
            return
        required = len(at_risk)
        refuges = [
            refuge for refuge in self.repository.list_entities(kind="refuge")
            if refuge["data"].get("location_code") in affected and refuge["status"] == "available"
        ]
        remaining = required
        plan = []
        for refuge in refuges:
            if remaining <= 0:
                break
            capacity = int(refuge["data"].get("capacity", 0) or 0)
            if capacity <= 0:
                continue
            take = min(capacity, remaining)
            plan.append((refuge, take))
            remaining -= take
        if remaining > 0:
            raise ConflictError("refuge capacity is short by %s" % remaining)

        updates = []
        now = utcnow()
        for refuge, take in plan:
            payload = dict(refuge["data"])
            payload["occupied"] = take
            payload["occupied_by_linkage"] = step.get("order_id")
            payload["occupied_at"] = now
            updates.append((refuge["id"], refuge["version"], "occupied", payload))
        versions = self.repository.update_many_entities(updates)
        for refuge, take in plan:
            cache[refuge["id"]] = self.repository.get_entity(refuge["id"])
            self.audit.record(refuge["id"], actor, "occupy", "available", "occupied", {
                "linkage": True,
                "occupied": take,
            })
            data.setdefault("reservations", []).append({"refuge_id": refuge["id"], "occupied": take})
        data["reserved_refuge_ids"] = [refuge["id"] for refuge, _take in plan]
        step["result_reason"] = "reserved %s refuge seats" % required

    def _execute_worker_step(self, step, data, actor, get_entity, cache):
        worker = get_entity(step["target_id"])
        if worker["status"] != "missing":
            step["result_reason"] = "worker no longer missing"
            return
        dedupe_key = "linkage-%s-missing-%s" % (data["incident_id"], worker["id"])
        existing_tasks = self.repository.find_entities("task", "dedupe_key", dedupe_key)
        if existing_tasks:
            task = existing_tasks[0]
            step["result_reason"] = "existing task %s" % task["id"]
            return
        task_id = "task-link-%s-%s" % (data["incident_id"], worker["id"])
        task_data = {
            "incident_id": data["incident_id"],
            "task_type": "rescue",
            "target": worker["id"],
            "dedupe_key": dedupe_key,
            "summary": "Check and guide missing worker during gas linkage",
            "created_by_linkage": step.get("order_id"),
        }
        task, created = self.repository.create_entity_if_absent(
            task_id, "task", "proposed", task_data, actor.user_id
        )
        if not created:
            step["result_reason"] = "existing task %s" % task_id
            return
        self.audit.record(task_id, actor, "create", None, "proposed", {"kind": "task", "linkage": True})
        payload = dict(task["data"])
        payload["assigned_by"] = actor.user_id
        task = self.repository.update_entity(task_id, task["version"], "assigned", payload)
        cache[task_id] = task
        self.audit.record(task_id, actor, "assign", "proposed", "assigned", {"linkage": True})
        step["result_reason"] = "task %s assigned" % task_id

    def _save_linkage_progress(self, order, data, cache, changed=True):
        if not changed:
            return
        updated = self.repository.update_entity(order["id"], order["version"], "active", data)
        order["version"] = updated["version"]
        order["status"] = updated["status"]
        order["data"] = updated["data"]

    def merge_offline(self, actor, records):
        """Merge field records by a stable (source_id, record_id) identity."""
        if not isinstance(records, list):
            raise ValidationError("records must be a list")
        created = []
        for raw in records:
            if not isinstance(raw, dict):
                raise ValidationError("each offline record must be an object")
            source_id = str(raw.get("source_id", "")).strip()
            record_id = str(raw.get("record_id", "")).strip()
            if not source_id or not record_id:
                raise ValidationError("source_id and record_id are required")
            digest = hashlib.sha256((source_id + "\0" + record_id).encode("utf-8")).hexdigest()[:32]
            entity_id = "offline-" + digest
            existing = self.repository.get_entity(entity_id)
            if existing:
                created.append(existing)
                continue
            payload = dict(raw)
            self.rules.validate_create(actor, "offline_record", payload, self._lookup)
            entity = self.repository.create_entity(
                entity_id,
                "offline_record",
                self.rules.initial_status("offline_record", payload),
                payload,
                actor.user_id,
            )
            self.audit.record(entity_id, actor, "merge_offline", None, entity["status"], {"source_id": source_id, "record_id": record_id})
            created.append(entity)
        return created

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
