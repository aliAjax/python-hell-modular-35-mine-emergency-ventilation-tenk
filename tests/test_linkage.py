import tempfile
import unittest
from pathlib import Path

from src.domain import Actor, InvalidTransition
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


class LinkageTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.service = DomainService(SQLiteRepository(Path(self.tmp.name) / "test.db"), RuleEngine())
        self.actor = Actor("dispatch-1", "dispatcher")
        self.admin = Actor("admin", "admin")

    def tearDown(self):
        self.tmp.cleanup()

    def create(self, kind, data, actor=None):
        return self.service.create(actor or self.admin, kind, data)

    def act(self, entity, action, data=None, actor=None):
        if data is not None and not isinstance(data, dict):
            actor = data
            data = {}
        return self.service.transition(actor or self.actor, entity["id"], action, data or {})

    def prepare(self, emergency_a_capacity=10, refuge_capacity=2):
        incident = self.create("incident", {
            "area_code": "A",
            "severity": "critical",
            "summary": "gas alarm",
        }, Actor("safety-1", "safety"))
        p1 = self.create("passage", {"from_location": "A", "to_location": "B", "width_m": 3})
        p2 = self.create("passage", {"from_location": "B", "to_location": "C", "width_m": 3})
        self.create("passage", {"from_location": "D", "to_location": "E", "width_m": 3})
        self.create("worker", {"name": "Active Worker", "location_code": "A", "team": "T1"})
        missing = self.create("worker", {"name": "Missing Worker", "location_code": "B", "team": "T1"})
        missing = self.act(missing, "mark_missing")
        fan_a = self.create("ventilation", {
            "name": "emergency-a", "area_code": "A", "capacity": emergency_a_capacity,
            "fan_type": "emergency",
        }, Actor("safety-1", "safety"))
        fan_a = self.act(fan_a, "stop", Actor("safety-1", "safety"))
        refuge = self.create("refuge", {
            "location_code": "C", "capacity": refuge_capacity, "name": "refuge-c",
        }, Actor("safety-1", "safety"))
        outside_fan = self.create("ventilation", {
            "name": "normal-d", "area_code": "D", "capacity": 5, "fan_type": "normal",
        }, Actor("safety-1", "safety"))
        return incident, p1, p2, missing, fan_a, refuge, outside_fan

    def steps(self, order):
        return {step["type"] + ":" + str(step.get("target_id")): step for step in order["data"]["steps"]}

    def test_linkage_is_idempotent_and_executes_sequence(self):
        incident, p1, p2, missing, fan_a, refuge, outside_fan = self.prepare()
        order = self.service.trigger_gas_linkage(self.actor, incident["id"], "A")
        duplicate = self.service.trigger_gas_linkage(self.actor, incident["id"], "A", alarm_id="second")

        self.assertEqual(duplicate["id"], order["id"])
        self.assertEqual(duplicate["version"], order["version"])
        self.assertEqual(order["status"], "completed")
        self.assertEqual(order["data"]["affected_areas"], ["A", "B", "C"])
        self.assertEqual(order["data"]["affected_fan_ids"], [fan_a["id"]])
        self.assertNotIn(outside_fan["id"], order["data"]["affected_fan_ids"])

        self.assertEqual(self.service.get(p1["id"])["status"], "blocked")
        self.assertEqual(self.service.get(p2["id"])["status"], "blocked")
        self.assertEqual(self.service.get(fan_a["id"])["status"], "running")
        self.assertEqual(self.service.get(fan_a["id"])["data"]["mode"], "emergency")
        occupied_refuge = self.service.get(refuge["id"])
        self.assertEqual(occupied_refuge["status"], "occupied")
        self.assertEqual(occupied_refuge["data"]["occupied"], 2)

        steps = self.steps(order)
        self.assertEqual(steps["isolate_passage:" + p1["id"]]["status"], "completed")
        self.assertEqual(steps["isolate_passage:" + p1["id"]]["executed_by"], "dispatch-1")
        self.assertTrue(steps["isolate_passage:" + p1["id"]]["executed_at"])
        self.assertEqual(steps["dispatch_missing_worker:" + missing["id"]]["status"], "completed")
        tasks = self.service.list("task")
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["status"], "assigned")
        self.assertEqual(tasks[0]["data"]["dedupe_key"], "linkage-%s-missing-%s" % (incident["id"], missing["id"]))

        repeated_alarm = self.service.trigger_gas_linkage(self.actor, incident["id"], "A", alarm_id="repeated")
        self.assertEqual(repeated_alarm["id"], order["id"])
        self.assertEqual(len(self.service.list("task")), 1)
        self.assertEqual(self.service.get(refuge["id"])["data"]["occupied"], 2)

    def test_completed_isolation_is_not_rolled_back_and_retry_completes_later_capacity(self):
        incident, _p1, _p2, _missing, fan_a, _refuge, _outside = self.prepare(
            emergency_a_capacity=1,
            refuge_capacity=1,
        )
        first = self.service.trigger_gas_linkage(self.actor, incident["id"], "A")
        self.assertEqual(first["status"], "active")
        steps = self.steps(first)
        self.assertEqual(steps["isolate_passage:" + _p1["id"]]["status"], "completed")
        self.assertEqual(steps["verify_emergency_capacity:None"]["status"], "pending")
        self.assertIn("capacity", steps["verify_emergency_capacity:None"]["reason"])
        self.assertEqual(self.service.get(_p1["id"])["status"], "blocked")
        self.assertEqual(self.service.get(_refuge["id"])["status"], "available")

        added_fan = self.create("ventilation", {
            "name": "emergency-b", "area_code": "B", "capacity": 1, "fan_type": "emergency",
        }, Actor("safety-1", "safety"))
        added_refuge = self.create("refuge", {"location_code": "B", "capacity": 1}, Actor("safety-1", "safety"))
        completed = self.service.retry_linkage(self.actor, self.steps(first) and first["id"])

        self.assertEqual(completed["status"], "completed")
        self.assertEqual(self.service.get(added_fan["id"])["data"]["mode"], "emergency")
        self.assertEqual(self.service.get(added_refuge["id"])["status"], "occupied")
        self.assertEqual(self.service.get(_p1["id"])["status"], "blocked")
        self.assertEqual(len(self.service.list("task")), 1)

    def test_close_requires_completed_or_cancelled_linkage_and_affected_fan_restore(self):
        incident, _p1, _p2, _missing, fan_a, _refuge, _outside = self.prepare(emergency_a_capacity=1)
        order = self.service.trigger_gas_linkage(self.actor, incident["id"], "A")
        self.assertEqual(order["status"], "active")

        added_fan = self.create("ventilation", {
            "name": "emergency-b", "area_code": "B", "capacity": 1, "fan_type": "emergency",
        }, Actor("safety-1", "safety"))
        added_refuge = self.create("refuge", {"location_code": "B", "capacity": 1}, Actor("safety-1", "safety"))
        self.service.retry_linkage(self.actor, order["id"])
        self.service.transition(Actor("safety-1", "safety"), added_fan["id"], "stop")

        for action in ("begin_evacuation", "search", "stabilize", "recover"):
            incident = self.service.transition(Actor("safety-1", "safety"), incident["id"], action)
        with self.assertRaises(Exception):
            self.service.transition(
                Actor("safety-1", "safety"), incident["id"], "close", {"summary": "done"}
            )
        # A fan outside the affected area must not block the linkage-scoped close.
        self.service.transition(Actor("safety-1", "safety"), _outside["id"], "stop")
        self.service.transition(Actor("safety-1", "safety"), added_fan["id"], "restore", {
            "tested_at": "2026-09-29T10:00:00Z",
        })
        # The missing-worker task and worker still have to be resolved before closing.
        task = self.service.list("task")[0]
        self.service.transition(Actor("safety-1", "safety"), task["id"], "cancel", {"reason": "manual response"})
        worker = self.service.get(_missing["id"])
        self.service.transition(Actor("safety-1", "safety"), worker["id"], "locate", {"located_at": "2026-09-29T10:01:00Z"})
        worker = self.service.get(_missing["id"])
        self.service.transition(Actor("safety-1", "safety"), worker["id"], "rescue", {"incident_id": incident["id"]})
        closed = self.service.transition(
            Actor("safety-1", "safety"), incident["id"], "close", {"summary": "all clear"}
        )
        self.assertEqual(closed["status"], "closed")

    def test_cancel_marks_pending_steps_and_completed_retry_is_rejected(self):
        incident, _p1, _p2, _missing, _fan, _refuge, _outside = self.prepare(emergency_a_capacity=1)
        order = self.service.trigger_gas_linkage(self.actor, incident["id"], "A")
        self.assertEqual(order["status"], "active")
        cancelled = self.service.transition(
            self.actor, order["id"], "cancel", {"reason": "manual override"}
        )
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["data"]["cancelled_by"], "dispatch-1")
        self.assertTrue(all(step["status"] != "pending" for step in cancelled["data"]["steps"]))
        with self.assertRaises(InvalidTransition):
            self.service.retry_linkage(self.actor, order["id"])

    def test_historical_incident_keeps_global_ventilation_close_rule(self):
        incident = self.create("incident", {
            "area_code": "old", "severity": "high", "summary": "before linkage",
        }, Actor("safety-1", "safety"))
        fan = self.create("ventilation", {"name": "fan", "area_code": "other", "capacity": 2}, Actor("safety-1", "safety"))
        self.service.transition(Actor("safety-1", "safety"), fan["id"], "stop")
        for action in ("begin_evacuation", "search", "stabilize", "recover"):
            incident = self.service.transition(Actor("safety-1", "safety"), incident["id"], action)
        with self.assertRaises(Exception):
            self.service.transition(
                Actor("safety-1", "safety"), incident["id"], "close", {"summary": "done"}
            )


if __name__ == "__main__":
    unittest.main()
