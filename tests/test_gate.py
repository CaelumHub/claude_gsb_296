"""发布门禁单元测试。

覆盖：项目规则版本化、多指标组合判定、历史规则快照、禁止发布审批、
有条件发布确认、放行幂等与审计留痕。
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import DefectManager, ReleaseGateManager, ReportGenerator
from storage import BuildStoreRegistry, StoreRegistry


class FakeCoverage:
    def __init__(self, percent: float):
        self.percent = percent

    def get(self, project_id: str, build_id: str):
        return {"project_id": project_id, "build_id": build_id,
                "percent": self.percent}


class ReleaseGateTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.registry = StoreRegistry(os.path.join(self.tmp.name, "store"))
        self.build_registry = BuildStoreRegistry(os.path.join(self.tmp.name, "builds"))
        self.report = ReportGenerator(self.build_registry)
        self.defects = DefectManager(self.registry)
        self.gate = ReleaseGateManager(
            self.registry, self.build_registry, self.report,
            FakeCoverage(82.0), self.defects)
        self.project_id = "proj_gate"
        self.registry.store("projects").insert({"id": self.project_id, "name": "门禁项目"})

    def tearDown(self):
        self.tmp.cleanup()

    def make_build(self, build_id: str = "b1", total: int = 10,
                   passed: int = 8, failed: int = 1, error: int = 1,
                   priorities=None, status: str = "failed"):
        store = self.build_registry.for_project(self.project_id)
        store.create(build_id, suite_id="suite_1", name="发布构建")
        store.set_total(build_id, total)
        priorities = priorities or {}
        result_no = 0
        for _ in range(passed):
            priority = priorities.get("passed", "P2")
            result_no += 1
            store.record_result(build_id, {
                "case_id": f"pass_{result_no}", "case_name": f"通过{result_no}",
                "group": "g", "priority": priority, "status": "passed",
                "duration": 0.1, "logs": [],
            })
        for status_name, count in (("failed", failed), ("error", error)):
            for i in range(count):
                priority = priorities.get(status_name, "P2")
                result_no += 1
                store.record_result(build_id, {
                    "case_id": f"{status_name}_{i}", "case_name": f"{status_name}{i}",
                    "group": "g", "priority": priority, "status": status_name,
                    "duration": 0.1, "logs": [],
                })
        skipped = total - passed - failed - error
        for i in range(skipped):
            result_no += 1
            store.record_result(build_id, {
                "case_id": f"skip_{i}", "case_name": f"跳过{i}",
                "group": "g", "priority": "P3", "status": "skipped",
                "duration": 0.0, "logs": [],
            })
        store.finish(build_id, status)
        return store.get(build_id)

    def rule(self, conditions, enabled=True):
        return self.gate.update_rule(self.project_id, {
            "name": "测试门禁",
            "enabled": enabled,
            "change_note": "测试规则",
            "conditions": conditions,
        }, actor="qa.owner")


class TestGateEvaluation(ReleaseGateTestBase):
    def test_collects_report_coverage_and_defect_metrics(self):
        self.make_build(total=10, passed=8, failed=1, error=1,
                        priorities={"failed": "P0"})
        self.defects.create(self.project_id, {"title": "d1", "severity": "critical"})
        self.defects.create(self.project_id, {"title": "d2", "severity": "minor",
                                               "status": "closed"})
        build = self.build_registry.for_project(self.project_id).get("b1")
        metrics = self.gate.collect_metrics(self.project_id, build)
        self.assertEqual(metrics["pass_rate"], 80.0)
        self.assertEqual(metrics["failure_count"], 2)
        self.assertEqual(metrics["priority_failures"]["P0"], 1)
        self.assertEqual(metrics["open_defects"], 1)
        self.assertEqual(metrics["severity_defects"]["critical"], 1)
        self.assertEqual(metrics["coverage"], 82.0)

    def test_blocked_has_precedence_over_conditional_and_creates_approval(self):
        self.make_build()
        self.rule([
            {"metric": "pass_rate", "operator": "gte", "threshold": 90,
             "on_fail": "conditional"},
            {"metric": "coverage", "operator": "gte", "threshold": 90,
             "on_fail": "blocked"},
        ])
        decision = self.gate.evaluate_build(self.project_id, "b1", actor="system")
        self.assertEqual(decision["outcome"], "blocked")
        self.assertEqual(decision["rule_version"], 1)
        self.assertIsNotNone(decision["approval_id"])
        approval = self.gate.get_approval(decision["approval_id"])
        self.assertEqual(approval["status"], "pending")
        with self.assertRaises(PermissionError):
            self.gate.release_build(self.project_id, "b1", actor="release.manager")

    def test_conditional_requires_confirmation(self):
        self.make_build(passed=9, failed=1, error=0)
        self.rule([
            {"metric": "pass_rate", "operator": "gte", "threshold": 95,
             "on_fail": "conditional"},
        ])
        decision = self.gate.evaluate_build(self.project_id, "b1", actor="system")
        self.assertEqual(decision["outcome"], "conditional")
        with self.assertRaises(PermissionError):
            self.gate.release_build(self.project_id, "b1", actor="rm")
        release = self.gate.release_build(
            self.project_id, "b1", actor="rm", confirm_conditional=True,
            comment="已确认风险")
        self.assertEqual(release["released_by"], "rm")

    def test_allow_can_release_directly(self):
        self.make_build(total=10, passed=10, failed=0, error=0, status="passed")
        self.rule([
            {"metric": "pass_rate", "operator": "gte", "threshold": 100,
             "on_fail": "blocked"},
            {"metric": "coverage", "operator": "gte", "threshold": 80,
             "on_fail": "blocked"},
        ])
        decision = self.gate.evaluate_build(self.project_id, "b1", actor="system")
        self.assertEqual(decision["outcome"], "allow")
        release = self.gate.release_build(self.project_id, "b1", actor="rm")
        self.assertTrue(release["id"].startswith("gaterel_"))

    def test_disabled_rule_allows_release(self):
        self.make_build()
        self.rule([{"metric": "pass_rate", "operator": "gte", "threshold": 99}],
                  enabled=False)
        decision = self.gate.evaluate_build(self.project_id, "b1", actor="system")
        self.assertEqual(decision["outcome"], "allow")


class TestGateVersioningApprovalAudit(ReleaseGateTestBase):
    def test_rule_change_creates_new_version_and_preserves_historical_decision(self):
        self.make_build(passed=9, failed=1, error=0)
        self.rule([
            {"metric": "pass_rate", "operator": "gte", "threshold": 80,
             "on_fail": "blocked"},
        ])
        first = self.gate.evaluate_build(self.project_id, "b1", actor="ci")
        self.assertEqual(first["outcome"], "allow")

        self.gate.update_rule(self.project_id, {
            "name": "严格门禁", "enabled": True, "change_note": "收紧",
            "conditions": [{"metric": "pass_rate", "operator": "gte",
                            "threshold": 95, "on_fail": "blocked"}],
        }, actor="qa.lead")
        second = self.gate.evaluate_build(
            self.project_id, "b1", actor="qa.lead", force=True)
        self.assertEqual(second["outcome"], "blocked")
        history = self.gate.decisions_for_build(self.project_id, "b1")
        self.assertEqual([d["rule_version"] for d in history], [2, 1])
        self.assertEqual(history[1]["rule_snapshot"]["conditions"][0]["threshold"], 80)
        self.assertEqual(self.gate.get_rule(self.project_id)["version"], 2)

    def test_approval_then_release_and_duplicate_guard(self):
        self.make_build()
        self.rule([{"metric": "pass_rate", "operator": "gte", "threshold": 99}])
        decision = self.gate.evaluate_build(self.project_id, "b1", actor="ci")
        approval = self.gate.decide_approval(
            decision["approval_id"], True, "director", comment="例外批准")
        self.assertEqual(approval["status"], "approved")
        release = self.gate.release_build(
            self.project_id, "b1", actor="release.bot", comment="审批后放行")
        self.assertEqual(release["approval_id"], approval["id"])
        with self.assertRaises(PermissionError):
            self.gate.release_build(self.project_id, "b1", actor="release.bot")

    def test_rejected_approval_still_blocks_release(self):
        self.make_build()
        self.rule([{"metric": "coverage", "operator": "gte", "threshold": 99}])
        decision = self.gate.evaluate_build(self.project_id, "b1", actor="ci")
        self.gate.decide_approval(decision["approval_id"], False, "director",
                                  comment="覆盖率不足")
        with self.assertRaises(PermissionError):
            self.gate.release_build(self.project_id, "b1", actor="rm")

    def test_re_evaluation_supersedes_pending_approval(self):
        self.make_build()
        self.rule([{"metric": "coverage", "operator": "gte", "threshold": 99}])
        first = self.gate.evaluate_build(self.project_id, "b1", actor="ci")
        self.gate.evaluate_build(self.project_id, "b1", actor="ci", force=True)
        old = self.gate.get_approval(first["approval_id"])
        self.assertEqual(old["status"], "superseded")

    def test_all_operator_actions_and_times_are_audited(self):
        self.make_build()
        self.rule([{"metric": "coverage", "operator": "gte", "threshold": 99}])
        decision = self.gate.evaluate_build(self.project_id, "b1", actor="ci")
        self.gate.decide_approval(decision["approval_id"], True, "director",
                                  comment="通过")
        self.gate.release_build(self.project_id, "b1", actor="release.manager")
        actions = [e["action"] for e in self.gate.list_audit(self.project_id)]
        self.assertIn("rule.created", actions)
        self.assertIn("approval.requested", actions)
        self.assertIn("approval.approved", actions)
        self.assertIn("release.granted", actions)
        release_events = [e for e in self.gate.list_audit(self.project_id)
                          if e["action"] == "release.granted"]
        self.assertEqual(release_events[0]["actor"], "release.manager")
        self.assertGreater(release_events[0]["at"], 0)


if __name__ == "__main__":
    unittest.main()
