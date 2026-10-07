"""发布门禁测试。

覆盖：规则校验与版本化、四类指标判定（通过率 / 失败用例等级 / 覆盖率 /
未关闭缺陷）、三档判定结果、审批放行流、操作留痕、历史规则追溯，
以及调度器构建结束后的自动判定。
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import (CoverageAnalyzer, DefectManager, EnvironmentManager,
                    GateManager, NotificationManager, ReportGenerator,
                    Scheduler, TestExecutor, new_id)
from storage import BuildStoreRegistry, StoreRegistry


def _make_stack(data_root):
    registry = StoreRegistry(os.path.join(data_root, "store"), shard_size=50)
    builds = BuildStoreRegistry(os.path.join(data_root, "builds"))
    coverage = CoverageAnalyzer(builds)
    defects = DefectManager(registry)
    notify = NotificationManager(registry)
    gate = GateManager(registry, builds, coverage, defects, notify)
    return registry, builds, coverage, defects, notify, gate


def _make_build(builds, project_id, results):
    """造一场已结束的构建。``results`` 为 ``(status, priority)`` 列表。"""
    store = builds.for_project(project_id)
    build_id = new_id("build")
    store.create(build_id, suite_id="suite_1", env_id="env_1", name="门禁测试")
    store.set_total(build_id, len(results))
    for i, (status, priority) in enumerate(results):
        store.record_result(build_id, {
            "case_id": f"case_{i}", "case_name": f"用例{i}", "group": "g",
            "priority": priority, "status": status, "duration": 0.01,
            "steps": [], "assertions": [], "logs": [],
        })
    failed = sum(1 for s, _ in results if s in ("failed", "error", "timeout"))
    store.finish(build_id, "failed" if failed else "passed")
    return build_id


def _pass_rule(**over):
    """只含通过率条件的规则，避免覆盖率随机波动影响判定。"""
    rule = {"name": "测试规则", "conditions": [
        {"metric": "pass_rate", "op": "lt", "value": 90, "level": "deny"},
        {"metric": "pass_rate", "op": "lt", "value": 100, "level": "conditional"},
    ]}
    rule.update(over)
    return rule


class TestGateRules(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        (self.registry, self.builds, self.coverage, self.defects,
         self.notify, self.gate) = _make_stack(self.tmp.name)
        self.pid = self.registry.store("projects").insert({"name": "P"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_condition_validation(self):
        bad = [
            {"metric": "nope", "op": "lt", "value": 1, "level": "deny"},
            {"metric": "pass_rate", "op": "??", "value": 1, "level": "deny"},
            {"metric": "pass_rate", "op": "lt", "value": 1, "level": "block"},
            {"metric": "pass_rate", "op": "lt", "value": "abc", "level": "deny"},
            {"metric": "failed_cases", "priority": "P9", "op": "gt",
             "value": 0, "level": "deny"},
            {"metric": "open_defects", "severity": "??", "op": "gt",
             "value": 0, "level": "deny"},
        ]
        for cond in bad:
            result = self.gate.create_rule(self.pid, {"conditions": [cond]})
            self.assertIn("error", result, cond)
        # 空条件 / 非数组
        self.assertIn("error", self.gate.create_rule(self.pid, {"conditions": []}))
        self.assertIn("error", self.gate.create_rule(self.pid, {}))

    def test_rule_versioning(self):
        r1 = self.gate.create_rule(self.pid, _pass_rule(), actor="张三")
        self.assertEqual(r1["version"], 1)
        r2 = self.gate.create_rule(self.pid, _pass_rule(name="v2 规则"),
                                   actor="李四")
        self.assertEqual(r2["version"], 2)

        current = self.gate.current_rule(self.pid)
        self.assertEqual(current["version"], 2)
        self.assertEqual(current["name"], "v2 规则")

        # 历史版本仍可查询
        old = self.gate.get_rule_version(self.pid, 1)
        self.assertIsNotNone(old)
        self.assertEqual(old["created_by"], "张三")
        self.assertEqual(len(self.gate.rule_versions(self.pid)), 2)

        # 规则变更留痕
        events = [e for e in self.gate.events(self.pid)
                  if e["action"] == "rule_created"]
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["actor"], "李四")  # 倒序，最新在前
        self.assertTrue(all(e.get("created_at") for e in events))


class TestGateEvaluation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        (self.registry, self.builds, self.coverage, self.defects,
         self.notify, self.gate) = _make_stack(self.tmp.name)
        self.pid = self.registry.store("projects").insert({"name": "P"})

    def tearDown(self):
        self.tmp.cleanup()

    def test_no_rule_returns_error(self):
        bid = _make_build(self.builds, self.pid, [("passed", "P1")] * 5)
        result = self.gate.evaluate_build(self.pid, bid)
        self.assertIsNone(result["decision"])
        self.assertIn("error", result)

    def test_allow_auto_released(self):
        self.gate.create_rule(self.pid, _pass_rule())
        bid = _make_build(self.builds, self.pid, [("passed", "P1")] * 10)
        ev = self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(ev["decision"], "allow")
        self.assertEqual(ev["violations"], [])
        self.assertEqual(ev["release"]["status"], "released")
        self.assertEqual(ev["release"]["source"], "auto")
        self.assertEqual(ev["metrics"]["pass_rate"], 100.0)

    def test_conditional_then_confirm_release(self):
        self.gate.create_rule(self.pid, _pass_rule())
        results = [("passed", "P1")] * 9 + [("failed", "P2")]
        bid = _make_build(self.builds, self.pid, results)
        ev = self.gate.evaluate_build(self.pid, bid)
        # 通过率 90%，未低于 90 不禁止，但 < 100 → 有条件发布
        self.assertEqual(ev["decision"], "conditional")
        self.assertEqual(ev["release"]["status"], "conditional")

        # 非 conditional 状态不能确认；conditional 确认后放行并留痕
        rel = self.gate.confirm_release(self.pid, bid, actor="王五", note="风险可接受")
        self.assertEqual(rel["status"], "released")
        self.assertEqual(rel["source"], "confirm")
        again = self.gate.confirm_release(self.pid, bid, actor="王五")
        self.assertIn("error", again)
        events = [e for e in self.gate.events(self.pid, build_id=bid)
                  if e["action"] == "released"]
        self.assertEqual(events[0]["actor"], "王五")

    def test_deny_blocks_and_creates_approval(self):
        self.gate.create_rule(self.pid, _pass_rule())
        results = [("passed", "P1")] * 8 + [("failed", "P2")] * 2  # 80%
        bid = _make_build(self.builds, self.pid, results)
        ev = self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(ev["decision"], "deny")
        self.assertEqual(ev["release"]["status"], "blocked")
        self.assertTrue(any(v["level"] == "deny" for v in ev["violations"]))

        # 自动发起审批单，且重复判定不重复发起
        approvals = self.gate.approvals(self.pid, status="pending")
        self.assertEqual(len(approvals), 1)
        self.assertEqual(approvals[0]["build_id"], bid)
        self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(len(self.gate.approvals(self.pid, status="pending")), 1)

    def test_failed_cases_by_priority(self):
        self.gate.create_rule(self.pid, {"conditions": [
            {"metric": "failed_cases", "priority": "P0", "op": "gt",
             "value": 0, "level": "deny"},
        ]})
        # P2 失败不触发 P0 条件
        bid1 = _make_build(self.builds, self.pid,
                           [("passed", "P1")] * 4 + [("failed", "P2")])
        self.assertEqual(self.gate.evaluate_build(self.pid, bid1)["decision"],
                         "allow")
        # P0 失败触发禁止
        bid2 = _make_build(self.builds, self.pid,
                           [("passed", "P1")] * 4 + [("failed", "P0")])
        ev = self.gate.evaluate_build(self.pid, bid2)
        self.assertEqual(ev["decision"], "deny")
        self.assertEqual(ev["metrics"]["failed_by_priority"], {"P0": 1})

    def test_open_defects_counts_and_severity(self):
        self.gate.create_rule(self.pid, {"conditions": [
            {"metric": "open_defects", "severity": "blocker", "op": "gt",
             "value": 0, "level": "deny"},
            {"metric": "open_defects", "op": "gt", "value": 2,
             "level": "conditional"},
        ]})
        # 已关闭缺陷不计入
        self.defects.create(self.pid, {"title": "已关闭", "status": "closed",
                                       "severity": "blocker"})
        self.defects.create(self.pid, {"title": "未关闭1", "severity": "major"})
        self.defects.create(self.pid, {"title": "未关闭2", "severity": "minor",
                                       "status": "in_progress"})
        bid = _make_build(self.builds, self.pid, [("passed", "P1")] * 5)
        ev = self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(ev["metrics"]["open_defects"], 2)
        self.assertEqual(ev["decision"], "allow")  # 无 blocker，总数未超 2

        self.defects.create(self.pid, {"title": " blocker 缺陷 ",
                                       "severity": "blocker"})
        ev2 = self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(ev2["metrics"]["open_defects"], 3)
        self.assertEqual(ev2["decision"], "deny")

    def test_approval_flow(self):
        self.gate.create_rule(self.pid, _pass_rule())
        bid = _make_build(self.builds, self.pid, [("failed", "P1")] * 5)
        self.gate.evaluate_build(self.pid, bid)
        approval = self.gate.approvals(self.pid, status="pending")[0]

        # 审批通过 → 放行，留痕操作人与时间
        decided = self.gate.decide_approval(approval["id"], actor="赵六",
                                            approve=True, note="紧急修复已确认")
        self.assertEqual(decided["status"], "approved")
        self.assertEqual(decided["decided_by"], "赵六")
        self.assertIsNotNone(decided["decided_at"])
        state = self.gate.release_state(self.pid, bid)
        self.assertEqual(state["release"]["status"], "approved")
        self.assertEqual(state["release"]["source"], "approval")

        # 已处理的审批单不能重复审批
        again = self.gate.decide_approval(approval["id"], actor="赵六",
                                          approve=False)
        self.assertIn("error", again)

        # 人工终态不被后续自动判定推翻
        self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(self.gate.release_state(self.pid, bid)["release"]["status"],
                         "approved")

    def test_approval_reject_keeps_blocked(self):
        self.gate.create_rule(self.pid, _pass_rule())
        bid = _make_build(self.builds, self.pid, [("failed", "P1")] * 5)
        self.gate.evaluate_build(self.pid, bid)
        approval = self.gate.approvals(self.pid, status="pending")[0]
        self.gate.decide_approval(approval["id"], actor="赵六", approve=False,
                                  note="质量不达标")
        state = self.gate.release_state(self.pid, bid)
        self.assertEqual(state["release"]["status"], "rejected")

    def test_history_traceable_across_rule_versions(self):
        # v1：通过率 < 90 禁止；v2：通过率 < 50 才禁止
        self.gate.create_rule(self.pid, _pass_rule())
        bid = _make_build(self.builds, self.pid,
                          [("passed", "P1")] * 8 + [("failed", "P1")] * 2)
        ev1 = self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(ev1["decision"], "deny")
        self.assertEqual(ev1["rule_version"], 1)

        self.gate.create_rule(self.pid, {"conditions": [
            {"metric": "pass_rate", "op": "lt", "value": 50, "level": "deny"},
        ]})
        ev2 = self.gate.evaluate_build(self.pid, bid)
        self.assertEqual(ev2["decision"], "allow")
        self.assertEqual(ev2["rule_version"], 2)

        # 按历史规则版本追溯当时的判定
        v1_evals = self.gate.evaluations(self.pid, rule_version=1)
        self.assertEqual(len(v1_evals), 1)
        self.assertEqual(v1_evals[0]["decision"], "deny")
        # 判定记录自带规则快照，即使不看规则表也能还原判定依据
        self.assertEqual(v1_evals[0]["rule_snapshot"]["conditions"][0]["value"], 90)
        v2_evals = self.gate.evaluations(self.pid, rule_version=2)
        self.assertEqual(v2_evals[0]["decision"], "allow")

    def test_events_audit_trail(self):
        self.gate.create_rule(self.pid, _pass_rule(), actor="张三")
        bid = _make_build(self.builds, self.pid, [("failed", "P1")] * 5)
        self.gate.evaluate_build(self.pid, bid, actor="system")
        approval = self.gate.approvals(self.pid, status="pending")[0]
        self.gate.decide_approval(approval["id"], actor="赵六", approve=True)

        actions = [e["action"] for e in self.gate.events(self.pid, build_id=bid)]
        for expected in ("evaluated", "approval_requested", "approval_approved"):
            self.assertIn(expected, actions)
        for e in self.gate.events(self.pid):
            self.assertTrue(e.get("actor"))
            self.assertTrue(e.get("created_at"))


class TestGateWithScheduler(unittest.TestCase):
    """构建结束后调度器自动执行门禁判定。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        (self.registry, self.builds, self.coverage, self.defects,
         self.notify, self.gate) = _make_stack(self.tmp.name)
        env_mgr = EnvironmentManager(self.registry, self.tmp.name)
        report = ReportGenerator(self.builds)
        self.sched = Scheduler(self.registry, self.builds, TestExecutor(),
                               env_mgr, report, self.coverage, self.defects,
                               self.notify, max_build_workers=2,
                               max_case_workers=4, tick_seconds=0.2,
                               gate_manager=self.gate)
        self.env_mgr = env_mgr

    def tearDown(self):
        self.sched.shutdown()
        self.tmp.cleanup()

    def test_build_auto_evaluated(self):
        pid = self.registry.store("projects").insert({"name": "P"})
        env = self.env_mgr.create(pid, {"name": "dev",
                                        "config": {"latency_ms": 0, "fail_rate": 0.0}})
        cases = self.registry.store("cases")
        ids = [cases.insert({
            "id": f"case_{i}", "project_id": pid, "name": f"用例{i}",
            "priority": "P2", "tags": ["g"], "timeout": 30,
            "steps": [{"action": "assert", "type": "equals",
                       "actual": "1", "expected": 1}],
        }) for i in range(6)]
        self.registry.store("suites").insert({
            "id": "suite_1", "project_id": pid, "name": "冒烟",
            "env_id": env["id"], "case_ids": ids,
        })
        self.gate.create_rule(pid, _pass_rule())

        result = self.sched.submit_build(pid, "suite_1")
        build_id = result["id"]
        deadline = time.time() + 20
        while time.time() < deadline:
            state = self.gate.release_state(pid, build_id)
            if state["evaluation"] is not None:
                break
            time.sleep(0.05)
        state = self.gate.release_state(pid, build_id)
        self.assertIsNotNone(state["evaluation"])
        self.assertEqual(state["evaluation"]["decision"], "allow")
        self.assertEqual(state["release"]["status"], "released")
        # 构建日志里留下判定记录
        logs = self.builds.for_project(pid).read_logs(build_id)["lines"]
        self.assertTrue(any("发布门禁判定" in line for line in logs))


if __name__ == "__main__":
    unittest.main()
