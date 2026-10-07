"""发布门禁：规则版本化、构建判定、人工审批与放行审计。

门禁把发布负责人原来分别翻阅报告、覆盖率、缺陷列表的经验判断固化为一组
可组合条件。每场构建结束后：

1. 读取项目当前规则（未配置时使用内置默认规则）；
2. 采集通过率、失败用例等级、覆盖率、未关闭缺陷等指标；
3. 任一条件不满足时按条件自身配置记为「有条件发布」或「禁止发布」，
   其中禁止发布优先级最高；
4. 判定记录和当时的规则快照、指标快照一并落盘，规则后续修改不会改写
   历史判定；
5. 禁止发布自动创建人工审批，审批通过后才能执行放行。

规则只追加新版本、不覆盖旧版本；审批、放行等操作全部写入审计流水。
"""

from __future__ import annotations

import copy
import time
from typing import Any, Optional

from .models import PRIORITIES, SEVERITIES, new_id

# 门禁结论
GATE_OUTCOMES = ("allow", "conditional", "blocked")

# 审批状态
APPROVAL_STATUSES = ("pending", "approved", "rejected", "superseded")

# 条件支持的指标
METRICS = (
    "build_status",
    "pass_rate",
    "coverage",
    "failed_cases",
    "priority_failures",
    "open_defects",
    "severity_defects",
)

OPERATORS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
}

FAILED_BUILD_STATUSES = ("failed", "error", "timeout")
UNRELEASED_APPROVAL = ("pending", "rejected", "superseded")


def default_rule(project_id: str) -> dict[str, Any]:
    """项目尚未保存规则时使用的内置基线（版本 0，不落盘）。"""
    return {
        "id": None,
        "project_id": project_id,
        "version": 0,
        "name": "系统默认发布门禁",
        "enabled": True,
        "change_note": "系统内置默认规则",
        "conditions": [
            {"metric": "build_status", "name": "构建必须成功",
             "operator": "eq", "threshold": "passed", "on_fail": "blocked"},
            {"metric": "pass_rate", "name": "通过率不低于 80%",
             "operator": "gte", "threshold": 80, "on_fail": "blocked"},
            {"metric": "pass_rate", "name": "通过率不低于 95%",
             "operator": "gte", "threshold": 95, "on_fail": "conditional"},
            {"metric": "coverage", "name": "覆盖率不低于 60%",
             "operator": "gte", "threshold": 60, "on_fail": "blocked"},
            {"metric": "coverage", "name": "覆盖率不低于 80%",
             "operator": "gte", "threshold": 80, "on_fail": "conditional"},
            {"metric": "priority_failures", "name": "P0 用例零失败",
             "operator": "lte", "threshold": 0, "level": "P0",
             "on_fail": "blocked"},
            {"metric": "priority_failures", "name": "P1 失败不超过 1 条",
             "operator": "lte", "threshold": 1, "level": "P1",
             "on_fail": "blocked"},
            {"metric": "priority_failures", "name": "P1 用例最好零失败",
             "operator": "lte", "threshold": 0, "level": "P1",
             "on_fail": "conditional"},
            {"metric": "open_defects", "name": "未关闭缺陷不超过 10 个",
             "operator": "lte", "threshold": 10, "on_fail": "blocked"},
            {"metric": "open_defects", "name": "未关闭缺陷不超过 5 个",
             "operator": "lte", "threshold": 5, "on_fail": "conditional"},
        ],
        "created_by": "system",
        "created_at": None,
    }


class ReleaseGateManager:
    """发布门禁规则、判定、审批与放行管理。"""

    def __init__(self, registry, build_registry, report_generator,
                 coverage_analyzer, defect_manager, notify_manager=None):
        self.registry = registry
        self.builds = build_registry
        self.report = report_generator
        self.coverage = coverage_analyzer
        self.defects = defect_manager
        self.notify = notify_manager

    @property
    def _rules(self):
        return self.registry.store("gate_rules")

    @property
    def _decisions(self):
        return self.registry.store("gate_decisions")

    @property
    def _approvals(self):
        return self.registry.store("gate_approvals")

    @property
    def _releases(self):
        return self.registry.store("gate_releases")

    @property
    def _audits(self):
        return self.registry.store("gate_audit")

    # ------------------------------------------------------------------ 审计
    def _audit(self, action: str, project_id: str, actor: str,
               build_id: Optional[str] = None, decision_id: Optional[str] = None,
               approval_id: Optional[str] = None, release_id: Optional[str] = None,
               comment: str = "", detail: Optional[dict] = None) -> dict:
        event = {
            "id": new_id("gateaudit"),
            "action": action,
            "project_id": project_id,
            "build_id": build_id,
            "decision_id": decision_id,
            "approval_id": approval_id,
            "release_id": release_id,
            "actor": actor,
            "comment": comment or "",
            "detail": detail or {},
            "at": time.time(),
        }
        self._audits.insert(event)
        return event

    def list_audit(self, project_id: str, build_id: Optional[str] = None,
                   limit: int = 100) -> list[dict]:
        where = [("project_id", "eq", project_id)]
        if build_id:
            where.append(("build_id", "eq", build_id))
        return self._audits.query(where=where, order_by="at", order="desc",
                                  limit=limit)

    # ------------------------------------------------------------------ 规则
    def get_rule(self, project_id: str) -> dict:
        """获取当前生效规则；没有保存过则返回版本 0 默认规则。"""
        rules = self._rules.query(where=[("project_id", "eq", project_id)],
                                  order_by="version", order="desc", limit=1)
        return copy.deepcopy(rules[0]) if rules else default_rule(project_id)

    def list_rules(self, project_id: str) -> list[dict]:
        return self._rules.query(where=[("project_id", "eq", project_id)],
                                 order_by="version", order="desc")

    def get_rule_by_id(self, rule_id: str) -> Optional[dict]:
        return self._rules.get(rule_id)

    def validate_rule(self, payload: dict) -> list[dict]:
        """校验并规范化前端提交的条件数组。"""
        raw = payload.get("conditions")
        if raw is None:
            raw = default_rule("")["conditions"]
        if not isinstance(raw, list):
            raise ValueError("conditions 必须是数组")
        conditions = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ValueError(f"第 {i + 1} 条条件格式不正确")
            metric = item.get("metric")
            if metric not in METRICS:
                raise ValueError(f"第 {i + 1} 条条件指标不支持: {metric}")
            operator = item.get("operator", "gte")
            if operator not in OPERATORS:
                raise ValueError(f"第 {i + 1} 条条件比较符不支持: {operator}")
            on_fail = item.get("on_fail", "blocked")
            if on_fail not in ("blocked", "conditional"):
                raise ValueError(f"第 {i + 1} 条条件命中后的结论必须是 blocked/conditional")

            threshold: Any = item.get("threshold")
            if metric == "build_status":
                operator = "eq"
                threshold = "passed"
            elif metric in ("pass_rate", "coverage"):
                threshold = self._as_number(threshold, f"第 {i + 1} 条条件阈值")
                if not 0 <= threshold <= 100:
                    raise ValueError(f"第 {i + 1} 条条件阈值必须在 0~100 之间")
            else:
                threshold = self._as_number(threshold, f"第 {i + 1} 条条件阈值")
                if threshold < 0:
                    raise ValueError(f"第 {i + 1} 条条件阈值不能为负数")
                threshold = int(threshold)

            level = item.get("level")
            if metric == "priority_failures" and level not in PRIORITIES:
                raise ValueError(f"第 {i + 1} 条条件需要指定有效的用例等级")
            if metric == "severity_defects" and level not in SEVERITIES:
                raise ValueError(f"第 {i + 1} 条条件需要指定有效的缺陷严重级")

            conditions.append({
                "metric": metric,
                "name": (item.get("name") or "").strip() or self._default_condition_name(metric, operator, threshold, level),
                "operator": operator,
                "threshold": threshold,
                "level": level,
                "on_fail": on_fail,
                "enabled": bool(item.get("enabled", True)),
            })
        return conditions

    @staticmethod
    def _as_number(value, label: str) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(f"{label}必须是数字") from None
        if number != number:  # NaN
            raise ValueError(f"{label}必须是有效数字")
        return number

    @staticmethod
    def _default_condition_name(metric: str, operator: str,
                                threshold: Any, level: Optional[str]) -> str:
        metric_names = {
            "pass_rate": "通过率",
            "coverage": "覆盖率",
            "failed_cases": "失败用例数",
            "priority_failures": f"{level} 失败用例数",
            "open_defects": "未关闭缺陷数",
            "severity_defects": f"{level} 未关闭缺陷数",
            "build_status": "构建状态",
        }
        op_names = {"gte": "≥", "lte": "≤", "gt": ">", "lt": "<",
                    "eq": "=", "ne": "≠"}
        return f"{metric_names.get(metric, metric)} {op_names.get(operator, operator)} {threshold}"

    def update_rule(self, project_id: str, payload: dict,
                    actor: str) -> dict:
        """以追加版本的方式修改项目门禁规则。"""
        if not actor or not actor.strip():
            raise ValueError("缺少操作人")
        current = self.get_rule(project_id)
        conditions = self.validate_rule(payload)
        rule = {
            "id": new_id("gaterule"),
            "project_id": project_id,
            "version": int(current.get("version", 0)) + 1,
            "name": (payload.get("name") or "项目发布门禁").strip(),
            "enabled": bool(payload.get("enabled", True)),
            "conditions": conditions,
            "change_note": (payload.get("change_note") or "").strip(),
            "created_by": actor.strip(),
            "created_at": time.time(),
        }
        self._rules.insert(rule)
        self._audit(
            "rule.created" if current.get("version", 0) == 0 else "rule.updated",
            project_id, actor,
            comment=rule["change_note"],
            detail={"rule_id": rule["id"], "version": rule["version"],
                    "condition_count": len(conditions)},
        )
        return copy.deepcopy(rule)

    # ------------------------------------------------------------------ 指标
    def collect_metrics(self, project_id: str, build: dict) -> dict[str, Any]:
        build_id = build["id"]
        total = int(build.get("total", 0) or 0)
        passed = int(build.get("passed", 0) or 0)
        failed = int(build.get("failed", 0) or 0)
        error = int(build.get("error", 0) or 0)
        timeout = int(build.get("timeout", 0) or 0)
        skipped = int(build.get("skipped", 0) or 0)
        finished = max(0, total - skipped)
        failure_count = failed + error + timeout

        coverage = self.coverage.get(project_id, build_id) or {}
        all_defects = self.defects.list(project_id)
        open_defects = [d for d in all_defects if d.get("status") != "closed"]

        by_priority = build.get("by_priority", {}) or {}
        priority_failures = {}
        for priority in PRIORITIES:
            item = by_priority.get(priority, {})
            priority_failures[priority] = sum(
                int(item.get(status, 0) or 0)
                for status in FAILED_BUILD_STATUSES
            )

        by_severity = {}
        for severity in SEVERITIES:
            by_severity[severity] = sum(
                1 for d in open_defects if d.get("severity") == severity
            )

        return {
            "build_id": build_id,
            "build_status": build.get("status"),
            "total": total,
            "passed": passed,
            "failed": failed,
            "error": error,
            "timeout": timeout,
            "skipped": skipped,
            "failure_count": failure_count,
            "pass_rate": round(passed / finished * 100, 1) if finished else 0.0,
            "coverage": float(coverage.get("percent", 0.0) or 0.0),
            "open_defects": len(open_defects),
            "priority_failures": priority_failures,
            "severity_defects": by_severity,
            "collected_at": time.time(),
        }

    def _actual_for(self, metric: str, metrics: dict,
                    level: Optional[str]) -> Any:
        if metric == "build_status":
            return metrics["build_status"]
        if metric == "priority_failures":
            return metrics["priority_failures"].get(level, 0)
        if metric == "severity_defects":
            return metrics["severity_defects"].get(level, 0)
        return metrics.get(metric)

    def evaluate_conditions(self, rule: dict, metrics: dict) -> list[dict]:
        results = []
        for condition in rule.get("conditions", []):
            if not condition.get("enabled", True):
                continue
            metric = condition["metric"]
            level = condition.get("level")
            actual = self._actual_for(metric, metrics, level)
            operator = condition["operator"]
            threshold = condition["threshold"]
            try:
                passed = OPERATORS[operator](actual, threshold)
            except (TypeError, ValueError):
                passed = False
            results.append({
                "name": condition.get("name", metric),
                "metric": metric,
                "level": level,
                "operator": operator,
                "threshold": threshold,
                "actual": actual,
                "on_fail": condition.get("on_fail", "blocked"),
                "passed": bool(passed),
            })
        return results

    # ------------------------------------------------------------------ 判定
    def latest_decision(self, project_id: str,
                        build_id: str) -> Optional[dict]:
        rows = self._decisions.query(
            where=[("project_id", "eq", project_id), ("build_id", "eq", build_id)],
            order_by="decided_at", order="desc", limit=1)
        return rows[0] if rows else None

    def list_decisions(self, project_id: str, limit: int = 50) -> list[dict]:
        return self._decisions.query(where=[("project_id", "eq", project_id)],
                                     order_by="decided_at", order="desc",
                                     limit=limit)

    def decisions_for_build(self, project_id: str, build_id: str) -> list[dict]:
        return self._decisions.query(
            where=[("project_id", "eq", project_id), ("build_id", "eq", build_id)],
            order_by="decided_at", order="desc")

    def evaluate_build(self, project_id: str, build_id: str,
                       actor: str = "system", force: bool = False,
                       rule: Optional[dict] = None) -> dict:
        """执行一次门禁判定；默认同场构建已判定时直接返回原判定。"""
        if not actor or not actor.strip():
            raise ValueError("缺少操作人")
        store = self.builds.for_project(project_id)
        build = store.get(build_id)
        if build is None:
            raise ValueError("构建不存在")
        if build.get("status") in ("pending", "running"):
            raise ValueError("构建尚未结束，暂时不能进行发布判定")

        if not force:
            existing = self.latest_decision(project_id, build_id)
            if existing is not None:
                return existing

        rule = copy.deepcopy(rule or self.get_rule(project_id))
        metrics = self.collect_metrics(project_id, build)
        condition_results = self.evaluate_conditions(rule, metrics)
        violations = [r for r in condition_results if not r["passed"]]
        blocked = [r for r in violations if r["on_fail"] == "blocked"]
        conditional = [r for r in violations if r["on_fail"] == "conditional"]

        if not rule.get("enabled", True):
            outcome = "allow"
        elif blocked:
            outcome = "blocked"
        elif conditional:
            outcome = "conditional"
        else:
            outcome = "allow"

        decision = {
            "id": new_id("gatedec"),
            "project_id": project_id,
            "build_id": build_id,
            "outcome": outcome,
            "rule_id": rule.get("id"),
            "rule_version": rule.get("version", 0),
            "rule_snapshot": copy.deepcopy(rule),
            "metrics": metrics,
            "condition_results": condition_results,
            "violations": violations,
            "blocked_conditions": blocked,
            "conditional_conditions": conditional,
            "decided_by": actor.strip(),
            "decided_at": time.time(),
        }

        # 新判定产生后，旧的待审批单不能再用于放行本场构建。
        for old in self._approvals.query(
                where=[("build_id", "eq", build_id), ("status", "eq", "pending")]):
            self._approvals.update(old["id"], {
                "status": "superseded",
                "decided_by": "system",
                "decided_at": time.time(),
                "comment": "新的门禁判定已产生，旧审批单自动作废",
            })
            self._audit("approval.superseded", project_id, "system",
                        build_id=build_id, approval_id=old["id"],
                        decision_id=decision["id"])

        approval_id = None
        if outcome == "blocked":
            approval = {
                "id": new_id("gateapp"),
                "project_id": project_id,
                "build_id": build_id,
                "decision_id": decision["id"],
                "rule_version": decision["rule_version"],
                "status": "pending",
                "requested_by": actor.strip(),
                "requested_at": time.time(),
                "decided_by": None,
                "decided_at": None,
                "comment": "",
            }
            self._approvals.insert(approval)
            approval_id = approval["id"]
            decision["approval_id"] = approval_id

        self._decisions.insert(decision)
        self._audit("gate.evaluated", project_id, actor.strip(),
                    build_id=build_id, decision_id=decision["id"],
                    approval_id=approval_id,
                    detail={"outcome": outcome,
                            "rule_version": decision["rule_version"]})
        if approval_id:
            self._audit("approval.requested", project_id, actor.strip(),
                        build_id=build_id, decision_id=decision["id"],
                        approval_id=approval_id,
                        detail={"reasons": [r["name"] for r in blocked]})
            if self.notify:
                self.notify.fire(project_id, "gate.blocked", {
                    "build_id": build_id,
                    "project_id": project_id,
                    "decision_id": decision["id"],
                    "approval_id": approval_id,
                    "outcome": outcome,
                    "reasons": [r["name"] for r in blocked],
                })
        else:
            if self.notify:
                self.notify.fire(project_id, "gate.evaluated", {
                    "build_id": build_id,
                    "project_id": project_id,
                    "decision_id": decision["id"],
                    "outcome": outcome,
                })

        store.append_log(
            build_id,
            f"发布门禁判定: {self.outcome_text(outcome)}（规则 v{decision['rule_version']}）")
        return copy.deepcopy(decision)

    @staticmethod
    def outcome_text(outcome: str) -> str:
        return {"allow": "允许发布", "conditional": "有条件发布",
                "blocked": "禁止发布"}.get(outcome, outcome)

    # ------------------------------------------------------------------ 审批
    def get_approval(self, approval_id: str) -> Optional[dict]:
        return self._approvals.get(approval_id)

    def list_approvals(self, project_id: str,
                       status: Optional[str] = None,
                       limit: int = 100) -> list[dict]:
        where = [("project_id", "eq", project_id)]
        if status:
            where.append(("status", "eq", status))
        return self._approvals.query(where=where, order_by="requested_at",
                                     order="desc", limit=limit)

    def decide_approval(self, approval_id: str, approved: bool,
                        actor: str, comment: str = "") -> dict:
        if not actor or not actor.strip():
            raise ValueError("缺少操作人")
        approval = self._approvals.get(approval_id)
        if approval is None:
            raise ValueError("审批单不存在")
        if approval.get("status") != "pending":
            raise ValueError("该审批单已处理或已作废")

        patch = {
            "status": "approved" if approved else "rejected",
            "decided_by": actor.strip(),
            "decided_at": time.time(),
            "comment": (comment or "").strip(),
        }
        updated = self._approvals.update(approval_id, patch)
        action = "approval.approved" if approved else "approval.rejected"
        self._audit(action, approval["project_id"], actor.strip(),
                    build_id=approval["build_id"],
                    decision_id=approval.get("decision_id"),
                    approval_id=approval_id, comment=patch["comment"])
        if self.notify:
            self.notify.fire(approval["project_id"],
                             "gate.approval_decided",
                             {"approval_id": approval_id,
                              "build_id": approval["build_id"],
                              "status": patch["status"],
                              "actor": patch["decided_by"]})
        return updated

    # ------------------------------------------------------------------ 放行
    def latest_release(self, project_id: str, build_id: str) -> Optional[dict]:
        rows = self._releases.query(
            where=[("project_id", "eq", project_id), ("build_id", "eq", build_id)],
            order_by="released_at", order="desc", limit=1)
        return rows[0] if rows else None

    def release_build(self, project_id: str, build_id: str, actor: str,
                      confirm_conditional: bool = False,
                      comment: str = "") -> dict:
        """按最新门禁判定执行放行；禁止发布必须已有审批通过记录。"""
        if not actor or not actor.strip():
            raise ValueError("缺少操作人")
        decision = self.latest_decision(project_id, build_id)
        if decision is None:
            decision = self.evaluate_build(project_id, build_id,
                                           actor=actor, force=True)
        outcome = decision["outcome"]
        approval = None
        if outcome == "blocked":
            approval_id = decision.get("approval_id")
            approval = self._approvals.get(approval_id) if approval_id else None
            if not approval or approval.get("status") != "approved":
                raise PermissionError("禁止发布的构建必须等待人工审批通过后才能放行")
        elif outcome == "conditional" and not confirm_conditional:
            raise PermissionError("有条件发布需要先确认并接受发布条件")

        existing = self.latest_release(project_id, build_id)
        if existing is not None:
            raise PermissionError("该构建已经放行，不能重复放行；请为新构建重新执行门禁")

        release = {
            "id": new_id("gaterel"),
            "project_id": project_id,
            "build_id": build_id,
            "decision_id": decision["id"],
            "approval_id": decision.get("approval_id") if outcome == "blocked" else None,
            "outcome_at_evaluation": outcome,
            "released_by": actor.strip(),
            "released_at": time.time(),
            "comment": (comment or "").strip(),
        }
        self._releases.insert(release)
        self._audit("release.granted", project_id, actor.strip(),
                    build_id=build_id, decision_id=decision["id"],
                    approval_id=release["approval_id"],
                    release_id=release["id"], comment=release["comment"],
                    detail={"outcome_at_evaluation": outcome})
        self.builds.for_project(project_id).append_log(
            build_id, f"发布门禁放行：操作人 {actor.strip()}")
        if self.notify:
            self.notify.fire(project_id, "gate.released", {
                "build_id": build_id,
                "project_id": project_id,
                "release_id": release["id"],
                "actor": release["released_by"],
            })
        return release

    def list_releases(self, project_id: str, limit: int = 100) -> list[dict]:
        return self._releases.query(where=[("project_id", "eq", project_id)],
                                    order_by="released_at", order="desc",
                                    limit=limit)

    # ------------------------------------------------------------------ 看板
    def dashboard(self, project_id: str, build_limit: int = 20) -> dict:
        """聚合项目最近构建的门禁结论、审批与放行状态。"""
        store = self.builds.for_project(project_id)
        builds = store.list_builds()[:build_limit]
        decisions = self.list_decisions(project_id, limit=500)
        approvals = self.list_approvals(project_id, limit=500)
        releases = self.list_releases(project_id, limit=500)

        latest_decision = {}
        for d in reversed(decisions):
            latest_decision[d["build_id"]] = d
        latest_approval = {}
        for a in reversed(approvals):
            latest_approval[a["build_id"]] = a
        latest_release = {}
        for r in reversed(releases):
            latest_release[r["build_id"]] = r

        rows = []
        for build in builds:
            bid = build["id"]
            rows.append({
                "build": build,
                "decision": latest_decision.get(bid),
                "approval": latest_approval.get(bid),
                "release": latest_release.get(bid),
            })
        return {
            "project_id": project_id,
            "rule": self.get_rule(project_id),
            "rule_versions": self.list_rules(project_id),
            "builds": rows,
            "pending_approvals": [a for a in approvals if a.get("status") == "pending"],
            "recent_audit": self.list_audit(project_id, limit=30),
        }
