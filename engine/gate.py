"""发布门禁：规则版本化 + 构建判定 + 审批放行 + 全程留痕。

把「能不能发」从人工翻报告的经验判断，收口为可配置、可追溯的门禁：

1. **规则（版本化）**：每个项目一份门禁规则，规则由若干「条件」组合而成。
   每次修改规则都产生一个**新版本**（旧版本不可变），判定记录会带上
   规则版本号与规则快照，因此规则改过之后，仍能回溯「当时按哪版规则
   给出了什么判定」。

2. **条件模型**：一条条件 = 指标 + 比较符 + 阈值 + 后果等级::

       {"metric": "pass_rate", "op": "lt", "value": 90, "level": "deny"}

   含义：通过率 < 90% → 禁止发布。指标支持通过率 / 失败用例数（可按
   优先级过滤）/ 覆盖率 / 未关闭缺陷数（可按严重级别过滤）。比较成立
   即视为「违反该条件」，触发其后果等级。

3. **判定**：构建结束后自动判定（也可手动重新判定）：
   - 任一 ``deny`` 条件被违反        → ``deny``        禁止发布
   - 否则任一 ``conditional`` 被违反 → ``conditional`` 有条件发布
   - 否则                            → ``allow``       允许发布
   每次判定都写入一条**不可变**的判定记录（指标快照 + 违反明细 +
   规则版本），这就是「判定留痕」。

4. **放行与审批**：
   - ``allow``       → 自动放行；
   - ``conditional`` → 待人工确认，确认后放行；
   - ``deny``        → 阻断，并自动发起一张人工审批单；审批通过才放行，
     审批拒绝则保持阻断。
   每一步（判定 / 放行 / 发起审批 / 审批通过 / 审批拒绝 / 规则变更）
   都写入操作日志，记录**操作人与时间**。

存储：规则版本、判定记录、放行状态、审批单、操作日志分别落在
``gate_rules`` / ``gate_evaluations`` / ``gate_releases`` /
``gate_approvals`` / ``gate_events`` 五个分片存储中，复用平台统一的
文件锁 + 原子写，并发构建同时判定也不会写乱。
"""

from __future__ import annotations

import time
from typing import Optional

from .models import (APPROVAL_STATUSES, GATE_DECISIONS, GATE_LEVELS,
                     GATE_METRICS, GATE_OPS, OPEN_DEFECT_STATUSES,
                     PRIORITIES, SEVERITIES, new_id)

# 新建项目/演示数据可用的默认规则模板：覆盖四类指标的典型阈值
DEFAULT_RULE_CONDITIONS = [
    {"metric": "pass_rate", "op": "lt", "value": 90, "level": "deny"},
    {"metric": "pass_rate", "op": "lt", "value": 100, "level": "conditional"},
    {"metric": "failed_cases", "priority": "P0", "op": "gt", "value": 0,
     "level": "deny"},
    {"metric": "failed_cases", "priority": "P1", "op": "gt", "value": 0,
     "level": "conditional"},
    {"metric": "coverage", "op": "lt", "value": 70, "level": "deny"},
    {"metric": "coverage", "op": "lt", "value": 80, "level": "conditional"},
    {"metric": "open_defects", "severity": "blocker", "op": "gt", "value": 0,
     "level": "deny"},
    {"metric": "open_defects", "op": "gt", "value": 10, "level": "conditional"},
]

_COMPARE = {
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "eq": lambda a, b: a == b,
}

_OP_LABEL = {"lt": "<", "lte": "≤", "gt": ">", "gte": "≥", "eq": "="}

_METRIC_LABEL = {
    "pass_rate": "通过率",
    "failed_cases": "失败用例数",
    "coverage": "覆盖率",
    "open_defects": "未关闭缺陷数",
}

# 人工介入后的终态：重新判定不推翻人的放行决定
_HUMAN_FINAL = ("approved",)  # released 需结合 source 判断，见 _apply_decision


class GateManager:
    """发布门禁管理。"""

    def __init__(self, registry, build_registry, coverage_analyzer,
                 defect_manager, notify_manager=None):
        self.builds = build_registry
        self.coverage = coverage_analyzer
        self.defects = defect_manager
        self.notify = notify_manager
        self._rules = registry.store("gate_rules")
        self._evaluations = registry.store("gate_evaluations")
        self._releases = registry.store("gate_releases")
        self._approvals = registry.store("gate_approvals")
        self._events = registry.store("gate_events")

    # ------------------------------------------------------------------ 规则
    def create_rule(self, project_id: str, payload: dict,
                    actor: str = "system") -> dict:
        """为项目创建一版新规则（版本号递增，旧版本保留不可变）。"""
        conditions = payload.get("conditions")
        if not isinstance(conditions, list) or not conditions:
            return {"error": "规则至少包含一条条件"}
        cleaned = []
        for cond in conditions:
            ok, result = self._validate_condition(cond)
            if not ok:
                return {"error": result}
            cleaned.append(result)

        current = self.current_rule(project_id)
        version = (current.get("version", 0) + 1) if current else 1
        rule = {
            "id": new_id("rule"),
            "project_id": project_id,
            "version": version,
            "name": (payload.get("name") or "发布门禁规则").strip() or "发布门禁规则",
            "enabled": bool(payload.get("enabled", True)),
            "conditions": cleaned,
            "note": payload.get("note", ""),
            "created_by": actor,
            "created_at": time.time(),
        }
        self._rules.insert(rule)
        self._log(project_id, None, "rule_created", actor, {
            "rule_id": rule["id"], "version": version,
            "name": rule["name"], "condition_count": len(cleaned),
        })
        return rule

    def current_rule(self, project_id: str) -> Optional[dict]:
        """项目当前生效的规则（版本号最大的一版）。"""
        versions = self._rules.query(where=[("project_id", "eq", project_id)],
                                     order_by="version", order="desc", limit=1)
        return versions[0] if versions else None

    def rule_versions(self, project_id: str) -> list[dict]:
        return self._rules.query(where=[("project_id", "eq", project_id)],
                                 order_by="version", order="desc")

    def get_rule_version(self, project_id: str, version: int) -> Optional[dict]:
        rows = self._rules.query(where=[("project_id", "eq", project_id),
                                        ("version", "eq", version)], limit=1)
        return rows[0] if rows else None

    @staticmethod
    def _validate_condition(cond: dict):
        """校验并规范化一条条件，返回 ``(ok, 条件或错误信息)``。"""
        if not isinstance(cond, dict):
            return False, "条件必须是对象"
        metric = cond.get("metric")
        if metric not in GATE_METRICS:
            return False, f"未知指标: {metric}（可选 {','.join(GATE_METRICS)}）"
        op = cond.get("op")
        if op not in GATE_OPS:
            return False, f"未知比较符: {op}（可选 {','.join(GATE_OPS)}）"
        level = cond.get("level")
        if level not in GATE_LEVELS:
            return False, f"未知后果等级: {level}（可选 deny/conditional）"
        try:
            value = float(cond.get("value"))
        except (TypeError, ValueError):
            return False, f"阈值必须是数字: {cond.get('value')!r}"
        out = {"metric": metric, "op": op, "value": value, "level": level}
        if metric == "failed_cases" and cond.get("priority"):
            if cond["priority"] not in PRIORITIES:
                return False, f"未知优先级: {cond['priority']}"
            out["priority"] = cond["priority"]
        if metric == "open_defects" and cond.get("severity"):
            if cond["severity"] not in SEVERITIES:
                return False, f"未知严重级别: {cond['severity']}"
            out["severity"] = cond["severity"]
        return True, out

    # ------------------------------------------------------------------ 判定
    def evaluate_build(self, project_id: str, build_id: str,
                       actor: str = "system", trigger: str = "auto") -> dict:
        """对一场构建执行门禁判定，落判定记录并更新放行状态。"""
        build = self.builds.for_project(project_id).get(build_id)
        if build is None:
            return {"error": "构建不存在"}
        rule = self.current_rule(project_id)
        if rule is None:
            return {"error": "项目未配置门禁规则", "decision": None}
        if not rule.get("enabled", True):
            return {"error": "门禁规则已停用", "decision": None}

        metrics = self._collect_metrics(project_id, build_id, build)
        decision, violations = self._judge(rule["conditions"], metrics)

        evaluation = {
            "id": new_id("gev"),
            "project_id": project_id,
            "build_id": build_id,
            "decision": decision,
            "metrics": metrics,
            "violations": violations,
            "rule_id": rule["id"],
            "rule_version": rule["version"],
            "rule_snapshot": {"name": rule.get("name"),
                              "conditions": rule["conditions"]},
            "trigger": trigger,
            "evaluated_by": actor,
            "evaluated_at": time.time(),
        }
        self._evaluations.insert(evaluation)

        release = self._apply_decision(project_id, build_id, evaluation)
        self._log(project_id, build_id, "evaluated", actor, {
            "evaluation_id": evaluation["id"],
            "decision": decision,
            "rule_version": rule["version"],
            "release_status": release["status"],
            "violation_count": len(violations),
        })

        # 通知：判定结束都发 gate.evaluated；禁止发布再发 gate.denied 提醒审批
        if self.notify is not None:
            payload = {
                "build_id": build_id, "project_id": project_id,
                "decision": decision, "rule_version": rule["version"],
                "release_status": release["status"],
                "pass_rate": metrics.get("pass_rate"),
                "coverage": metrics.get("coverage"),
                "open_defects": metrics.get("open_defects"),
            }
            try:
                self.notify.fire(project_id, "gate.evaluated", payload)
                if decision == "deny":
                    self.notify.fire(project_id, "gate.denied", payload)
            except Exception:  # noqa: BLE001
                pass

        evaluation["release"] = release
        return evaluation

    def _collect_metrics(self, project_id: str, build_id: str,
                         build: dict) -> dict:
        """汇总判定所需的全部指标快照。"""
        total = build.get("total", 0)
        passed = build.get("passed", 0)
        failed_total = (build.get("failed", 0) + build.get("error", 0)
                        + build.get("timeout", 0))

        # 按优先级统计失败用例（failed+error+timeout 都算未通过）
        failed_by_priority: dict[str, int] = {}
        for prio, agg in (build.get("by_priority") or {}).items():
            n = (agg.get("failed", 0) + agg.get("error", 0)
                 + agg.get("timeout", 0))
            if n:
                failed_by_priority[prio] = n

        try:
            coverage = self.coverage.get(project_id, build_id).get("percent", 0.0)
        except Exception:  # noqa: BLE001
            coverage = 0.0

        open_defects = 0
        open_by_severity: dict[str, int] = {}
        for d in self.defects.list(project_id):
            if d.get("status") in OPEN_DEFECT_STATUSES:
                open_defects += 1
                sev = d.get("severity", "major")
                open_by_severity[sev] = open_by_severity.get(sev, 0) + 1

        return {
            "total": total,
            "passed": passed,
            "failed_total": failed_total,
            "pass_rate": round(passed / total * 100, 2) if total else 100.0,
            "failed_by_priority": failed_by_priority,
            "coverage": coverage,
            "open_defects": open_defects,
            "open_defects_by_severity": open_by_severity,
        }

    def _judge(self, conditions: list, metrics: dict):
        """逐条评估条件，返回 ``(判定结果, 违反明细)``。"""
        violations = []
        for cond in conditions:
            actual = self._metric_value(metrics, cond)
            if _COMPARE[cond["op"]](actual, cond["value"]):
                violations.append({
                    "metric": cond["metric"],
                    "priority": cond.get("priority"),
                    "severity": cond.get("severity"),
                    "op": cond["op"],
                    "value": cond["value"],
                    "actual": actual,
                    "level": cond["level"],
                    "message": self._violation_message(cond, actual),
                })
        if any(v["level"] == "deny" for v in violations):
            return "deny", violations
        if any(v["level"] == "conditional" for v in violations):
            return "conditional", violations
        return "allow", violations

    @staticmethod
    def _metric_value(metrics: dict, cond: dict) -> float:
        metric = cond["metric"]
        if metric == "pass_rate":
            return metrics.get("pass_rate", 0.0)
        if metric == "coverage":
            return metrics.get("coverage", 0.0)
        if metric == "failed_cases":
            prio = cond.get("priority")
            if prio:
                return (metrics.get("failed_by_priority") or {}).get(prio, 0)
            return metrics.get("failed_total", 0)
        if metric == "open_defects":
            sev = cond.get("severity")
            if sev:
                return (metrics.get("open_defects_by_severity") or {}).get(sev, 0)
            return metrics.get("open_defects", 0)
        return 0.0

    @staticmethod
    def _violation_message(cond: dict, actual: float) -> str:
        label = _METRIC_LABEL.get(cond["metric"], cond["metric"])
        if cond.get("priority"):
            label = f"{cond['priority']} {label}"
        if cond.get("severity"):
            label = f"{label}（{cond['severity']}）"
        unit = "%" if cond["metric"] in ("pass_rate", "coverage") else ""
        return (f"{label} {actual}{unit} 触发阈值 "
                f"{_OP_LABEL[cond['op']]} {cond['value']}{unit}")

    # ------------------------------------------------------------------ 放行
    def _apply_decision(self, project_id: str, build_id: str,
                        evaluation: dict) -> dict:
        """按判定结果推进构建的放行状态（人工终态不被自动判定推翻）。"""
        release = self._get_release(project_id, build_id)
        decision = evaluation["decision"]

        human_final = (release["status"] == "approved"
                       or (release["status"] == "released"
                           and release.get("source") == "confirm"))
        release["decision"] = decision
        release["evaluation_id"] = evaluation["id"]
        release["updated_at"] = time.time()

        if human_final:
            # 人工已放行/审批通过：保留人的决定，仅更新最新判定指针
            self._save_release(release)
            return release

        if decision == "allow":
            release["status"] = "released"
            release["source"] = "auto"
        elif decision == "conditional":
            release["status"] = "conditional"
            release["source"] = None
        else:  # deny
            release["status"] = "blocked"
            release["source"] = None
            self._ensure_approval(project_id, build_id, evaluation)
        self._save_release(release)
        return release

    def _get_release(self, project_id: str, build_id: str) -> dict:
        rows = self._releases.query(where=[("build_id", "eq", build_id)], limit=1)
        if rows:
            return rows[0]
        return {
            "id": new_id("rel"),
            "project_id": project_id,
            "build_id": build_id,
            "decision": None,
            "status": "none",
            "source": None,
            "evaluation_id": None,
            "created_at": time.time(),
        }

    def _save_release(self, release: dict) -> None:
        if self._releases.get(release["id"]):
            patch = dict(release)
            patch.pop("id", None)
            self._releases.update(release["id"], patch)
        else:
            self._releases.insert(release)

    def release_state(self, project_id: str, build_id: str) -> dict:
        """构建的门禁全景：最新判定 + 放行状态 + 审批单。"""
        release = self._get_release(project_id, build_id)
        evaluation = None
        if release.get("evaluation_id"):
            evaluation = self._evaluations.get(release["evaluation_id"])
        approvals = self._approvals.query(
            where=[("build_id", "eq", build_id)],
            order_by="created_at", order="desc")
        return {"release": release, "evaluation": evaluation,
                "approvals": approvals}

    def confirm_release(self, project_id: str, build_id: str,
                        actor: str, note: str = "") -> dict:
        """有条件发布的构建：人工确认放行。"""
        release = self._get_release(project_id, build_id)
        if release["status"] != "conditional":
            return {"error": f"当前状态（{release['status']}）无需确认放行"}
        release["status"] = "released"
        release["source"] = "confirm"
        release["updated_at"] = time.time()
        self._save_release(release)
        self._log(project_id, build_id, "released", actor,
                  {"note": note, "via": "confirm"})
        return release

    # ------------------------------------------------------------------ 审批
    def _ensure_approval(self, project_id: str, build_id: str,
                         evaluation: dict) -> dict:
        """禁止发布时自动发起审批单（已有待审批单则不重复发起）。"""
        pending = self._approvals.query(
            where=[("build_id", "eq", build_id), ("status", "eq", "pending")],
            limit=1)
        if pending:
            return pending[0]
        approval = {
            "id": new_id("gap"),
            "project_id": project_id,
            "build_id": build_id,
            "evaluation_id": evaluation["id"],
            "status": "pending",
            "reason": "门禁判定为禁止发布，需人工审批后方可放行",
            "created_by": "system",
            "created_at": time.time(),
            "decided_by": None,
            "decided_at": None,
            "decision_note": None,
        }
        self._approvals.insert(approval)
        self._log(project_id, build_id, "approval_requested", "system",
                  {"approval_id": approval["id"],
                   "evaluation_id": evaluation["id"]})
        return approval

    def request_approval(self, project_id: str, build_id: str,
                         actor: str, reason: str = "") -> dict:
        """人工补发起审批（例如判定为有条件但团队希望走审批）。"""
        release = self._get_release(project_id, build_id)
        evaluation = None
        if release.get("evaluation_id"):
            evaluation = self._evaluations.get(release["evaluation_id"])
        if evaluation is None:
            return {"error": "构建尚未判定，无法发起审批"}
        approval = self._ensure_approval(project_id, build_id, evaluation)
        if reason:
            self._approvals.update(approval["id"], {"reason": reason,
                                                    "created_by": actor})
            approval = self._approvals.get(approval["id"])
        return approval

    def decide_approval(self, approval_id: str, actor: str, approve: bool,
                        note: str = "") -> dict:
        """审批：通过则放行构建，拒绝则保持阻断。"""
        approval = self._approvals.get(approval_id)
        if approval is None:
            return {"error": "审批单不存在"}
        if approval["status"] != "pending":
            return {"error": "审批单已处理，不能重复审批"}

        status = "approved" if approve else "rejected"
        approval = self._approvals.update(approval_id, {
            "status": status,
            "decided_by": actor,
            "decided_at": time.time(),
            "decision_note": note,
        })

        project_id = approval["project_id"]
        build_id = approval["build_id"]
        release = self._get_release(project_id, build_id)
        release["status"] = "approved" if approve else "rejected"
        if approve:
            release["source"] = "approval"
        release["updated_at"] = time.time()
        self._save_release(release)

        self._log(project_id, build_id,
                  "approval_approved" if approve else "approval_rejected",
                  actor, {"approval_id": approval_id, "note": note})
        approval["release"] = release
        return approval

    def approvals(self, project_id: str, status: Optional[str] = None) -> list[dict]:
        where = [("project_id", "eq", project_id)]
        if status in APPROVAL_STATUSES:
            where.append(("status", "eq", status))
        return self._approvals.query(where=where, order_by="created_at",
                                     order="desc")

    # ------------------------------------------------------------------ 查询
    def evaluations(self, project_id: str, build_id: Optional[str] = None,
                    rule_version: Optional[int] = None,
                    limit: int = 100) -> list[dict]:
        """判定历史：可按构建或规则版本过滤（追溯历史规则下的判定）。"""
        where = [("project_id", "eq", project_id)]
        if build_id:
            where.append(("build_id", "eq", build_id))
        if rule_version is not None:
            where.append(("rule_version", "eq", rule_version))
        return self._evaluations.query(where=where, order_by="evaluated_at",
                                       order="desc", limit=limit)

    def events(self, project_id: str, build_id: Optional[str] = None,
               limit: int = 200) -> list[dict]:
        """操作留痕：谁在什么时间做了什么。"""
        where = [("project_id", "eq", project_id)]
        if build_id:
            where.append(("build_id", "eq", build_id))
        return self._events.query(where=where, order_by="created_at",
                                  order="desc", limit=limit)

    def overview(self, project_id: str, limit: int = 30) -> list[dict]:
        """项目构建 + 门禁状态一览（门禁页主列表）。"""
        builds = self.builds.for_project(project_id).list_builds()[:limit]
        releases = {r["build_id"]: r for r in self._releases.query(
            where=[("project_id", "eq", project_id)])}
        out = []
        for b in builds:
            release = releases.get(b["id"])
            out.append({
                "build_id": b["id"],
                "name": b.get("name") or b["id"],
                "status": b.get("status"),
                "trigger": b.get("trigger"),
                "passed": b.get("passed", 0),
                "total": b.get("total", 0),
                "finished_at": b.get("finished_at"),
                "decision": release.get("decision") if release else None,
                "release_status": release.get("status", "none") if release else "none",
                "rule_version": None,
            })
        # 补上每次判定用的规则版本（批量取，避免逐条查询）
        for ev in self.evaluations(project_id, limit=limit * 2):
            for row in out:
                if row["build_id"] == ev["build_id"] and row["rule_version"] is None:
                    row["rule_version"] = ev.get("rule_version")
        return out

    # ------------------------------------------------------------------ 日志
    def _log(self, project_id: str, build_id: Optional[str], action: str,
             actor: str, detail: dict) -> None:
        self._events.insert({
            "id": new_id("gevt"),
            "project_id": project_id,
            "build_id": build_id,
            "action": action,
            "actor": actor or "system",
            "detail": detail,
            "created_at": time.time(),
        })
