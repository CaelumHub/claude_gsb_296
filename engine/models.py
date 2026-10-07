"""领域模型：枚举常量、id 生成与通用工具。"""

from __future__ import annotations

import time
import uuid

# 用例优先级
PRIORITIES = ["P0", "P1", "P2", "P3"]

# 用例结果状态（单条）
CASE_STATUSES = ["passed", "failed", "error", "skipped", "timeout"]

# 构建状态（一次执行）
BUILD_STATUSES = ["pending", "running", "passed", "failed", "cancelled", "error"]

# 缺陷严重级别与状态流
SEVERITIES = ["blocker", "critical", "major", "minor", "trivial"]
DEFECT_STATUSES = ["open", "in_progress", "fixed", "verified", "closed", "reopened"]

# 通知集成类型
INTEGRATION_TYPES = ["webhook", "slack", "email", "dingtalk"]

# 触发来源
TRIGGER_TYPES = ["manual", "schedule", "webhook", "ci"]

# ---------------------------------------------------------------------------
# 发布门禁
# ---------------------------------------------------------------------------
# 门禁判定结果：允许发布 / 有条件发布 / 禁止发布
GATE_DECISIONS = ["allow", "conditional", "deny"]

# 可参与判定的指标
# - pass_rate     构建通过率（%）
# - failed_cases  失败用例数（可按优先级过滤，如 P0 失败数）
# - coverage      代码覆盖率（%）
# - open_defects  未关闭缺陷数（可按严重级别过滤）
GATE_METRICS = ["pass_rate", "failed_cases", "coverage", "open_defects"]

# 条件比较符（满足即视为「违反」，触发对应后果等级）
GATE_OPS = ["lt", "lte", "gt", "gte", "eq"]

# 条件被违反时的后果等级：禁止发布 / 有条件发布
GATE_LEVELS = ["deny", "conditional"]

# 构建的发布放行状态：
# none        未判定（项目未配置门禁规则）
# released    已放行（允许发布自动放行，或有条件发布经人工确认）
# conditional 有条件发布，待人工确认放行
# blocked     禁止发布，待审批
# approved    禁止发布经人工审批通过后放行
# rejected    审批被拒绝，禁止放行
RELEASE_STATUSES = ["none", "released", "conditional", "blocked",
                    "approved", "rejected"]

# 审批单状态
APPROVAL_STATUSES = ["pending", "approved", "rejected"]

# 计入「未关闭缺陷」的缺陷状态
OPEN_DEFECT_STATUSES = ["open", "in_progress", "reopened"]


def new_id(prefix: str) -> str:
    """生成带前缀的唯一 id（时间戳 + 随机后缀，便于阅读与排查）。"""
    return f"{prefix}_{int(time.time() * 1000)}_{uuid.uuid4().hex[:6]}"


def now() -> float:
    return time.time()
