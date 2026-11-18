"""凭据有效期推进与环境绑定 — 跨模块核心。

凭据状态不是孤立字段：它由「有效期日期」与「人工动作（轮换/吊销）」共同决定，
环境绑定则按有效期解析出下一次安全切换点，保证运行时永不落到已过期或已吊销凭据上。

数据流::

    credential_store（有效期 / 轮换周期）
        → CredentialValidity（状态推进 + 下一次安全切换点）
        → EnvBinding（可执行环境绑定清单）
        → RuntimeSession（按处理项龙边界选择凭据、记录切换原因、恢复不倒退）

处理项龙（handling item）是运行会话的边界：一个处理项龙对应一份可执行环境绑定清单，
同一处理项龙重复提交只计一次，归档后可恢复到最近的合法绑定。

两套处理边界：
- ``switch_failover``：采集批次执行中凭据过期，切到备用凭据继续；
- ``pause_and_wait``：暂停批次，等待原凭据轮换完成。
两者都不会使用过期凭据；边界冲突时绑定落到「27号处理终态」。
"""
from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from app.store import store

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

STATUS_NORMAL = "正常"
STATUS_EXPIRING = "即将过期"
STATUS_EXPIRED = "已过期"
STATUS_REVOKED = "已吊销"

CREDENTIAL_STATUSES = [STATUS_NORMAL, STATUS_EXPIRING, STATUS_EXPIRED, STATUS_REVOKED]
UNUSABLE_STATUSES = (STATUS_EXPIRED, STATUS_REVOKED)

BINDING_PENDING = "待生效"
BINDING_ACTIVE = "生效中"
BINDING_SWITCHED = "已切换"
BINDING_INVALID = "已失效"
BINDING_WAITING = "等待轮换"
# 冲突终态：两套处理边界同时落到同一绑定上时，绑定落到该终态
CONFLICT_TERMINAL_STATE = "27号处理终态"

SESSION_RUNNING = "执行中"
SESSION_WAITING = "等待轮换"
SESSION_SWITCHED = "已切换"
SESSION_ARCHIVED = "已归档"
SESSION_RESTORED = "已恢复"
SESSION_CONFLICT = CONFLICT_TERMINAL_STATE

BOUNDARY_SWITCH = "switch_failover"
BOUNDARY_PAUSE = "pause_and_wait"
BOUNDARIES = (BOUNDARY_SWITCH, BOUNDARY_PAUSE)
BOUNDARY_LABELS = {
    BOUNDARY_SWITCH: "切换备用凭据继续执行",
    BOUNDARY_PAUSE: "暂停批次等待原凭据轮换",
}

# 会话状态机：只允许这些有向流转
SESSION_TRANSITIONS: dict[str, set[str]] = {
    SESSION_RUNNING: {SESSION_SWITCHED, SESSION_WAITING, SESSION_ARCHIVED, SESSION_CONFLICT},
    SESSION_SWITCHED: {SESSION_ARCHIVED, SESSION_WAITING, SESSION_CONFLICT},
    SESSION_WAITING: {SESSION_SWITCHED, SESSION_ARCHIVED, SESSION_CONFLICT},
    SESSION_ARCHIVED: {SESSION_RESTORED},
    SESSION_RESTORED: {SESSION_RUNNING, SESSION_SWITCHED, SESSION_WAITING, SESSION_ARCHIVED},
    SESSION_CONFLICT: set(),
}

DEFAULT_ROTATION_DAYS = 7
MAX_WARNING_WINDOW_DAYS = 14
SWITCH_SAFETY_MARGIN = timedelta(minutes=5)

_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d",
)
_DATE_ONLY_FORMAT = "%Y-%m-%d"


# ---------------------------------------------------------------------------
# 时间 / 有效期解析
# ---------------------------------------------------------------------------

def now_utc(now: datetime | None = None) -> datetime:
    """统一到带时区的 UTC 时间；测试可注入固定时刻。"""
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


def parse_validity(value: Any) -> datetime | None:
    """解析「有效期」字段，支持日期、日期时间与 ISO 字符串。"""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return now_utc(value)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        return now_utc(parsed)
    except ValueError:
        pass
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse_rotation_days(value: Any) -> int:
    """解析「轮换周期」，兼容 30 / 30天 / 720h / 4周 等写法。"""
    if value is None:
        return DEFAULT_ROTATION_DAYS
    if isinstance(value, (int, float)):
        return max(int(value), 1)
    text = str(value).strip()
    digits = "".join(ch for ch in text if ch.isdigit())
    if not digits:
        return DEFAULT_ROTATION_DAYS
    amount = int(digits)
    if "周" in text or text.lower().endswith("w"):
        amount *= 7
    elif "h" in text.lower() or "小时" in text:
        amount = max(amount // 24, 1)
    return max(amount, 1)


def warning_window_days(row: dict[str, Any]) -> int:
    """「即将过期」告警窗口：约为轮换周期的一半，最多 14 天、至少 1 天。

    取一半而不是整个轮换周期，避免刚轮换完就立刻落回「即将过期」——
    状态与有效期必须同步推进，而不是互相打脸。
    """
    rotation_days = parse_rotation_days(row.get("轮换周期"))
    return max(1, min(rotation_days // 2, MAX_WARNING_WINDOW_DAYS))


def is_unusable(status: str | None) -> bool:
    return status in UNUSABLE_STATUSES


def derive_status(row: dict[str, Any], now: datetime | None = None) -> str:
    """按有效期推进凭据状态；吊销是终态，不被日期覆盖。"""
    if row.get("status") == STATUS_REVOKED or row.get("revoked_at"):
        return STATUS_REVOKED
    expiry = parse_validity(row.get("有效期"))
    if expiry is None:
        return row.get("status") or STATUS_NORMAL
    moment = now_utc(now)
    if expiry <= moment:
        return STATUS_EXPIRED
    warning_days = warning_window_days(row)
    if expiry - moment <= timedelta(days=warning_days):
        return STATUS_EXPIRING
    return STATUS_NORMAL


def next_safe_switch_point(
    row: dict[str, Any],
    now: datetime | None = None,
    standby_available: bool = True,
) -> dict[str, Any]:
    """解析单个凭据的下一次安全切换点。

    规则：切换绝不能晚于有效期；预留安全余量。落在轮换窗口内且存在备用凭据时，
    安全切换点就是「现在」——再等就会踩到过期。
    """
    moment = now_utc(now)
    expiry = parse_validity(row.get("有效期"))
    if row.get("status") == STATUS_REVOKED or row.get("revoked_at"):
        return {"at": moment.isoformat(),
                "reason": "凭据已吊销，必须立即切换到备用凭据",
                "source": "revoked", "immediate": True}
    if expiry is None:
        return {"at": None, "reason": "有效期缺失，无法解析切换点",
                "source": "unknown", "immediate": False}
    if expiry <= moment:
        return {"at": moment.isoformat(), "reason": "凭据已过期，必须立即切换",
                "source": "expired", "immediate": True}
    warning_days = warning_window_days(row)
    latest = expiry - SWITCH_SAFETY_MARGIN
    if expiry - moment <= timedelta(days=warning_days) and standby_available:
        return {"at": moment.isoformat(),
                "reason": f"进入 {warning_days} 天轮换窗口，存在可用备用凭据",
                "source": "rotation_window", "immediate": True}
    return {
        "at": latest.isoformat(),
        "reason": "有效期到达前切换，保留安全余量",
        "source": "credential_expiry",
        "immediate": latest <= moment,
    }


# ---------------------------------------------------------------------------
# 数据实体
# ---------------------------------------------------------------------------

@dataclass
class Binding:
    """凭据环境绑定：哪个目标系统在什么时间窗内用哪条凭据跑哪个环境。"""
    binding_id: int
    target_system: str
    credential_id: int
    env_id: int | None
    effective_at: datetime
    expires_at: datetime | None
    status: str = BINDING_ACTIVE
    reason: str = ""
    superseded_by: int | None = None
    terminal_state: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_id": self.binding_id,
            "target_system": self.target_system,
            "credential_id": self.credential_id,
            "env_id": self.env_id,
            "effective_at": self.effective_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "reason": self.reason,
            "superseded_by": self.superseded_by,
            "terminal_state": self.terminal_state,
        }


@dataclass
class SwitchRecord:
    """切换记录：用户可在凭据工作台核对「为什么切、从哪切到哪」。"""
    seq: int
    at: datetime
    target_system: str
    from_credential_id: int | None
    to_credential_id: int | None
    binding_id: int | None
    reason: str
    handling_item: str | None = None
    boundary: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "at": self.at.isoformat(),
            "target_system": self.target_system,
            "from_credential_id": self.from_credential_id,
            "to_credential_id": self.to_credential_id,
            "binding_id": self.binding_id,
            "reason": self.reason,
            "handling_item": self.handling_item,
            "boundary": self.boundary,
            "boundary_label": BOUNDARY_LABELS.get(self.boundary or "", ""),
        }


# ---------------------------------------------------------------------------
# 核心服务
# ---------------------------------------------------------------------------

class CredentialBindingService:
    """凭据状态推进、环境绑定解析与运行会话管理（纯跨模块服务）。"""

    SERVICE_NAME = "credential_binding"

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._clock: datetime | None = None
        self._bindings: dict[int, Binding] = {}
        self._binding_seq = 0
        self._switch_log: list[SwitchRecord] = []
        self._switch_seq = 0
        self._sessions: dict[str, dict[str, Any]] = {}
        self._idempotency: dict[str, str] = {}
        self._seeded = False

    def now(self, now: datetime | None = None) -> datetime:
        """统一时间源：显式传入优先，其次服务固定时钟，最后取系统当前时间。

        固定时钟让「有效期推进」在测试和复现时可核对。
        """
        return now_utc(now or self._clock)

    def reset(self) -> None:
        """重建绑定状态：批量替换/导入凭据后清掉旧绑定与旧会话。

        运行时会话和切换记录一并清空，随后按当前凭据有效期重新解析绑定。
        """
        with self._lock:
            self._bindings.clear()
            self._binding_seq = 0
            self._switch_log.clear()
            self._switch_seq = 0
            self._sessions.clear()
            self._idempotency.clear()
            self._seeded = False

    # ---- 凭据读取 -------------------------------------------------------

    def _credentials(self) -> list[dict[str, Any]]:
        return store.rows("credential_store")

    def _credential(self, credential_id: int) -> dict[str, Any] | None:
        return store.find("credential_store", credential_id)

    def _environments(self) -> list[dict[str, Any]]:
        return store.rows("env_profile")

    def _active_env_ids(self) -> list[int]:
        return [
            int(row.get("id", 0)) for row in self._environments()
            if row.get("status") in ("可用", "待验证")
        ]

    def _system_credentials(self, system: str) -> list[dict[str, Any]]:
        return [
            row for row in self._credentials()
            if str(row.get("目标系统", "")).strip() == system.strip()
        ]

    def _candidate_credentials(self, system: str) -> list[dict[str, Any]]:
        """同一目标系统下按有效期排序的候选凭据。"""
        rows = self._system_credentials(system)
        if rows:
            return sorted(
                rows,
                key=lambda row: parse_validity(row.get("有效期"))
                or datetime.max.replace(tzinfo=timezone.utc),
            )
        # 目标系统未精确匹配时退回模糊匹配（示例数据里目标系统可能是描述性文本）
        fuzzy = [
            row for row in self._credentials()
            if system and (system in str(row.get("目标系统", ""))
                           or str(row.get("目标系统", "")) in system)
        ]
        return sorted(
            fuzzy,
            key=lambda row: parse_validity(row.get("有效期"))
            or datetime.max.replace(tzinfo=timezone.utc),
        )

    def _all_systems(self) -> list[str]:
        """需要解析绑定的目标系统：由凭据覆盖的目标系统决定。

        环境只作为绑定的执行载体（env_id），不作为目标系统本身；
        没有凭据的环境无法单独构成可执行绑定。
        """
        return sorted({
            str(row.get("目标系统", "")).strip()
            for row in self._credentials()
            if str(row.get("目标系统", "")).strip()
        })

    # ---- 状态推进 -------------------------------------------------------

    def sync_credential_statuses(self, now: datetime | None = None) -> dict[str, Any]:
        """把「有效期」与「动作状态」共同推进到凭据行上。

        已吊销永远不回到正常；过期只保留历史引用，不再参与绑定解析。
        """
        changed: list[dict[str, Any]] = []
        with self._lock:
            for row in self._credentials():
                before = row.get("status")
                after = derive_status(row, now)
                if before != after:
                    row["status"] = after
                    row["status_changed_at"] = self.now(now).isoformat()
                    row["pending"] = after != STATUS_REVOKED
                    row["abnormal"] = after in (STATUS_EXPIRING, STATUS_EXPIRED, STATUS_REVOKED)
                    changed.append({
                        "credential_id": row.get("id"),
                        "from": before,
                        "to": after,
                    })
            invalidated = self._expire_stale_bindings(now)
        return {"changed": changed, "count": len(changed), "invalidated_bindings": invalidated}

    def _expire_stale_bindings(self, now: datetime | None = None) -> list[int]:
        """绑定指向过期/吊销凭据时立即失效，过期凭据只保留历史引用。"""
        moment = self.now(now)
        invalidated: list[int] = []
        for binding in self._bindings.values():
            if binding.status not in (BINDING_ACTIVE, BINDING_SWITCHED):
                continue
            credential = self._credential(binding.credential_id)
            if credential is None:
                reason = "凭据已不存在"
            elif is_unusable(derive_status(credential, moment)):
                reason = f"绑定凭据已{derive_status(credential, moment)}，停止使用"
            else:
                continue
            binding.status = BINDING_INVALID
            binding.reason = reason
            invalidated.append(binding.binding_id)
            self._log_switch(
                system=binding.target_system,
                from_id=binding.credential_id,
                to_id=None,
                binding_id=binding.binding_id,
                reason=reason,
                now=moment,
            )
        return invalidated

    def credential_view(self, row: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
        """凭据工作台视图：有效期、剩余天数、当前绑定与下一次安全切换点。"""
        moment = self.now(now)
        expiry = parse_validity(row.get("有效期"))
        status = derive_status(row, moment)
        system = str(row.get("目标系统", ""))
        binding = self.current_binding(system, moment)
        standby = self.resolve_standby(system, exclude_id=int(row.get("id", 0)), now=moment)
        switch = next_safe_switch_point(row, moment, standby_available=standby is not None)
        remaining = None
        if expiry is not None:
            remaining = round((expiry - moment).total_seconds() / 86400, 1)
        return {
            "id": row.get("id"),
            "name": row.get("凭据名称"),
            "target_system": system,
            "auth_type": row.get("认证方式"),
            "account": row.get("账户标识"),
            "validity": row.get("有效期"),
            "rotation_cycle": row.get("轮换周期"),
            "last_used": row.get("最后使用"),
            "status": status,
            "remaining_days": remaining,
            "current_binding": binding,
            "standby_credential_id": standby.get("id") if standby else None,
            "next_switch_at": switch["at"],
            "switch_reason": switch["reason"],
            "switch_source": switch["source"],
            "switch_immediate": switch["immediate"],
            "history_only": status in UNUSABLE_STATUSES,
            "switch_records": self.switch_records(int(row.get("id", 0))),
        }

    # ---- 绑定 -----------------------------------------------------------

    def ensure_bindings(self, now: datetime | None = None) -> None:
        """首次访问时按现有凭据/环境建立绑定，并推进一次状态。"""
        with self._lock:
            if self._seeded:
                return
            self.sync_credential_statuses(now)
            env_ids = self._active_env_ids()
            for index, system in enumerate(self._all_systems()):
                chosen = self._pick_valid_credential(system, None, now)
                if chosen is None:
                    continue
                self._create_binding(
                    system=system,
                    credential=chosen,
                    env_id=env_ids[index % len(env_ids)] if env_ids else None,
                    reason="初始化绑定：按当前有效期选择凭据",
                    now=now,
                )
            self._seeded = True

    def _pick_valid_credential(
        self,
        system: str,
        exclude_id: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """按当前有效期选择凭据，并记录选择原因。

        选择顺序：最近可用的轮换窗口凭据优先（延长整体有效期），
        但任何时候都把过期/吊销凭据排除在外。
        """
        moment = self.now(now)
        usable = [
            row for row in self._candidate_credentials(system)
            if int(row.get("id", 0)) != (exclude_id or -1)
            and not is_unusable(derive_status(row, moment))
            and (parse_validity(row.get("有效期")) or moment) > moment
        ]
        if not usable:
            return None
        usable.sort(key=lambda row: (
            0 if derive_status(row, moment) == STATUS_NORMAL else 1,
            -(parse_validity(row.get("有效期")) or moment).timestamp(),
        ))
        return usable[0]

    @staticmethod
    def _credential_usable(row: dict[str, Any], moment: datetime) -> bool:
        """凭据当前是否可用于绑定：未过期、未吊销、有效期在未来。"""
        if is_unusable(derive_status(row, moment)):
            return False
        expiry = parse_validity(row.get("有效期"))
        return expiry is None or expiry > moment

    def resolve_standby(
        self,
        system: str,
        exclude_id: int | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """解析备用凭据：同系统、未过期未吊销、且不是当前凭据。"""
        with self._lock:
            return self._pick_valid_credential(system, exclude_id, now)

    def _create_binding(
        self,
        *,
        system: str,
        credential: dict[str, Any],
        env_id: int | None,
        reason: str,
        now: datetime | None = None,
        effective_at: datetime | None = None,
    ) -> Binding:
        self._binding_seq += 1
        moment = self.now(now)
        binding = Binding(
            binding_id=self._binding_seq,
            target_system=system,
            credential_id=int(credential.get("id", 0)),
            env_id=env_id,
            effective_at=effective_at or moment,
            expires_at=parse_validity(credential.get("有效期")),
            status=BINDING_ACTIVE,
            reason=reason,
        )
        self._bindings[binding.binding_id] = binding
        return binding

    def _log_switch(
        self,
        *,
        system: str,
        from_id: int | None,
        to_id: int | None,
        binding_id: int | None,
        reason: str,
        now: datetime | None = None,
        handling_item: str | None = None,
        boundary: str | None = None,
    ) -> None:
        self._switch_seq += 1
        self._switch_log.append(SwitchRecord(
            seq=self._switch_seq,
            at=self.now(now),
            target_system=system,
            from_credential_id=from_id,
            to_credential_id=to_id,
            binding_id=binding_id,
            reason=reason,
            handling_item=handling_item,
            boundary=boundary,
        ))

    def switch_records(self, credential_id: int | None = None) -> list[dict[str, Any]]:
        with self._lock:
            records = self._switch_log
            if credential_id is not None:
                records = [
                    record for record in records
                    if credential_id in (record.from_credential_id, record.to_credential_id)
                ]
            return [record.to_dict() for record in records]

    def current_binding(self, system: str, now: datetime | None = None) -> dict[str, Any] | None:
        """当前生效绑定；若绑定凭据已过期/吊销，则如实标记不可用。"""
        self.ensure_bindings(now)
        moment = self.now(now)
        with self._lock:
            candidates = [
                binding for binding in self._bindings.values()
                if binding.target_system == system and binding.status in (BINDING_ACTIVE, BINDING_SWITCHED)
            ]
        if not candidates:
            return None
        binding = max(candidates, key=lambda item: item.effective_at)
        credential = self._credential(binding.credential_id)
        status = derive_status(credential or {}, moment)
        payload = binding.to_dict()
        payload.update({
            "credential_name": (credential or {}).get("凭据名称"),
            "credential_status": status,
            "credential_expiry": (credential or {}).get("有效期"),
            "usable": not is_unusable(status),
        })
        return payload

    # ---- 可执行环境绑定清单 ---------------------------------------------

    def resolve_manifest(
        self,
        *,
        target_system: str | None = None,
        handling_item: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """解析每个目标系统的下一次安全切换点，生成可执行环境绑定清单。"""
        self.ensure_bindings(now)
        status_sync = self.sync_credential_statuses(now)
        moment = self.now(now)
        systems = self._all_systems()
        if target_system:
            systems = [system for system in systems if system == target_system]

        items: list[dict[str, Any]] = []
        blocked: list[dict[str, Any]] = []
        for system in systems:
            item = self._manifest_item(system, moment, handling_item)
            items.append(item)
            if not item["executable"]:
                blocked.append({
                    "target_system": system,
                    "reason": item["blocked_reason"],
                })

        digest_source = {
            "handling_item": handling_item,
            "items": [
                {
                    "system": item["target_system"],
                    "credential_id": item["credential_id"],
                    "binding_id": item["binding_id"],
                    "expires_at": item["expires_at"],
                    "next_switch_at": item["next_switch_at"],
                }
                for item in items
            ],
        }
        digest = hashlib.sha256(
            json.dumps(digest_source, ensure_ascii=False, sort_keys=True).encode("utf-8")
        ).hexdigest()[:16]

        return {
            "handling_item": handling_item,
            "generated_at": moment.isoformat(),
            "manifest_digest": digest,
            "executable": bool(items) and not blocked,
            "items": items,
            "blocked": blocked,
            "status_changes": status_sync["changed"],
            "excluded_credentials": self._excluded_credentials(moment),
        }

    def _manifest_item(
        self,
        system: str,
        moment: datetime,
        handling_item: str | None,
    ) -> dict[str, Any]:
        binding = self.current_binding(system, moment)
        excluded = [
            {
                "credential_id": row.get("id"),
                "credential_name": row.get("凭据名称"),
                "status": derive_status(row, moment),
                "validity": row.get("有效期"),
                "reason": f"凭据{derive_status(row, moment)}，不参与可执行绑定",
            }
            for row in self._system_credentials(system)
            if is_unusable(derive_status(row, moment))
        ]

        if binding and not binding["usable"]:
            # 绑定指向的凭据已失效：决议一次切换，但绝不沿用过期凭据
            resolved = self._rebind_system(
                system=system,
                reason=f"当前绑定凭据已{derive_status(self._credential(binding['credential_id']) or {}, moment)}，重新解析安全绑定",
                now=moment,
                handling_item=handling_item,
            )
            if resolved is not None:
                binding = self.current_binding(system, moment)

        if binding is None:
            resolved = self._rebind_system(
                system=system,
                reason="无可执行绑定，按当前有效期解析",
                now=moment,
                handling_item=handling_item,
            )
            if resolved is not None:
                binding = self.current_binding(system, moment)

        if binding is None or not binding["usable"]:
            return {
                "handling_item": handling_item,
                "target_system": system,
                "binding_id": binding["binding_id"] if binding else None,
                "credential_id": binding["credential_id"] if binding else None,
                "credential_name": binding.get("credential_name") if binding else None,
                "credential_status": binding.get("credential_status") if binding else None,
                "credential_validity": binding.get("credential_expiry") if binding else None,
                "env_id": binding["env_id"] if binding else None,
                "effective_at": binding["effective_at"] if binding else None,
                "expires_at": binding["expires_at"] if binding else None,
                "next_switch_at": None,
                "switch_reason": "无可用凭据，需轮换或登记新凭据",
                "standby_credential_id": None,
                "standby_validity": None,
                "executable": False,
                "blocked_reason": "目标系统没有未过期且未吊销的凭据",
                "excluded_credentials": excluded,
            }

        credential = self._credential(binding["credential_id"]) or {}
        standby = self.resolve_standby(
            system, exclude_id=binding["credential_id"], now=moment)
        switch = next_safe_switch_point(
            credential, moment, standby_available=standby is not None)
        return {
            "handling_item": handling_item,
            "target_system": system,
            "binding_id": binding["binding_id"],
            "credential_id": binding["credential_id"],
            "credential_name": credential.get("凭据名称"),
            "credential_status": binding["credential_status"],
            "credential_validity": credential.get("有效期"),
            "env_id": binding["env_id"],
            "effective_at": binding["effective_at"],
            "expires_at": binding["expires_at"],
            "next_switch_at": switch["at"],
            "switch_reason": switch["reason"],
            "switch_immediate": switch["immediate"],
            "standby_credential_id": standby.get("id") if standby else None,
            "standby_validity": standby.get("有效期") if standby else None,
            "executable": binding["usable"],
            "blocked_reason": None,
            "excluded_credentials": excluded,
        }

    def _excluded_credentials(self, moment: datetime) -> list[dict[str, Any]]:
        return [
            {
                "credential_id": row.get("id"),
                "target_system": row.get("目标系统"),
                "status": derive_status(row, moment),
                "validity": row.get("有效期"),
            }
            for row in self._credentials()
            if is_unusable(derive_status(row, moment))
        ]

    def _rebind_system(
        self,
        *,
        system: str,
        reason: str,
        now: datetime | None = None,
        handling_item: str | None = None,
    ) -> Binding | None:
        """把目标系统的有效绑定推进到下一条合法凭据；无合法凭据时挂起。"""
        with self._lock:
            moment = self.now(now)
            previous = self.current_binding(system, moment)
            chosen = self._pick_valid_credential(system, None, moment)
            if chosen is None:
                if previous is not None:
                    old = self._bindings.get(previous["binding_id"])
                    if old is not None:
                        old.status = BINDING_WAITING
                        old.reason = "无可用凭据，等待轮换"
                return None

            if previous is not None and previous["credential_id"] == chosen.get("id"):
                # 当前绑定仍然合法，无需切换
                return self._bindings.get(previous["binding_id"])

            env_id = previous["env_id"] if previous else None
            if env_id is None:
                env_ids = self._active_env_ids()
                env_id = env_ids[0] if env_ids else None

            binding = self._create_binding(
                system=system, credential=chosen, env_id=env_id,
                reason=reason, now=moment,
            )
            if previous is not None:
                old = self._bindings.get(previous["binding_id"])
                if old is not None:
                    old.status = BINDING_SWITCHED
                    old.superseded_by = binding.binding_id
                    old.reason = reason
                self._log_switch(
                    system=system,
                    from_id=previous["credential_id"],
                    to_id=binding.credential_id,
                    binding_id=binding.binding_id,
                    reason=reason,
                    now=moment,
                    handling_item=handling_item,
                )
            return binding

    # ---- 凭据动作：轮换 / 吊销 ------------------------------------------

    def rotate_credential(
        self,
        credential_id: int,
        *,
        now: datetime | None = None,
        handling_item: str | None = None,
    ) -> tuple[dict[str, Any] | None, str]:
        """轮换凭据：延长有效期并推进绑定，切换原因写入切换记录。"""
        moment = self.now(now)
        with self._lock:
            row = self._credential(credential_id)
            if row is None:
                return None, f"系统凭据 {credential_id} 不存在或已归档"
            status = derive_status(row, moment)
            if status == STATUS_REVOKED:
                return None, f"系统凭据 {credential_id} 已吊销，请重新登记新凭据"

            rotation_days = parse_rotation_days(row.get("轮换周期"))
            previous_validity = row.get("有效期")
            # 轮换只延长有效期：从「当前有效期」与「现在」中较晚者起算
            anchor = max(parse_validity(previous_validity) or moment, moment)
            row["有效期"] = (anchor + timedelta(days=rotation_days)).strftime(
                _DATE_ONLY_FORMAT)
            row["最后使用"] = moment.strftime("%Y-%m-%d %H:%M:%S")
            row["status"] = STATUS_NORMAL
            row["pending"] = True
            row["abnormal"] = False
            row["rotated_at"] = moment.isoformat()
            row.pop("revoked_at", None)

            system = str(row.get("目标系统", ""))
            current = self.current_binding(system, moment)
            reason = (
                f"轮换凭据 {row.get('凭据名称')}：有效期 {previous_validity} → "
                f"{row['有效期']}，绑定按新有效期推进"
            )
            bound_to_rotated = current is not None and current["credential_id"] == credential_id
            if bound_to_rotated:
                target = self._bindings.get(int(current["binding_id"]))
                if target is not None:
                    target.expires_at = parse_validity(row["有效期"])
                    target.status = BINDING_ACTIVE
                    target.reason = reason
                self._log_switch(
                    system=system,
                    from_id=credential_id,
                    to_id=credential_id,
                    binding_id=current["binding_id"],
                    reason=reason,
                    now=moment,
                    handling_item=handling_item,
                )
            elif current is None or not current["usable"]:
                # 没有合法生效绑定：轮换后的凭据立即接管绑定
                self._bind_rotated(system, row, current, reason, moment, handling_item)
            # 轮换的是备用凭据时不抢走当前生效绑定，等安全切换点再推进
            store.channel.publish(
                topic="rpa.credential_rotated",
                source="credential_store",
                payload={
                    "credential_id": credential_id,
                    "target_system": system,
                    "validity": row["有效期"],
                    "status": STATUS_NORMAL,
                },
            )
        return row, f"{row.get('凭据名称')}已轮换，有效期至 {row['有效期']}"

    def _bind_rotated(
        self,
        system: str,
        credential: dict[str, Any],
        current: dict[str, Any] | None,
        reason: str,
        moment: datetime,
        handling_item: str | None,
    ) -> Binding:
        """轮换后把绑定推进到刚轮换的凭据，旧的生效绑定标记为已切换。"""
        env_id = current["env_id"] if current else None
        if env_id is None:
            env_ids = self._active_env_ids()
            env_id = env_ids[0] if env_ids else None
        binding = self._create_binding(
            system=system, credential=credential, env_id=env_id,
            reason=reason, now=moment,
        )
        if current is not None:
            old = self._bindings.get(int(current["binding_id"]))
            if old is not None:
                old.status = BINDING_SWITCHED
                old.superseded_by = binding.binding_id
                old.reason = reason
            self._log_switch(
                system=system,
                from_id=current["credential_id"],
                to_id=binding.credential_id,
                binding_id=binding.binding_id,
                reason=reason,
                now=moment,
                handling_item=handling_item,
            )
        return binding

    def revoke_credential(
        self,
        credential_id: int,
        *,
        now: datetime | None = None,
        handling_item: str | None = None,
    ) -> tuple[dict[str, Any] | None, str]:
        """吊销凭据：终态，绑定立即失效并尝试切到备用凭据。"""
        moment = self.now(now)
        with self._lock:
            row = self._credential(credential_id)
            if row is None:
                return None, f"系统凭据 {credential_id} 不存在或已归档"
            if derive_status(row, moment) == STATUS_REVOKED:
                return None, "凭据已吊销，无需重复操作"

            row["status"] = STATUS_REVOKED
            row["pending"] = False
            row["abnormal"] = True
            row["revoked_at"] = moment.isoformat()
            system = str(row.get("目标系统", ""))

            active = [
                binding for binding in self._bindings.values()
                if binding.target_system == system and binding.credential_id == credential_id
                and binding.status in (BINDING_ACTIVE, BINDING_SWITCHED)
            ]
            for binding in active:
                binding.status = BINDING_INVALID
                binding.reason = "凭据已吊销，绑定失效"
            if active:
                self._log_switch(
                    system=system,
                    from_id=credential_id,
                    to_id=None,
                    binding_id=active[-1].binding_id,
                    reason="凭据已吊销，立即停止使用",
                    now=moment,
                    handling_item=handling_item,
                )
            self._rebind_system(
                system=system,
                reason=f"原凭据 {credential_id} 已吊销，切换到备用凭据",
                now=moment,
                handling_item=handling_item,
            )
            store.channel.publish(
                topic="rpa.credential_revoked",
                source="credential_store",
                payload={
                    "credential_id": credential_id,
                    "target_system": system,
                    "status": STATUS_REVOKED,
                },
            )
        return row, f"{row.get('凭据名称')}已吊销，绑定已停用"

    # ---- 运行会话 -------------------------------------------------------

    def start_session(
        self,
        handling_item: str,
        *,
        boundary: str = BOUNDARY_SWITCH,
        manifest: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """按处理项龙边界启动运行会话；重复提交只计一次。"""
        if boundary not in BOUNDARIES:
            raise ValueError(f"未知处理边界: {boundary}")
        with self._lock:
            moment = self.now(now)
            manifest = manifest or self.resolve_manifest(
                handling_item=handling_item, now=moment)
            dedupe_key = self._dedupe_key(handling_item, boundary, manifest, idempotency_key)
            existing_id = self._idempotency.get(dedupe_key)
            if existing_id:
                session = self._sessions[existing_id]
                session["dedup_hits"] += 1
                session["last_submit_at"] = moment.isoformat()
                return {
                    "ok": True,
                    "deduplicated": True,
                    "counted_runs": 1,
                    "session": self._session_view(session),
                }

            session_id = f"RS-{uuid.uuid4().hex[:8].upper()}"
            assignments: dict[str, Any] = {}
            for item in manifest.get("items", []):
                if not item.get("executable"):
                    continue
                assignments[item["target_system"]] = {
                    "binding_id": item["binding_id"],
                    "credential_id": item["credential_id"],
                    "credential_name": item.get("credential_name"),
                    "credential_validity": item.get("credential_validity"),
                    "env_id": item.get("env_id"),
                    "next_switch_at": item.get("next_switch_at"),
                    "switch_reason": item.get("switch_reason"),
                }
            session = {
                "session_id": session_id,
                "handling_item": handling_item,
                "boundary": boundary,
                "boundary_label": BOUNDARY_LABELS[boundary],
                "manifest_digest": manifest.get("manifest_digest"),
                "status": SESSION_RUNNING if assignments else SESSION_WAITING,
                "assignments": assignments,
                "created_at": moment.isoformat(),
                "updated_at": moment.isoformat(),
                "last_submit_at": moment.isoformat(),
                "resumes": 0,
                "dedup_hits": 0,
                "counted_runs": 1,
                "switches": [],
                "blocked_reason": None if assignments else "清单中没有可执行绑定",
                "terminal_state": None,
                "idempotency_key": idempotency_key,
            }
            self._sessions[session_id] = session
            self._idempotency[dedupe_key] = session_id
            return {
                "ok": True,
                "deduplicated": False,
                "counted_runs": 1,
                "session": self._session_view(session),
            }

    @staticmethod
    def _dedupe_key(
        handling_item: str,
        boundary: str,
        manifest: dict[str, Any],
        idempotency_key: str | None,
    ) -> str:
        if idempotency_key:
            return f"{handling_item}:{boundary}:key:{idempotency_key}"
        return f"{handling_item}:{boundary}:digest:{manifest.get('manifest_digest')}"

    def _session_view(self, session: dict[str, Any]) -> dict[str, Any]:
        return json.loads(json.dumps(session, ensure_ascii=False, default=str))

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        with self._lock:
            session = self._sessions.get(session_id)
            return self._session_view(session) if session else None

    def list_sessions(self, handling_item: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            sessions = list(self._sessions.values())
            if handling_item:
                sessions = [s for s in sessions if s["handling_item"] == handling_item]
            return [self._session_view(s) for s in sessions]

    def _transition(self, session: dict[str, Any], target: str) -> bool:
        if session["status"] == target:
            return True
        allowed = SESSION_TRANSITIONS.get(session["status"], set())
        if target not in allowed:
            return False
        session["status"] = target
        return True

    def _validate_assignment(
        self,
        assignment: dict[str, Any],
        moment: datetime,
    ) -> dict[str, Any] | None:
        """校验会话中的凭据仍然可用；返回问题描述，无问题返回 None。"""
        credential = self._credential(int(assignment.get("credential_id") or 0))
        if credential is None:
            return "凭据不存在"
        status = derive_status(credential, moment)
        if status in UNUSABLE_STATUSES:
            return "凭据不可用：已过期或已吊销"
        expiry = parse_validity(credential.get("有效期"))
        if expiry is not None and expiry <= moment:
            return "凭据不可用：已过有效期"
        binding = self._bindings.get(int(assignment.get("binding_id") or 0))
        if binding is not None and binding.status == BINDING_INVALID:
            return "绑定已失效"
        return None

    def resume_session(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """恢复会话：重新核对可执行绑定，绝不回退到已过期/已吊销凭据。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return {"ok": False, "resumed": False, "message": "会话不存在"}
            if session["status"] == SESSION_CONFLICT:
                return {
                    "ok": False, "resumed": False,
                    "used_expired_credential": False,
                    "message": f"会话已处于{CONFLICT_TERMINAL_STATE}，不可恢复",
                    "session": self._session_view(session),
                }
            moment = self.now(now)
            session["resumes"] += 1
            # 恢复会话必须先核对可执行清单；清单只剩阻断项时不进入会话体
            self.sync_credential_statuses(moment)
            manifest = self.resolve_manifest(
                handling_item=session["handling_item"], now=moment)
            problems: list[str] = []
            switched: list[dict[str, Any]] = []

            for system, assignment in list(session["assignments"].items()):
                problem = self._validate_assignment(assignment, moment)
                if problem is None:
                    continue
                problems.append(f"{system}: {problem}")
                self._expire_stale_bindings(moment)
                previous_id = int(assignment.get("credential_id") or 0)
                if session["boundary"] == BOUNDARY_PAUSE:
                    # 暂停边界只等原凭据轮换，不擅自换用备用凭据
                    original = self._credential(previous_id)
                    if original is not None and self._credential_usable(original, moment):
                        restored = self._bind_rotated(
                            system=system,
                            credential=original,
                            current={
                                "binding_id": assignment.get("binding_id"),
                                "credential_id": previous_id,
                                "env_id": assignment.get("env_id"),
                            },
                            reason="原凭据轮换完成，暂停批次按原凭据恢复",
                            moment=moment,
                            handling_item=session["handling_item"],
                        )
                        assignment.update({
                            "binding_id": restored.binding_id,
                            "credential_id": previous_id,
                            "credential_name": original.get("凭据名称"),
                            "credential_validity": original.get("有效期"),
                            "env_id": restored.env_id,
                            "next_switch_at": next_safe_switch_point(
                                original, moment,
                                standby_available=self.resolve_standby(
                                    system, exclude_id=previous_id, now=moment) is not None,
                            )["at"],
                            "switch_reason": "原凭据轮换完成，暂停批次按原凭据恢复",
                        })
                        record = {
                            "at": moment.isoformat(),
                            "target_system": system,
                            "from_credential_id": previous_id,
                            "to_credential_id": previous_id,
                            "reason": assignment["switch_reason"],
                        }
                        session["switches"].append(record)
                        switched.append(record)
                        continue
                    assignment["switch_reason"] = f"{problem}，等待原凭据轮换完成后恢复"
                    continue
                standby = self._pick_valid_credential(system, exclude_id=previous_id, now=moment)
                if standby is None:
                    assignment["switch_reason"] = (
                        f"{problem}，且无可用备用凭据，等待轮换")
                    continue

                binding = self._rebind_system(
                    system=system,
                    reason=f"{problem}，按清单切换到备用凭据",
                    now=moment,
                    handling_item=session["handling_item"],
                )
                if binding is None:
                    continue
                assignment.update({
                    "binding_id": binding.binding_id,
                    "credential_id": binding.credential_id,
                    "credential_name": standby.get("凭据名称"),
                    "credential_validity": standby.get("有效期"),
                    "env_id": binding.env_id,
                    "next_switch_at": next_safe_switch_point(
                        standby, moment,
                        standby_available=self.resolve_standby(
                            system, exclude_id=binding.credential_id, now=moment) is not None,
                    )["at"],
                    "switch_reason": f"{problem}，已切换到备用凭据 {standby.get('凭据名称')}",
                })
                record = {
                    "at": moment.isoformat(),
                    "target_system": system,
                    "from_credential_id": previous_id,
                    "to_credential_id": binding.credential_id,
                    "reason": assignment["switch_reason"],
                }
                session["switches"].append(record)
                switched.append(record)
                self._log_switch(
                    system=system,
                    from_id=previous_id,
                    to_id=binding.credential_id,
                    binding_id=binding.binding_id,
                    reason=assignment["switch_reason"],
                    now=moment,
                    handling_item=session["handling_item"],
                    boundary=session["boundary"],
                )

            session["updated_at"] = moment.isoformat()

            # 恢复后的凭据必须全部可用，否则会话停在等待轮换
            invalid = [
                system for system, assignment in session["assignments"].items()
                if self._validate_assignment(assignment, moment) is not None
            ]
            if invalid:
                self._transition(session, SESSION_WAITING)
                session["blocked_reason"] = "；".join(problems) or "凭据不可用"
                session["manifest_digest"] = manifest["manifest_digest"]
                return {
                    "ok": False,
                    "resumed": False,
                    "blocked": True,
                    "used_expired_credential": False,
                    "message": session["blocked_reason"],
                    "session": self._session_view(session),
                    "switches": switched,
                }

            session["manifest_digest"] = manifest["manifest_digest"]
            target = SESSION_SWITCHED if switched else SESSION_RESTORED
            if session["status"] == SESSION_ARCHIVED:
                # 归档会话恢复：先进入已恢复，再进入目标状态
                self._transition(session, SESSION_RESTORED)
            self._transition(session, target)
            session["blocked_reason"] = None
            return {
                "ok": True,
                "resumed": True,
                "used_expired_credential": False,
                "message": (
                    f"会话已恢复，切换 {len(switched)} 条凭据"
                    if switched else "会话已按当前有效凭据恢复"
                ),
                "session": self._session_view(session),
                "switches": switched,
            }

    def archive_session(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return {"ok": False, "message": "会话不存在"}
            if not self._transition(session, SESSION_ARCHIVED):
                return {"ok": False, "message": f"当前状态 {session['status']} 不允许归档"}
            session["archived_at"] = self.now().isoformat()
            return {"ok": True, "message": "会话已归档", "session": self._session_view(session)}

    def handle_mid_batch_expiry(
        self,
        session_id: str,
        boundary: str = BOUNDARY_SWITCH,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """批次执行中凭据过期：按边界切换或暂停，两套都不使用过期凭据。"""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise ValueError("会话不存在")
            if boundary not in BOUNDARIES:
                raise ValueError(f"未知处理边界: {boundary}")
            moment = self.now(now)
            # 批次执行到中段：先把有效期推进到状态上，再判断走哪套边界
            self.sync_credential_statuses(moment)

            conflicting = [
                other for other in self._sessions.values()
                if other["handling_item"] == session["handling_item"]
                and other["session_id"] != session_id
                and other["boundary"] != boundary
                and other["status"] not in (SESSION_ARCHIVED, SESSION_CONFLICT)
            ]
            if session["boundary"] != boundary and session["status"] not in (
                SESSION_ARCHIVED, SESSION_CONFLICT,
            ):
                # 同一处理项龙已按另一套边界启动，再按新边界处理即为边界冲突
                conflicting.append(session)

            if conflicting:
                return self._resolve_conflict(session, boundary, moment)

            session["boundary"] = boundary
            session["boundary_label"] = BOUNDARY_LABELS[boundary]

            if boundary == BOUNDARY_SWITCH:
                all_switched = True
                for system, assignment in session["assignments"].items():
                    problem = self._validate_assignment(assignment, moment)
                    if problem is None:
                        continue
                    previous_id = int(assignment.get("credential_id") or 0)
                    standby = self._pick_valid_credential(
                        system, exclude_id=previous_id, now=moment)
                    if standby is None:
                        all_switched = False
                        assignment["switch_reason"] = f"{problem}，无备用凭据可用"
                        continue
                    binding = self._rebind_system(
                        system=system,
                        reason=f"批次执行中{problem}，切换备用凭据继续",
                        now=moment,
                        handling_item=session["handling_item"],
                    )
                    if binding is None:
                        all_switched = False
                        continue
                    assignment.update({
                        "binding_id": binding.binding_id,
                        "credential_id": binding.credential_id,
                        "credential_name": standby.get("凭据名称"),
                        "credential_validity": standby.get("有效期"),
                        "env_id": binding.env_id,
                        "next_switch_at": next_safe_switch_point(
                            standby, moment,
                            standby_available=self.resolve_standby(
                                system, exclude_id=binding.credential_id,
                                now=moment) is not None,
                        )["at"],
                        "switch_reason": f"批次执行中{problem}，已切换备用凭据",
                    })
                    record = {
                        "at": moment.isoformat(),
                        "target_system": system,
                        "from_credential_id": previous_id,
                        "to_credential_id": binding.credential_id,
                        "reason": assignment["switch_reason"],
                        "boundary": boundary,
                    }
                    session["switches"].append(record)

                session["updated_at"] = moment.isoformat()
                invalid = [
                    system for system, assignment in session["assignments"].items()
                    if self._validate_assignment(assignment, moment) is not None
                ]
                if invalid or not all_switched:
                    self._transition(session, SESSION_WAITING)
                    session["blocked_reason"] = "无可用备用凭据，等待原凭据轮换"
                    return {
                        "ok": False,
                        "boundary": boundary,
                        "paused": True,
                        "used_expired_credential": False,
                        "message": session["blocked_reason"],
                        "session": self._session_view(session),
                    }
                self._transition(session, SESSION_SWITCHED)
                session["blocked_reason"] = None
                return {
                    "ok": True,
                    "boundary": boundary,
                    "switched": True,
                    "used_expired_credential": False,
                    "message": "已切换到备用凭据继续当前批次",
                    "session": self._session_view(session),
                }

            # pause_and_wait：暂停批次，等原凭据轮换完成
            self._transition(session, SESSION_WAITING)
            session["paused_at"] = moment.isoformat()
            session["updated_at"] = moment.isoformat()
            session["blocked_reason"] = "批次已暂停，等待原凭据轮换完成"
            return {
                "ok": True,
                "boundary": boundary,
                "paused": True,
                "used_expired_credential": False,
                "message": session["blocked_reason"],
                "session": self._session_view(session),
            }

    def _resolve_conflict(
        self,
        session: dict[str, Any],
        boundary: str,
        moment: datetime,
    ) -> dict[str, Any]:
        """两套处理边界冲突：绑定落到 27号处理终态，会话停止。"""
        affected: list[int] = []
        for assignment in session["assignments"].values():
            binding = self._bindings.get(int(assignment.get("binding_id") or 0))
            if binding is not None:
                binding.status = CONFLICT_TERMINAL_STATE
                binding.terminal_state = CONFLICT_TERMINAL_STATE
                binding.reason = (
                    f"处理边界冲突：{BOUNDARY_LABELS.get(boundary, boundary)} 与 "
                    f"{BOUNDARY_LABELS.get(session['boundary'], session['boundary'])} 同时命中"
                )
                affected.append(binding.binding_id)
        session["updated_at"] = moment.isoformat()
        session["terminal_state"] = CONFLICT_TERMINAL_STATE
        session["status"] = SESSION_CONFLICT
        session["blocked_reason"] = "处理边界冲突，绑定已落到" + CONFLICT_TERMINAL_STATE
        return {
            "ok": False,
            "conflict": True,
            "boundary": boundary,
            "used_expired_credential": False,
            "terminal_state": CONFLICT_TERMINAL_STATE,
            "affected_bindings": affected,
            "message": session["blocked_reason"],
            "session": self._session_view(session),
        }

    # ---- 工作台 ---------------------------------------------------------

    def workbench(self, *, now: datetime | None = None) -> dict[str, Any]:
        """凭据工作台：有效期、当前绑定、切换记录、可执行清单与恢复入口。"""
        moment = self.now(now)
        self.ensure_bindings(moment)
        self.sync_credential_statuses(moment)
        credentials = [
            self.credential_view(row, moment) for row in self._credentials()
        ]
        manifest = self.resolve_manifest(now=moment)
        return {
            "generated_at": moment.isoformat(),
            "credentials": credentials,
            "bindings": self.list_bindings(),
            "switch_records": self.switch_records(),
            "manifest": manifest,
            "summary": {
                "total": len(credentials),
                "normal": sum(1 for c in credentials if c["status"] == STATUS_NORMAL),
                "expiring": sum(1 for c in credentials if c["status"] == STATUS_EXPIRING),
                "expired": sum(1 for c in credentials if c["status"] == STATUS_EXPIRED),
                "revoked": sum(1 for c in credentials if c["status"] == STATUS_REVOKED),
                "history_only": sum(1 for c in credentials if c["history_only"]),
            },
        }

    def list_bindings(self, system: str | None = None) -> list[dict[str, Any]]:
        self.ensure_bindings()
        with self._lock:
            bindings = list(self._bindings.values())
            if system:
                bindings = [b for b in bindings if b.target_system == system]
            return [binding.to_dict() for binding in sorted(
                bindings, key=lambda item: item.binding_id)]

    def domain_snapshot(self) -> dict[str, Any]:
        manifest = self.resolve_manifest()
        self.sync_credential_statuses()
        credentials = self._credentials()
        by_status = {
            status: sum(1 for row in credentials if row.get("status") == status)
            for status in CREDENTIAL_STATUSES
        }
        return {
            "module": self.SERVICE_NAME,
            "entity": "凭据环境绑定",
            "artifact": "可执行环境绑定清单",
            "count": len(self._bindings),
            "by_status": by_status,
            "executable_systems": sum(1 for item in manifest["items"] if item["executable"]),
            "blocked_systems": len(manifest["blocked"]),
            "switch_records": len(self._switch_log),
            "sessions": len(self._sessions),
            "terminal_state": CONFLICT_TERMINAL_STATE,
        }


# 全局单例：凭据工作台、运行会话和链路共用同一份绑定状态
env_binding = CredentialBindingService()
