"""凭据管理领域服务 — 安全凭据生命周期，输出 domain_snapshot。

数据工程核心：数据入湖存储与分区管理 — 跨模块数据产物

凭据状态与绑定生效时间共同推进：
- 「有效期」+「轮换周期」决定状态（正常 / 即将过期 / 已过期）；
- 「吊销」是人工终态，不会被日期覆盖，也不会回到正常；
- 每次轮换/吊销都会推进环境绑定并写入切换记录，
  运行时恢复只按可执行环境绑定清单选择未过期、未吊销的凭据。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.services.base import BaseModuleService
from app.services.credential_binding import (
    STATUS_NORMAL,
    STATUS_REVOKED,
    BOUNDARIES,
    BOUNDARY_LABELS,
    env_binding,
    next_safe_switch_point,
)
from app.store import store


class CredentialStoreService(BaseModuleService):
    MODULE = "credential_store"
    ENTITY = "系统凭据"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["凭据名称", "目标系统", "认证方式", "账户标识", "有效期", "轮换周期", "最后使用"]
    REQUIRED_FIELDS = ["凭据名称", "目标系统", "认证方式"]
    STATUS_ORDER = ["正常", "即将过期", "已过期", "已吊销"]
    # 轮换把凭据推进到正常（同时延长有效期）；吊销落到已吊销终态。
    # 状态与有效期日期共同决定绑定何时切换，因此这里不再把吊销改回正常。
    ACTION_RULES = {"轮换凭据": "正常", "吊销凭据": "已吊销"}
    NEGATIVE_ACTIONS = ["吊销凭据"]

    def list_entries(self, *args: Any, **kwargs: Any):
        """列表读取即推进一次状态，保证工作台看到的有效期与状态一致。"""
        env_binding.sync_credential_statuses()
        items, total = super().list_entries(*args, **kwargs)
        for item in items:
            view = env_binding.credential_view(item)
            item["剩余天数"] = view["remaining_days"]
            item["当前绑定凭据"] = (view["current_binding"] or {}).get("credential_id")
            item["下次切换时间"] = view["next_switch_at"]
            item["切换原因"] = view["switch_reason"]
        return items, total

    def create_entry(self, values: dict[str, Any]):
        entry, missing = super().create_entry(values)
        if entry is not None:
            # 新登记的凭据先按有效期定状态，再参与绑定解析
            from app.services.credential_binding import derive_status
            entry["status"] = derive_status(entry)
            entry["abnormal"] = entry["status"] != STATUS_NORMAL
            entry["pending"] = entry["status"] != STATUS_REVOKED
            env_binding.sync_credential_statuses()
        return entry, missing

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        """动作接口：轮换/吊销走后端绑定服务，其余动作仍按通用规则流转。"""
        if action == "轮换凭据":
            return env_binding.rotate_credential(entry_id)
        if action == "吊销凭据":
            return env_binding.revoke_credential(entry_id)
        return super().run_action(entry_id, action)

    # ---- 工作台 ----

    def workbench(self, now: datetime | None = None) -> dict[str, Any]:
        """凭据工作台数据：有效期、当前绑定、切换记录与恢复入口。"""
        payload = env_binding.workbench(now=now)
        payload["boundaries"] = [
            {"key": key, "label": BOUNDARY_LABELS[key]} for key in BOUNDARIES
        ]
        payload["sessions"] = env_binding.list_sessions()
        return payload

    # ---- 跨模块业务方法 ----

    def check_expiring_credentials(self) -> dict[str, Any]:
        """检查即将过期/已过期的凭据列表。"""
        env_binding.sync_credential_statuses()
        rows = store.rows(self.MODULE)
        expiring = [
            {
                "id": row.get("id"),
                "name": row.get("凭据名称"),
                "system": row.get("目标系统"),
                "auth_type": row.get("认证方式"),
                "expiry": row.get("有效期"),
                "rotation": row.get("轮换周期"),
                "status": row.get("status"),
                "next_switch_at": next_safe_switch_point(row)["at"],
            }
            for row in rows if row.get("status") in ("即将过期", "已过期")
        ]
        return {
            "total_expiring": len(expiring),
            "expiring_credentials": expiring,
            "normal_count": sum(1 for row in rows if row.get("status") == STATUS_NORMAL),
        }

    def get_system_credentials(self, system: str) -> list[dict[str, Any]]:
        """查询指定目标系统的凭据状态（只返回仍在有效期内的）。"""
        env_binding.sync_credential_statuses()
        rows = store.rows(self.MODULE)
        return [
            {
                "id": row.get("id"),
                "name": row.get("凭据名称"),
                "auth_type": row.get("认证方式"),
                "status": row.get("status"),
                "last_used": row.get("最后使用"),
                "validity": row.get("有效期"),
            }
            for row in rows
            if system in row.get("目标系统", "")
            and row.get("status") in ("正常", "即将过期")
        ]

    def resolve_executable_manifest(
        self,
        *,
        target_system: str | None = None,
        handling_item: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """为运行时消费方生成可执行环境绑定清单。"""
        return env_binding.resolve_manifest(
            target_system=target_system,
            handling_item=handling_item,
            now=now,
        )

    def domain_snapshot(self) -> dict[str, Any]:
        base = super().domain_snapshot()
        expiring = self.check_expiring_credentials()
        binding_snapshot = env_binding.domain_snapshot()
        return {
            **base,
            "expiring_count": expiring["total_expiring"],
            "bindings": binding_snapshot["count"],
            "executable_systems": binding_snapshot["executable_systems"],
            "blocked_systems": binding_snapshot["blocked_systems"],
            "switch_records": binding_snapshot["switch_records"],
            "sessions": binding_snapshot["sessions"],
            "terminal_state": binding_snapshot["terminal_state"],
        }
