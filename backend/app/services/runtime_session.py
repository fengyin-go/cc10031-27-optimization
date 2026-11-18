"""运行时会话服务 — 消费定位策略并执行自动化操作。

这是新建的跨模块消费服务（不存在于 spec 的独立模块），
是元素定位链路的末端消费者。

数据流:
    channel("rpa.locator_strategies") ← element_selector
    → runtime_session 消费 → 模拟页面自动化执行
    → channel("rpa.automation_executed") → execution_log
"""
from __future__ import annotations

import random
import uuid
from datetime import datetime, timezone
from typing import Any

from app.services.credential_binding import env_binding
from app.store import store


class RuntimeSessionService:
    """运行时会话管理 — 不继承 BaseModuleService，是纯跨模块消费者。"""

    SERVICE_NAME = "runtime_session"

    def __init__(self) -> None:
        self._sessions: dict[str, dict[str, Any]] = {}

    def consume_strategies_and_execute(self) -> dict[str, Any]:
        """消费定位策略并执行模拟自动化操作。

        从 channel("rpa.locator_strategies") 获取策略，
        模拟在浏览器会话中应用定位规则执行自动化。

        Returns:
            {"executed": int, "session_id": str, "results": [...]}
        """
        msgs = store.channel.consume(
            consumer=self.SERVICE_NAME,
            topic="rpa.locator_strategies",
        )
        if not msgs:
            return {"executed": 0, "session_id": None, "results": []}

        session_id = str(uuid.uuid4())[:8]
        session = {
            "session_id": session_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "strategies_applied": 0,
            "actions_executed": 0,
            "errors": 0,
        }
        results = []

        for msg in msgs:
            strategy = msg.payload
            action_result = self._simulate_automation_action(strategy)

            if action_result["success"]:
                session["actions_executed"] += 1
            else:
                session["errors"] += 1
                # 记录失败到恢复管理器
                store.recovery.log(
                    module=self.SERVICE_NAME,
                    batch_ref=session_id,
                    step=f"apply_locator:{strategy.get('rule_name', 'unknown')}",
                    error_detail=action_result.get("error", "unknown"),
                )

            session["strategies_applied"] += 1
            results.append(action_result)
            store.channel.confirm(msg.msg_id, self.SERVICE_NAME)

        # 发布执行结果
        store.channel.publish(
            topic="rpa.automation_executed",
            source=self.SERVICE_NAME,
            payload={
                "session_id": session_id,
                "total_strategies": len(msgs),
                "successful": session["actions_executed"],
                "failed": session["errors"],
                "results": results,
            },
        )

        self._sessions[session_id] = session
        return {
            "executed": session["actions_executed"],
            "session_id": session_id,
            "total": len(msgs),
            "errors": session["errors"],
            "results": results,
        }

    def _simulate_automation_action(self, strategy: dict[str, Any]) -> dict[str, Any]:
        """模拟自动化操作执行（模拟浏览器元素交互）。

        Args:
            strategy: 定位策略

        Returns:
            {"success": bool, "action": str, "duration_ms": int, ...}
        """
        selector_type = strategy.get("selector_type", "css")
        expression = strategy.get("expression", "")
        wait = strategy.get("wait_condition", "visible")

        # 模拟不同定位策略的成功率
        success_rates = {"id": 0.95, "css": 0.85, "xpath": 0.80, "text": 0.75}
        base_rate = success_rates.get(selector_type, 0.80)

        # 等待条件影响成功率
        if wait == "visible":
            base_rate += 0.05
        elif wait == "none":
            base_rate -= 0.10

        success = random.random() < base_rate
        duration_ms = random.randint(50, 500)

        result = {
            "rule_name": strategy.get("rule_name"),
            "selector_type": selector_type,
            "expression": expression[:50],
            "success": success,
            "duration_ms": duration_ms,
        }

        if success:
            result["action"] = f"定位成功: {strategy.get('rule_name', 'N/A')}"
            result["element_found"] = True
        else:
            result["action"] = "定位失败"
            result["error"] = self._generate_error(selector_type, expression)
            # 尝试回退
            fallback = strategy.get("fallback", "")
            if fallback:
                result["fallback_used"] = fallback
                # 回退一定次数后成功
                if random.random() < 0.5:
                    result["success"] = True
                    result["action"] = f"回退定位成功: {fallback[:30]}"

        return result

    @staticmethod
    def _generate_error(selector_type: str, expression: str) -> str:
        errors = [
            f"选择器超时: 元素 {expression[:30]} 在等待时间内未出现",
            "元素被遮挡，无法交互",
            f"页面动态加载导致 {selector_type} 选择器失效",
            "元素在 iframe 内，需切换上下文",
        ]
        return random.choice(errors)

    def list_sessions(self) -> list[dict[str, Any]]:
        """列出所有运行中的会话。"""
        return list(self._sessions.values())

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        return self._sessions.get(session_id)

    # ---- 凭据环境绑定：按处理项龙边界核对可执行清单 --------------------

    def start_credential_session(
        self,
        handling_item: str,
        boundary: str = "switch_failover",
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """在校验可执行环境绑定清单后启动运行会话。

        会话只持有清单里 executable=True 的绑定；清单为空时进入等待轮换，
        不会退化成「找一条凭据先跑」。
        """
        manifest = env_binding.resolve_manifest(handling_item=handling_item, now=now)
        result = env_binding.start_session(
            handling_item, boundary=boundary, manifest=manifest, now=now)
        session = result["session"]
        self._sessions[session["session_id"]] = {
            "session_id": session["session_id"],
            "started_at": session["created_at"],
            "credential_session": True,
            "handling_item": handling_item,
            "boundary": boundary,
            "status": session["status"],
            "strategies_applied": 0,
            "actions_executed": 0,
            "errors": 0,
            "manifest_digest": manifest.get("manifest_digest"),
            "credential_ids": [
                item["credential_id"] for item in manifest.get("items", [])
                if item.get("executable")
            ],
        }
        return {**result, "manifest": manifest}

    def handle_credential_expiry(
        self,
        session_id: str,
        boundary: str = "switch_failover",
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """同一采集批次执行中凭据过期：按边界切换或暂停，都不使用过期凭据。"""
        result = env_binding.handle_mid_batch_expiry(session_id, boundary, now=now)
        local = self._sessions.get(session_id)
        if local is not None:
            local["status"] = result["session"]["status"]
            local["credential_ids"] = [
                assignment["credential_id"]
                for assignment in result["session"]["assignments"].values()
            ]
        return result

    def resume_credential_session(
        self,
        session_id: str,
        *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """恢复会话：重新核对清单，绝不回退到已过期或已吊销凭据。"""
        result = env_binding.resume_session(session_id, now=now)
        local = self._sessions.get(session_id)
        if local is not None and result.get("session"):
            local["status"] = result["session"]["status"]
            local["credential_ids"] = [
                assignment["credential_id"]
                for assignment in result["session"]["assignments"].values()
            ]
        return result

    def domain_snapshot(self) -> dict[str, Any]:
        credential_snapshot = env_binding.domain_snapshot()
        return {
            "module": self.SERVICE_NAME,
            "entity": "运行时会话",
            "artifact": "自动化执行记录",
            "active_sessions": len(self._sessions),
            "actions_executed": sum(
                s.get("actions_executed", 0) for s in self._sessions.values()),
            "automation_events": len(
                store.channel.snapshot(topic="rpa.automation_executed")),
            "credential_sessions": sum(
                1 for s in self._sessions.values() if s.get("credential_session")),
            "credential_bindings": credential_snapshot["count"],
            "credential_sessions_pending": credential_snapshot["sessions"],
            "terminal_state": credential_snapshot["terminal_state"],
        }


# 全局运行时实例
runtime_session = RuntimeSessionService()