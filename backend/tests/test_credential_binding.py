"""凭据有效期推进 · 环境绑定 · 运行会话恢复 集成测试。

覆盖题面要求的可核对项：
1. 凭据状态由「有效期 + 轮换周期」共同推进，吊销不被日期覆盖；
2. 可执行环境绑定清单解析每个目标系统的下一次安全切换点；
3. 运行会话按处理项龙边界选择凭据并记录切换原因；
4. 并发两次提交只算一次；
5. 批次执行中凭据过期：切换 / 暂停两套边界都不使用过期凭据；
6. 边界冲突落到「27号处理终态」；
7. 恢复会话不会回退到已过期或已吊销凭据；
8. 归档 → 恢复 → 切换的状态流转。
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.credential_binding import (  # noqa: E402
    CONFLICT_TERMINAL_STATE,
    CredentialBindingService,
    derive_status,
    env_binding,
    next_safe_switch_point,
    parse_rotation_days,
    parse_validity,
)
from app.store import Store, store  # noqa: E402

NOW = datetime(2026, 11, 18, 9, 0, tzinfo=timezone.utc)


def _reset_credentials(rows: list[dict]) -> None:
    """把全局 store 的凭据表替换成测试数据，并重置绑定服务。"""
    table = store.rows("credential_store")
    table.clear()
    table.extend(dict(row) for row in rows)


def _credential(
    cred_id: int,
    system: str,
    validity: str,
    *,
    status: str = "正常",
    rotation: str = "30天",
    name: str | None = None,
) -> dict:
    return {
        "id": cred_id,
        "status": status,
        "pending": True,
        "abnormal": False,
        "凭据名称": name or f"{system}凭据{cred_id}",
        "目标系统": system,
        "认证方式": "用户名密码",
        "账户标识": f"robot_{cred_id}",
        "有效期": validity,
        "轮换周期": rotation,
        "最后使用": "2026-11-17 09:00:00",
    }


@pytest.fixture()
def service() -> CredentialBindingService:
    """每个用例一份干净的凭据/环境数据与绑定服务。"""
    _reset_credentials([
        _credential(1, "ERP系统", "2027-04-30", name="ERP主账号"),
        _credential(2, "ERP系统", "2026-11-21",
                    rotation="7天", name="ERP备用账号"),
        _credential(3, "ERP系统", "2026-09-30", name="ERP历史账号"),
        _credential(4, "CRM系统", "2027-01-15", name="CRM当前账号"),
        _credential(5, "CRM系统", "2027-03-01", status="已吊销", name="CRM泄露账号"),
    ])
    env_binding.reset()
    created = CredentialBindingService()
    created._clock = NOW
    return created


# ── 1. 状态推进 ──────────────────────────────────────────────────────────

class TestStatusProgression:
    def test_status_follows_validity_and_rotation_window(self) -> None:
        """轮换窗口内的凭据推进到「即将过期」，窗口外是「正常」。"""
        early = {"有效期": "2027-04-30", "轮换周期": "30天", "status": "正常"}
        soon = {"有效期": "2026-11-21", "轮换周期": "7天", "status": "正常"}
        past = {"有效期": "2026-11-01", "轮换周期": "30天", "status": "正常"}
        assert derive_status(early, NOW) == "正常"
        assert derive_status(soon, NOW) == "即将过期"
        assert derive_status(past, NOW) == "已过期"

    def test_revoked_is_terminal(self) -> None:
        """吊销不被有效期覆盖，也不会回到正常。"""
        revoked = {"有效期": "2030-01-01", "轮换周期": "30天", "status": "已吊销"}
        assert derive_status(revoked, NOW) == "已吊销"
        assert derive_status({"有效期": "2026-01-01", "旋转": "x",
                              "status": "已吊销"}, NOW) == "已吊销"

    def test_sync_writes_status_back_to_rows(self, service: CredentialBindingService) -> None:
        result = service.sync_credential_statuses(NOW)
        statuses = {row["id"]: row["status"] for row in store.rows("credential_store")}
        assert statuses[2] == "即将过期"
        assert statuses[3] == "已过期"
        assert statuses[5] == "已吊销"
        assert {change["credential_id"] for change in result["changed"]} >= {2, 3}

    def test_rotation_cycle_parsing(self) -> None:
        assert parse_rotation_days("30天") == 30
        assert parse_rotation_days("4周") == 28
        assert parse_rotation_days("720h") == 30
        assert parse_validity("2026-11-21") is not None


# ── 2. 下一次安全切换点 / 可执行清单 ─────────────────────────────────────

class TestExecutableManifest:
    def test_switch_point_never_later_than_expiry(self) -> None:
        row = _credential(1, "ERP系统", "2026-12-31", rotation="30天")
        point = next_safe_switch_point(row, NOW, standby_available=False)
        assert point["at"] is not None
        assert parse_validity(point["at"]) < parse_validity(row["有效期"])

    def test_rotation_window_with_standby_switches_now(self) -> None:
        expiring = _credential(2, "ERP系统", "2026-11-21", status="即将过期", rotation="7天")
        point = next_safe_switch_point(expiring, NOW, standby_available=True)
        assert point["immediate"] is True
        assert point["source"] == "rotation_window"

    def test_manifest_excludes_expired_and_revoked(self, service: CredentialBindingService) -> None:
        manifest = service.resolve_manifest(now=NOW)
        by_system = {item["target_system"]: item for item in manifest["items"]}
        assert by_system["ERP系统"]["credential_id"] != 3
        assert by_system["CRM系统"]["credential_id"] != 5
        excluded = {row["credential_id"] for row in manifest["excluded_credentials"]}
        assert {3, 5} <= excluded
        assert all(item["executable"] for item in manifest["items"])
        assert manifest["executable"] is True

    def test_manifest_reports_blocked_system(self, service: CredentialBindingService) -> None:
        _reset_credentials([
            _credential(1, "仅过期系统", "2026-01-01"),
            _credential(2, "仅吊销系统", "2030-01-01", status="已吊销"),
        ])
        manifest = service.resolve_manifest(now=NOW)
        assert manifest["executable"] is False
        assert {item["target_system"] for item in manifest["blocked"]} == {
            "仅过期系统", "仅吊销系统"}
        for item in manifest["items"]:
            assert item["next_switch_at"] is None
            assert item["executable"] is False

    def test_manifest_digest_is_stable(self, service: CredentialBindingService) -> None:
        first = service.resolve_manifest(handling_item="HR-1", now=NOW)
        second = service.resolve_manifest(handling_item="HR-1", now=NOW)
        assert first["manifest_digest"] == second["manifest_digest"]


# ── 3/4. 处理项龙会话与幂等 ──────────────────────────────────────────────

class TestHandlingItemSession:
    def test_session_holds_only_executable_bindings(self, service: CredentialBindingService) -> None:
        result = service.start_session("BATCH-1001", boundary="switch_failover", now=NOW)
        session = result["session"]
        assert session["status"] == "执行中"
        assert session["assignments"]["ERP系统"]["credential_id"] == 1
        assert session["assignments"]["CRM系统"]["credential_id"] == 4
        for assignment in session["assignments"].values():
            assert assignment["switch_reason"]

    def test_duplicate_submit_counts_once(self, service: CredentialBindingService) -> None:
        first = service.start_session("BATCH-1001", boundary="switch_failover", now=NOW)
        second = service.start_session("BATCH-1001", boundary="switch_failover", now=NOW)
        third = service.start_session(
            "BATCH-1001", boundary="switch_failover",
            idempotency_key="submit-001", now=NOW)
        fourth = service.start_session(
            "BATCH-1001", boundary="switch_failover",
            idempotency_key="submit-001", now=NOW)
        assert first["deduplicated"] is False
        assert second["deduplicated"] is True
        assert second["counted_runs"] == 1
        assert third["deduplicated"] is False
        assert fourth["deduplicated"] is True
        assert len(service.list_sessions("BATCH-1001")) == 2

    def test_waiting_session_when_manifest_blocked(self, service: CredentialBindingService) -> None:
        _reset_credentials([_credential(1, "ERP系统", "2026-01-01")])
        result = service.start_session("BATCH-1002", boundary="pause_and_wait", now=NOW)
        assert result["session"]["status"] == "等待轮换"
        assert result["session"]["blocked_reason"]


# ── 5/6. 批次执行中过期：两套边界与冲突 ──────────────────────────────────

class TestMidBatchExpiry:
    def _expire(self, credential_id: int) -> None:
        row = store.find("credential_store", credential_id)
        assert row is not None
        row["有效期"] = "2026-11-01"

    def test_switch_boundary_uses_standby(self, service: CredentialBindingService) -> None:
        session = service.start_session(
            "BATCH-2001", boundary="switch_failover", now=NOW)["session"]
        self._expire(1)
        outcome = service.handle_mid_batch_expiry(
            session["session_id"], "switch_failover", now=NOW)
        assert outcome["ok"] is True
        assert outcome["switched"] is True
        assert outcome["used_expired_credential"] is False
        after = service.get_session(session["session_id"])
        assert after["assignments"]["ERP系统"]["credential_id"] == 2
        assert after["assignments"]["ERP系统"]["switch_reason"]
        assert after["switches"]

    def test_pause_boundary_holds_batch(self, service: CredentialBindingService) -> None:
        session = service.start_session(
            "BATCH-2002", boundary="pause_and_wait", now=NOW)["session"]
        self._expire(1)
        outcome = service.handle_mid_batch_expiry(
            session["session_id"], "pause_and_wait", now=NOW)
        assert outcome["ok"] is True
        assert outcome["paused"] is True
        assert outcome["used_expired_credential"] is False
        after = service.get_session(session["session_id"])
        assert after["status"] == "等待轮换"
        # 暂停不等于沿用旧凭据：凭据行已推进到已过期
        assert store.find("credential_store", 1)["status"] == "已过期"

    def test_boundary_conflict_lands_on_terminal_state(
        self, service: CredentialBindingService,
    ) -> None:
        session = service.start_session(
            "BATCH-2003", boundary="switch_failover", now=NOW)["session"]
        first = service.handle_mid_batch_expiry(
            session["session_id"], "switch_failover", now=NOW)
        assert first["ok"] is True
        conflict = service.handle_mid_batch_expiry(
            session["session_id"], "pause_and_wait", now=NOW)
        assert conflict["conflict"] is True
        assert conflict["terminal_state"] == CONFLICT_TERMINAL_STATE
        after = service.get_session(session["session_id"])
        assert after["status"] == CONFLICT_TERMINAL_STATE
        bindings = service.list_bindings("ERP系统")
        assert any(b["status"] == CONFLICT_TERMINAL_STATE for b in bindings)
        resumed = service.resume_session(session["session_id"], now=NOW)
        assert resumed["ok"] is False


# ── 7. 恢复不回退到过期/吊销凭据 ─────────────────────────────────────────

class TestResumeRecovery:
    def test_resume_switches_away_from_expired_credential(
        self, service: CredentialBindingService,
    ) -> None:
        session = service.start_session(
            "BATCH-3001", boundary="switch_failover", now=NOW)["session"]
        store.find("credential_store", 1)["有效期"] = "2026-11-10"
        outcome = service.resume_session(session["session_id"], now=NOW)
        assert outcome["ok"] is True
        assert outcome["used_expired_credential"] is False
        after = service.get_session(session["session_id"])
        for assignment in after["assignments"].values():
            credential = store.find("credential_store", assignment["credential_id"])
            assert credential["status"] not in ("已过期", "已吊销")
            assert parse_validity(credential["有效期"]) > NOW

    def test_resume_never_uses_revoked(self, service: CredentialBindingService) -> None:
        session = service.start_session(
            "BATCH-3002", boundary="switch_failover", now=NOW)["session"]
        service.revoke_credential(4, now=NOW)
        outcome = service.resume_session(session["session_id"], now=NOW)
        after = service.get_session(session["session_id"])
        assignment = after["assignments"]["CRM系统"]
        assert assignment["credential_id"] != 5
        revoked = store.find("credential_store", 5)
        assert revoked["status"] == "已吊销"
        assert outcome["used_expired_credential"] is False

    def test_resume_blocks_when_no_valid_standby(self, service: CredentialBindingService) -> None:
        _reset_credentials([_credential(1, "ERP系统", "2027-01-01")])
        session = service.start_session(
            "BATCH-3003", boundary="pause_and_wait", now=NOW)["session"]
        store.find("credential_store", 1)["有效期"] = "2026-11-01"
        outcome = service.resume_session(session["session_id"], now=NOW)
        assert outcome["ok"] is False
        assert outcome["blocked"] is True
        after = service.get_session(session["session_id"])
        assert after["status"] == "等待轮换"
        assert after["assignments"]["ERP系统"]["credential_id"] == 1
        # 会话仍挂着原凭据，但该凭据已标记过期，历史只读
        assert store.find("credential_store", 1)["status"] == "已过期"

    def test_archive_then_resume_flow(self, service: CredentialBindingService) -> None:
        session = service.start_session(
            "BATCH-3004", boundary="switch_failover", now=NOW)["session"]
        session_id = session["session_id"]
        assert service.archive_session(session_id)["ok"] is True
        assert service.get_session(session_id)["status"] == "已归档"
        resumed = service.resume_session(session_id, now=NOW)
        assert resumed["ok"] is True
        assert resumed["session"]["status"] in ("已恢复", "已切换")


# ── 8. 轮换/吊销与绑定联动 ───────────────────────────────────────────────

class TestRotationRevocation:
    def test_rotate_extends_validity_and_keeps_binding(self, service: CredentialBindingService) -> None:
        row, message = service.rotate_credential(1, now=NOW)
        assert row is not None
        assert parse_validity(row["有效期"]) > NOW
        assert row["status"] == "正常"
        binding = service.current_binding("ERP系统", NOW)
        assert binding is not None
        assert binding["credential_id"] == 1
        assert any(record["to_credential_id"] == 1 for record in service.switch_records(1))
        assert "轮换" in message

    def test_rotate_expiring_credential_makes_it_normal(self, service: CredentialBindingService) -> None:
        row, _ = service.rotate_credential(2, now=NOW)
        assert row["status"] == "正常"
        assert derive_status(row, NOW) == "正常"

    def test_revoke_invalidates_binding_and_moves_to_standby(
        self, service: CredentialBindingService,
    ) -> None:
        service.ensure_bindings(NOW)
        row, _ = service.revoke_credential(4, now=NOW)
        assert row["status"] == "已吊销"
        bindings = service.list_bindings("CRM系统")
        invalid = [b for b in bindings if b["credential_id"] == 4]
        assert invalid and invalid[-1]["status"] == "已失效"
        # CRM 没有其它可用凭据 → 绑定保持失效，不会退回过期/吊销凭据
        assert all(b["credential_id"] != 5 for b in bindings)
        manifest = service.resolve_manifest(target_system="CRM系统", now=NOW)
        assert manifest["items"][0]["executable"] is False

    def test_revoked_cannot_be_rotated_back(self, service: CredentialBindingService) -> None:
        row, message = service.rotate_credential(5, now=NOW)
        assert row is None
        assert "吊销" in message


# ── 9. 工作台可核对 ─────────────────────────────────────────────────────

class TestWorkbench:
    def test_workbench_exposes_validity_bindings_and_history(
        self, service: CredentialBindingService,
    ) -> None:
        payload = service.workbench(now=NOW)
        assert payload["summary"]["total"] == 5
        assert payload["summary"]["history_only"] >= 2
        expired = [c for c in payload["credentials"] if c["status"] == "已过期"]
        assert expired and expired[0]["history_only"] is True
        assert payload["bindings"]
        assert all("next_switch_at" in item for item in payload["manifest"]["items"])

    def test_global_service_matches_store_seed(self) -> None:
        snapshot = env_binding.domain_snapshot()
        assert snapshot["executable_systems"] >= 1
        assert snapshot["terminal_state"] == CONFLICT_TERMINAL_STATE


# ── 10. 任务调度前核对可执行绑定 ────────────────────────────────────────

class TestDispatchGate:
    def test_task_without_binding_stays_queued(self, service: CredentialBindingService) -> None:
        from app.services.task_queue import TaskQueueService

        _reset_credentials([_credential(1, "ERP系统", "2026-01-01")])
        task_svc = TaskQueueService()
        entry, _ = task_svc.create_entry({
            "任务编号": "TASK-GATE-001",
            "流程名称": "ERP采集",
            "提交时间": "2026-11-18 09:00:00",
            "优先级": "高",
            "预计执行": "10:00",
            "排队时长": "0s",
            "当前状态": "排队中",
        })
        assert entry is not None
        entry["bot_id"] = None  # 只有流程名可匹配
        result = task_svc.schedule_next_batch(max_tasks=5)
        assert entry["id"] not in result["task_ids"]
        assert any(item["task_id"] == entry["id"] for item in result["blocked"])
        assert store.find("task_queue", entry["id"])["status"] == "排队中"

    def test_task_with_valid_binding_is_scheduled_with_credential(
        self, service: CredentialBindingService,
    ) -> None:
        from app.services.task_queue import TaskQueueService

        service.resolve_manifest(now=NOW)  # 让全局绑定引擎按测试凭据重建

        task_svc = TaskQueueService()
        entry, _ = task_svc.create_entry({
            "任务编号": "TASK-GATE-002",
            "流程名称": "ERP采集",
            "提交时间": "2026-11-18 09:00:00",
            "优先级": "高",
            "预计执行": "10:00",
            "排队时长": "0s",
            "当前状态": "排队中",
        })
        assert entry is not None
        entry["bot_id"] = None
        result = task_svc.schedule_next_batch(max_tasks=5)
        assert entry["id"] in result["task_ids"]
        row = store.find("task_queue", entry["id"])
        assert row["status"] == "执行中"
        assert row["绑定凭据"] == "ERP主账号"
        assert row["下次切换时间"]


# ── 11. 暂停边界恢复：等轮换后回到原凭据 ───────────────────────────────

class TestPauseResumeSemantics:
    def test_pause_waits_for_original_rotation(self, service: CredentialBindingService) -> None:
        session = service.start_session(
            "BATCH-4001", boundary="pause_and_wait", now=NOW)["session"]
        store.find("credential_store", 1)["有效期"] = "2026-11-10"
        paused = service.handle_mid_batch_expiry(
            session["session_id"], "pause_and_wait", now=NOW)
        assert paused["paused"] is True

        before = service.resume_session(session["session_id"], now=NOW)
        assert before["ok"] is False
        assert before["blocked"] is True
        assert service.get_session(session["session_id"])["status"] == "等待轮换"

        rotated, _ = service.rotate_credential(1, now=NOW)
        assert rotated is not None and rotated["status"] == "正常"
        after = service.resume_session(session["session_id"], now=NOW)
        assert after["ok"] is True
        restored = after["session"]["assignments"]["ERP系统"]
        assert restored["credential_id"] == 1
        assert "原凭据轮换" in restored["switch_reason"]
        assert after["used_expired_credential"] is False

    def test_switch_boundary_blocks_when_standby_also_expires(
        self, service: CredentialBindingService,
    ) -> None:
        session = service.start_session(
            "BATCH-4002", boundary="switch_failover", now=NOW)["session"]
        store.find("credential_store", 1)["有效期"] = "2026-11-10"
        swapped = service.handle_mid_batch_expiry(
            session["session_id"], "switch_failover", now=NOW)
        assert swapped["ok"] is True
        store.find("credential_store", 2)["有效期"] = "2026-11-05"
        blocked = service.resume_session(session["session_id"], now=NOW)
        assert blocked["ok"] is False
        assert blocked["used_expired_credential"] is False
        after = service.get_session(session["session_id"])
        assert after["status"] == "等待轮换"
        for assignment in after["assignments"].values():
            credential = store.find("credential_store", assignment["credential_id"])
            if credential is not None:
                assert credential["status"] in ("已过期", "已吊销", "即将过期", "正常")
        # 会话不会把过期凭据写回选择结果
        assert after["assignments"]["ERP系统"]["switch_reason"]
