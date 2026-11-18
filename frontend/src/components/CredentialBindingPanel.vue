<template>
  <section class="cred-panel" data-testid="credential-workbench">
    <header class="cred-head">
      <div>
        <h3>凭据有效期与环境绑定</h3>
        <p class="page-desc">
          状态由有效期与轮换周期共同推进；切换记录可核对每次绑定的切换原因。
        </p>
      </div>
      <button class="btn" type="button" data-testid="credential-refresh" @click="reload">
        刷新工作台
      </button>
    </header>

    <p v-if="errorMessage" class="error-text">{{ errorMessage }}</p>

    <div class="stat-row">
      <article class="stat-card">
        <span class="stat-label">正常</span>
        <strong class="stat-value" data-testid="summary-normal">{{ summary.normal }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">即将过期</span>
        <strong class="stat-value" data-testid="summary-expiring">{{ summary.expiring }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">已过期</span>
        <strong class="stat-value" data-testid="summary-expired">{{ summary.expired }}</strong>
      </article>
      <article class="stat-card">
        <span class="stat-label">仅历史引用</span>
        <strong class="stat-value" data-testid="summary-history">{{ summary.history_only }}</strong>
      </article>
    </div>

    <table class="data-table">
      <thead>
        <tr>
          <th>凭据</th>
          <th>目标系统</th>
          <th>有效期</th>
          <th>剩余天数</th>
          <th>当前状态</th>
          <th>当前绑定</th>
          <th>下次安全切换</th>
          <th>切换原因</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="row in workbench.credentials"
          :key="row.id"
          :data-testid="`credential-${row.id}`"
          :data-status="row.status"
        >
          <td>{{ row.name }}</td>
          <td>{{ row.target_system }}</td>
          <td>{{ row.validity }}</td>
          <td>{{ row.remaining_days ?? '—' }}</td>
          <td>
            {{ row.status }}
            <span v-if="row.history_only" class="tag">仅历史引用</span>
          </td>
          <td>{{ bindingLabel(row) }}</td>
          <td>{{ formatMoment(row.next_switch_at) }}</td>
          <td class="reason-cell">{{ row.switch_reason }}</td>
        </tr>
        <tr v-if="!workbench.credentials.length">
          <td colspan="8" class="empty-state">暂无凭据数据</td>
        </tr>
      </tbody>
    </table>

    <h4 class="section-title">可执行环境绑定清单</h4>
    <p class="page-desc">
      按处理项龙边界解析：清单只包含未过期、未吊销的凭据。
      <span data-testid="manifest-digest">清单摘要：{{ workbench.manifest.manifest_digest || '—' }}</span>
    </p>
    <table class="data-table">
      <thead>
        <tr>
          <th>目标系统</th>
          <th>绑定凭据</th>
          <th>绑定环境</th>
          <th>下次安全切换点</th>
          <th>备用凭据</th>
          <th>可执行</th>
          <th>排除凭据</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in workbench.manifest.items" :key="item.target_system">
          <td>{{ item.target_system }}</td>
          <td>{{ item.credential_name ?? '—' }}</td>
          <td>{{ item.env_id ?? '—' }}</td>
          <td>{{ formatMoment(item.next_switch_at) }}</td>
          <td>{{ item.standby_credential_id ?? '—' }}</td>
          <td>{{ item.executable ? '可执行' : item.blocked_reason }}</td>
          <td>
            <span
              v-for="excluded in item.excluded_credentials"
              :key="excluded.credential_id"
              class="tag"
            >
              {{ excluded.credential_name }}（{{ excluded.status }}）
            </span>
            <span v-if="!item.excluded_credentials.length">—</span>
          </td>
        </tr>
      </tbody>
    </table>

    <h4 class="section-title">运行会话</h4>
    <form class="filter-bar" @submit.prevent="startSession">
      <label class="filter-item">
        <span>处理项龙</span>
        <input v-model="handlingItem" data-testid="handling-item" placeholder="如 BATCH-1001" />
      </label>
      <label class="filter-item">
        <span>处理边界</span>
        <select v-model="boundary" data-testid="boundary-select">
          <option v-for="item in workbench.boundaries" :key="item.key" :value="item.key">
            {{ item.label }}
          </option>
        </select>
      </label>
      <button class="btn primary" data-testid="start-session" type="submit">启动会话</button>
    </form>
    <p v-if="sessionMessage" class="session-message" data-testid="session-message">
      {{ sessionMessage }}
    </p>

    <table class="data-table">
      <thead>
        <tr>
          <th>会话</th>
          <th>处理项龙</th>
          <th>处理边界</th>
          <th>状态</th>
          <th>凭据选择</th>
          <th>提交计数</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="session in workbench.sessions"
          :key="session.session_id"
          :data-testid="`session-${session.session_id}`"
          :data-status="session.status"
        >
          <td>{{ session.session_id }}</td>
          <td>{{ session.handling_item }}</td>
          <td>{{ session.boundary_label }}</td>
          <td>{{ session.status }}</td>
          <td>
            <div
              v-for="(assignment, system) in session.assignments"
              :key="system"
              class="assignment"
            >
              {{ system }} → {{ assignment.credential_name }}（{{ assignment.credential_validity }}）
            </div>
            <span v-if="!Object.keys(session.assignments).length">—</span>
          </td>
          <td>{{ session.counted_runs }}</td>
          <td class="row-actions">
            <button
              class="link"
              type="button"
              :data-testid="`expiry-${session.session_id}`"
              @click="reportExpiry(session.session_id)"
            >
              模拟批次内过期
            </button>
            <button
              class="link"
              type="button"
              :data-testid="`resume-${session.session_id}`"
              @click="resumeSession(session.session_id)"
            >
              恢复会话
            </button>
            <button
              class="link"
              type="button"
              :data-testid="`archive-${session.session_id}`"
              @click="archiveSession(session.session_id)"
            >
              归档
            </button>
          </td>
        </tr>
        <tr v-if="!workbench.sessions.length">
          <td colspan="7" class="empty-state">暂无运行会话，先按处理项龙启动一次</td>
        </tr>
      </tbody>
    </table>

    <h4 class="section-title">切换记录</h4>
    <table class="data-table">
      <thead>
        <tr>
          <th>时间</th>
          <th>目标系统</th>
          <th>原凭据</th>
          <th>新凭据</th>
          <th>处理项龙</th>
          <th>原因</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="record in recentSwitches" :key="record.seq">
          <td>{{ formatMoment(record.at) }}</td>
          <td>{{ record.target_system }}</td>
          <td>{{ record.from_credential_id ?? '—' }}</td>
          <td>{{ record.to_credential_id ?? '—' }}</td>
          <td>{{ record.handling_item ?? '—' }}</td>
          <td class="reason-cell">{{ record.reason }}</td>
        </tr>
        <tr v-if="!recentSwitches.length">
          <td colspan="6" class="empty-state">暂无切换记录</td>
        </tr>
      </tbody>
    </table>
  </section>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import {
  archiveCredentialSession,
  loadCredentialWorkbench,
  reportSessionExpiry,
  resumeCredentialSession,
  startCredentialSession,
} from '@/api/credential-binding'
import type { CredentialView, CredentialWorkbench } from '@/domain/credential-binding'

const emptyWorkbench: CredentialWorkbench = {
  generated_at: '',
  summary: { total: 0, normal: 0, expiring: 0, expired: 0, revoked: 0, history_only: 0 },
  credentials: [],
  bindings: [],
  switch_records: [],
  manifest: {
    handling_item: null,
    generated_at: '',
    manifest_digest: '',
    executable: false,
    items: [],
    blocked: [],
    excluded_credentials: [],
  },
  boundaries: [],
  sessions: [],
}

const workbench = ref<CredentialWorkbench>(emptyWorkbench)
const errorMessage = ref('')
const sessionMessage = ref('')
const handlingItem = ref('BATCH-1001')
const boundary = ref('switch_failover')

const summary = computed(() => workbench.value.summary)
const recentSwitches = computed(() => [...workbench.value.switch_records].reverse().slice(0, 10))

function bindingLabel(row: CredentialView): string {
  const binding = row.current_binding
  if (!binding) return '未绑定'
  return `#${binding.binding_id} / ${binding.status}${binding.usable ? '' : '（不可用）'}`
}

function formatMoment(value: string | null | undefined): string {
  if (!value) return '—'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString('zh-CN', { hour12: false })
}

async function reload() {
  errorMessage.value = ''
  try {
    workbench.value = await loadCredentialWorkbench()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '凭据工作台读取失败'
  }
}

async function startSession() {
  errorMessage.value = ''
  sessionMessage.value = ''
  try {
    const result = await startCredentialSession(handlingItem.value.trim(), boundary.value)
    sessionMessage.value = result.session
      ? `${result.deduplicated ? '重复提交已合并' : '会话已启动'}：${result.session.status}（计入 ${result.counted_runs} 次）`
      : result.message ?? '会话未启动'
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '会话启动失败'
  }
}

async function reportExpiry(sessionId: string) {
  errorMessage.value = ''
  try {
    const result = await reportSessionExpiry(sessionId, boundary.value)
    sessionMessage.value = result.message ?? ''
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '边界处理失败'
  }
}

async function resumeSession(sessionId: string) {
  errorMessage.value = ''
  try {
    const result = await resumeCredentialSession(sessionId)
    sessionMessage.value = result.message ?? ''
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '会话恢复失败'
  }
}

async function archiveSession(sessionId: string) {
  errorMessage.value = ''
  try {
    const result = await archiveCredentialSession(sessionId)
    sessionMessage.value = result.message ?? ''
    await reload()
  } catch (error) {
    errorMessage.value = error instanceof Error ? error.message : '会话归档失败'
  }
}

onMounted(reload)
</script>

<style scoped>
.cred-panel { margin-top: 24px; border-top: 2px solid var(--border); padding-top: 12px; }
.cred-head { display: flex; justify-content: space-between; align-items: flex-start; }
.cred-head h3 { margin: 8px 0 4px; font-size: 15px; }
.section-title { margin: 20px 0 6px; font-size: 14px; }
.reason-cell { max-width: 280px; }
.tag {
  display: inline-block;
  margin-left: 4px;
  padding: 1px 6px;
  border-radius: 10px;
  background: #eef2ff;
  color: #4338ca;
  font-size: 11px;
}
.assignment { font-size: 12px; }
.session-message { font-size: 13px; color: #0f766e; }
.filter-item select { padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; }
</style>
