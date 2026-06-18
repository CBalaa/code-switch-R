<template>
  <div class="pool-panel">
    <!-- 子标签页切换 -->
    <div class="pool-sub-tabs">
      <button
        class="sub-tab-pill"
        :class="{ active: subTab === 'providers' }"
        @click="subTab = 'providers'"
      >
        {{ t('components.main.pool.subTabs.providers') }}
      </button>
      <button
        class="sub-tab-pill"
        :class="{ active: subTab === 'pools' }"
        @click="subTab = 'pools'"
      >
        {{ t('components.main.pool.subTabs.pools') }}
      </button>
      <div class="sub-tab-actions">
        <button v-if="subTab === 'providers'" class="sub-tab-action-btn" @click="$emit('addProvider')">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
          </svg>
          {{ t('components.main.pool.addProvider') }}
        </button>
        <button v-if="subTab === 'pools'" class="sub-tab-action-btn" @click="openCreatePool">
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
          </svg>
          {{ t('components.main.pool.createPool') }}
        </button>
      </div>
    </div>

    <!-- 供应商子标签页：原样展示供应商卡片，去掉直接应用/开关 -->
    <div v-if="subTab === 'providers'" class="provider-sub-tab">
      <div class="provider-list">
        <article
          v-for="card in providers"
          :key="card.id"
          class="automation-card pool-provider-card"
          :class="{
            'is-highlighted': highlightedProvider === card.name,
          }"
        >
          <div class="card-leading">
            <div
              :class="['card-icon', { empty: !providerFaviconUrl(card.officialSite) }]"
              :style="{
                backgroundColor: providerFaviconUrl(card.officialSite) ? card.tint : 'transparent',
                color: card.accent,
              }"
            >
              <img
                v-if="providerFaviconUrl(card.officialSite)"
                class="provider-favicon"
                :src="providerFaviconUrl(card.officialSite)"
                :alt="`${card.name} icon`"
                loading="lazy"
                decoding="async"
                @error="markFaviconFailed(card.officialSite)"
                aria-hidden="true"
              />
            </div>
            <div class="card-text">
              <div class="card-title-row">
                <p class="card-title">{{ card.name }}</p>
                <button
                  v-if="card.officialSite"
                  class="card-site"
                  type="button"
                  @click.stop="openOfficialSite(card.officialSite)"
                >
                  {{ formatOfficialSite(card.officialSite) }}
                </button>
              </div>
              <p
                v-for="stats in [providerStatDisplay(card.name)]"
                :key="`metrics-${card.id}`"
                class="card-metrics"
              >
                <template v-if="stats.state !== 'ready'">
                  {{ stats.message }}
                </template>
                <template v-else>
                  <span v-if="stats.successRateLabel" class="card-success-rate" :class="stats.successRateClass">
                    {{ stats.successRateLabel }}
                  </span>
                  <span class="card-metric-separator" aria-hidden="true">·</span>
                  <span>{{ stats.requests }}</span>
                  <span class="card-metric-separator" aria-hidden="true">·</span>
                  <span>{{ stats.tokens }}</span>
                </template>
              </p>
            </div>
          </div>
          <div class="card-actions">
            <!-- 只有编辑和删除按钮，没有开关和直接应用 -->
            <button class="ghost-icon" :data-tooltip="t('components.main.form.editTitle')" @click.stop="$emit('edit', card)">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M11.983 2.25a1.125 1.125 0 011.077.81l.563 2.101a7.482 7.482 0 012.326 1.343l2.08-.621a1.125 1.125 0 011.356.651l1.313 3.207a1.125 1.125 0 01-.442 1.339l-1.86 1.205a7.418 7.418 0 010 2.686l1.86 1.205a1.125 1.125 0 01.442 1.339l-1.313 3.207a1.125 1.125 0 01-1.356.651l-2.08-.621a7.482 7.482 0 01-2.326 1.343l-.563 2.101a1.125 1.125 0 01-1.077.81h-2.634a1.125 1.125 0 01-1.077-.81l-.563-2.101a7.482 7.482 0 01-2.326-1.343l-2.08.621a1.125 1.125 0 01-1.356-.651l-1.313-3.207a1.125 1.125 0 01.442-1.339l1.86-1.205a7.418 7.418 0 010-2.686l-1.86-1.205a1.125 1.125 0 01-.442-1.339l1.313-3.207a1.125 1.125 0 011.356-.651l2.08.621a7.482 7.482 0 012.326-1.343l.563-2.101a1.125 1.125 0 011.077-.81h2.634z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </button>
            <button class="ghost-icon" :data-tooltip="t('components.main.controls.duplicate')" @click.stop="$emit('duplicate', card)">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </button>
            <button class="ghost-icon" :data-tooltip="t('components.main.form.actions.delete')" @click.stop="$emit('remove', card)">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M9 3h6m-7 4h8m-6 0v11m4-11v11M5 7h14l-.867 12.138A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.862L5 7z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </button>
          </div>
        </article>
      </div>
    </div>

    <!-- 池子子标签页 -->
    <div v-if="subTab === 'pools'" class="pool-sub-tab">

      <div class="pool-list">
        <div
          v-for="pool in pools"
          :key="pool.id"
          class="pool-container"

        >
          <div class="pool-header">
            <div class="pool-header-left">
              <span class="pool-name">{{ pool.name }}</span>
            </div>
            <div class="pool-header-right">
              <!-- 模式开关：左=手动(黄色)，右=托管(绿色) -->
              <div class="mode-switch-group">
                <span class="mode-label manual-label" :class="{ active: pool.mode === 'manual' }">{{ t('components.main.pool.modeManual') }}</span>
                <label class="mode-switch">
                  <input
                    type="checkbox"
                    :checked="pool.mode === 'managed'"
                    @change="togglePoolMode(pool.id, ($event.target as HTMLInputElement).checked ? 'managed' : 'manual')"
                  />
                  <span class="mode-track"></span>
                </label>
                <span class="mode-label managed-label" :class="{ active: pool.mode === 'managed' }">{{ t('components.main.pool.modeManaged') }}</span>
              </div>
              <button class="ghost-icon" :data-tooltip="t('components.main.pool.editPool')" @click="openEditPool(pool)">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M11.983 2.25a1.125 1.125 0 011.077.81l.563 2.101a7.482 7.482 0 012.326 1.343l2.08-.621a1.125 1.125 0 011.356.651l1.313 3.207a1.125 1.125 0 01-.442 1.339l-1.86 1.205a7.418 7.418 0 010 2.686l1.86 1.205a1.125 1.125 0 01.442 1.339l-1.313 3.207a1.125 1.125 0 01-1.356.651l-2.08-.621a7.482 7.482 0 01-2.326 1.343l-.563 2.101a1.125 1.125 0 01-1.077.81h-2.634a1.125 1.125 0 01-1.077-.81l-.563-2.101a7.482 7.482 0 01-2.326-1.343l-2.08.621a1.125 1.125 0 01-1.356-.651l-1.313-3.207a1.125 1.125 0 01.442-1.339l1.86-1.205a7.418 7.418 0 010-2.686l-1.86-1.205a1.125 1.125 0 01-.442-1.339l1.313-3.207a1.125 1.125 0 011.356-.651l2.08.621a7.482 7.482 0 012.326-1.343l.563-2.101a1.125 1.125 0 011.077-.81h2.634z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                  <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              </button>
              <button
                class="ghost-icon"
                :data-tooltip="t('components.main.pool.deletePool')"
                @click="requestDeletePool(pool)"
              >
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M9 3h6m-7 4h8m-6 0v11m4-11v11M5 7h14l-.867 12.138A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.862L5 7z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                </svg>
              </button>
            </div>
          </div>

          <!-- 池子内的供应商卡片 -->
          <div class="pool-members">
            <div
              v-for="member in getPoolMembersWithProviders(pool)"
              :key="member.providerId"
              class="pool-member-card"
              :class="{ disabled: pool.mode === 'managed' && !member.memberEnabled }"
            >
              <div class="pool-member-info">
                <div
                  class="pool-member-icon"
                  :style="{
                    backgroundColor: member.faviconUrl ? member.tint : 'transparent',
                    color: member.accent,
                  }"
                >
                  <img
                    v-if="member.faviconUrl"
                    :src="member.faviconUrl"
                    :alt="member.name"
                    loading="lazy"
                    decoding="async"
                    @error="markFaviconFailed(member.officialSite)"
                  />
                </div>
                <span class="pool-member-name">{{ member.name }}</span>
                <!-- 托管模式：池内 Level 选择器 -->
                <select
                  v-if="pool.mode === 'managed'"
                  class="level-select-inline member-level-select"
                  :value="member.memberLevel"
                  @change="updateMemberLevel(pool.id, member.providerId, Number(($event.target as HTMLSelectElement).value))"
                >
                  <option v-for="lvl in 10" :key="lvl" :value="lvl">L{{ lvl }}</option>
                </select>
              </div>
              <div class="pool-member-actions">
                <!-- 托管模式开关 -->
                <label v-if="pool.mode === 'managed'" class="mac-switch sm" :title="t('components.main.pool.memberEnabledHint')">
                  <input
                    type="checkbox"
                    :checked="member.memberEnabled"
                    @change="toggleMemberEnabled(pool.id, member.providerId, ($event.target as HTMLInputElement).checked)"
                  />
                  <span></span>
                </label>
                <!-- 手动模式直接应用按钮 -->
                <button
                  v-if="pool.mode === 'manual'"
                  class="ghost-icon manual-apply-btn"
                  :class="{ 'is-active': isManualApplied(pool, member.providerId) }"
                  :data-tooltip="isManualApplied(pool, member.providerId) ? t('components.main.pool.manualApplied') : t('components.main.pool.manualApply')"
                  @click.stop="setManualProvider(pool.id, member.providerId)"
                >
                  <svg viewBox="0 0 24 24" aria-hidden="true" class="lightning-icon">
                    <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" :fill="isManualApplied(pool, member.providerId) ? 'currentColor' : 'none'" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                </button>
              </div>
            </div>
            <div v-if="getPoolMembersWithProviders(pool).length === 0" class="pool-empty">
              {{ t('components.main.pool.emptyPool') }}
            </div>
          </div>

          <!-- 拉黑状态 -->
          <div v-if="(blacklistStatus.get(pool.id) || []).length > 0" class="pool-blacklist-section">
            <div class="pool-keys-header">{{ t('components.main.pool.blacklistedProviders') }}</div>
            <div class="pool-keys-list">
              <div
                v-for="penalty in blacklistStatus.get(pool.id) || []"
                :key="penalty.providerID"
                class="pool-key-card blacklisted"
              >
                <div class="pool-key-info">
                  <svg viewBox="0 0 24 24" class="key-icon" aria-hidden="true" style="color: var(--color-red, #ef4444);">
                    <path d="M12 2L2 22h20L12 2z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M12 10v4m0 4h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                  </svg>
                  <span class="pool-key-name">{{ getProviderNameById(penalty.providerID) }}</span>
                  <span class="blacklist-time">{{ t('components.main.pool.blacklistRemaining', { minutes: getBlacklistRemainingMinutes(penalty) }) }}</span>
                  <button class="ghost-icon key-unbind-btn" :data-tooltip="t('components.main.pool.unblacklist')" @click.stop="unblacklistProvider(pool.id, penalty.providerID)">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
                    </svg>
                  </button>
                </div>
              </div>
            </div>
          </div>

          <!-- 绑定到该池子的密钥 -->
          <div class="pool-keys-section">
            <div class="pool-keys-header">{{ t('components.main.pool.boundKeys') }}</div>
            <div class="pool-keys-list">
              <div
                v-for="key in getKeysBoundToPool(pool.id)"
                :key="key.id"
                class="pool-key-card"
              >
                <div class="pool-key-info">
                  <svg viewBox="0 0 24 24" class="key-icon" aria-hidden="true">
                    <path d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
                  </svg>
                  <span class="pool-key-name">{{ key.name }}</span>
                  <button class="ghost-icon key-unbind-btn" :data-tooltip="t('components.main.pool.unbindKey')" @click.stop="unbindKey(key.id, pool.id)">
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
                    </svg>
                  </button>
                </div>
              </div>
              <div v-if="getKeysBoundToPool(pool.id).length === 0" class="pool-no-keys">
                {{ t('components.main.pool.noBoundKeys') }}
              </div>
            </div>
          </div>
        </div>

        <div v-if="pools.length === 0" class="pool-list-empty">
          {{ t('components.main.pool.noPools') }}
        </div>
      </div>

      <!-- 未绑定该 platform 任何池子的密钥 -->
      <div v-if="unboundKeys.length > 0" class="unbound-keys-section">
        <div class="unbound-keys-header">{{ t('components.main.pool.unboundKeys') }}</div>
        <div class="unbound-keys-list">
          <div
            v-for="key in unboundKeys"
            :key="key.id"
            class="unbound-key-card"
          >
            <div class="unbound-key-info">
              <svg viewBox="0 0 24 24" class="key-icon" aria-hidden="true">
                <path d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
              <span class="unbound-key-name">{{ key.name }}</span>
            </div>
            <div class="unbound-key-bind">
              <select class="key-bind-select" @change="bindKeyToPool(key.id, ($event.target as HTMLSelectElement).value)">
                <option value="">{{ t('components.main.pool.selectPool') }}</option>
                <option v-for="pool in pools" :key="pool.id" :value="pool.id">{{ pool.name }}</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      <!-- 创建/编辑池子弹窗 -->
      <BaseModal
        :open="poolModalState.open"
        :title="poolModalState.editingId ? t('components.main.pool.editPoolTitle') : t('components.main.pool.createPoolTitle')"
        @close="closePoolModal"
      >
        <form class="vendor-form pool-form" @submit.prevent="submitPoolModal">
          <label class="form-field">
            <span>{{ t('components.main.pool.poolName') }}</span>
            <BaseInput
              v-model="poolModalState.form.name"
              type="text"
              :placeholder="t('components.main.pool.poolNamePlaceholder')"
              required
            />
          </label>

          <div class="form-field">
            <span>{{ t('components.main.pool.poolMode') }}</span>
            <div class="pool-mode-selector">
              <label class="pool-mode-option" :class="{ selected: poolModalState.form.mode === 'managed' }">
                <input type="radio" v-model="poolModalState.form.mode" value="managed" />
                <div class="mode-card">
                  <span class="mode-title">{{ t('components.main.pool.modeManaged') }}</span>
                  <span class="mode-desc">{{ t('components.main.pool.modeManagedDesc') }}</span>
                </div>
              </label>
              <label class="pool-mode-option" :class="{ selected: poolModalState.form.mode === 'manual' }">
                <input type="radio" v-model="poolModalState.form.mode" value="manual" />
                <div class="mode-card">
                  <span class="mode-title">{{ t('components.main.pool.modeManual') }}</span>
                  <span class="mode-desc">{{ t('components.main.pool.modeManualDesc') }}</span>
                </div>
              </label>
            </div>
          </div>

          <!-- 自动拉黑配置（仅 managed 模式） -->
          <div v-if="poolModalState.form.mode === 'managed'" class="form-field">
            <span>{{ t('components.main.pool.autoBlacklist') }}</span>
            <div class="blacklist-config">
              <label class="pool-member-checkbox">
                <input
                  type="checkbox"
                  v-model="poolModalState.form.autoBlacklistEnabled"
                />
                <span class="member-checkbox-label">{{ t('components.main.pool.autoBlacklistEnable') }}</span>
              </label>
              <div v-if="poolModalState.form.autoBlacklistEnabled" class="blacklist-config-inputs">
                <label class="form-field" style="margin-top: 8px;">
                  <span>{{ t('components.main.pool.blacklistThreshold') }}</span>
                  <input
                    type="number"
                    :min="1"
                    :max="100"
                    class="mac-input"
                    v-model.number="poolModalState.form.autoBlacklistThreshold"
                  />
                </label>
                <label class="form-field" style="margin-top: 8px;">
                  <span>{{ t('components.main.pool.blacklistDuration') }}</span>
                  <input
                    type="number"
                    :min="1"
                    :max="1440"
                    class="mac-input"
                    v-model.number="poolModalState.form.autoBlacklistDurationMinutes"
                  />
                </label>
              </div>
            </div>
          </div>

          <!-- 选择池子成员供应商 -->
          <div class="form-field">
            <span>{{ t('components.main.pool.selectMembers') }}</span>
            <div class="pool-member-selector">
              <div
                v-for="p in providers"
                :key="p.id"
                class="pool-member-row"
              >
                <label class="pool-member-checkbox">
                  <input
                    type="checkbox"
                    :value="p.id"
                  :checked="isMemberSelected(p.id)"
                  @change="toggleMemberSelection(p.id, ($event.target as HTMLInputElement).checked)"
                />
                <span class="member-checkbox-label">{{ p.name }}</span>
              </label>
              </div>
              <div v-if="providers.length === 0" class="pool-member-empty">
                {{ t('components.main.pool.noProviders') }}
              </div>
            </div>
          </div>

          <footer class="form-actions">
            <BaseButton variant="outline" type="button" @click="closePoolModal">
              {{ t('components.main.form.actions.cancel') }}
            </BaseButton>
            <BaseButton type="submit">
              {{ t('components.main.form.actions.save') }}
            </BaseButton>
          </footer>
        </form>
      </BaseModal>

      <!-- 删除池子确认框 -->
      <BaseModal
        :open="deleteConfirmState.open"
        :title="t('components.main.pool.deletePoolTitle')"
        variant="confirm"
        @close="closeDeleteConfirm"
      >
        <div class="confirm-body">
          <p>{{ t('components.main.pool.deletePoolMessage', { name: deleteConfirmState.pool?.name ?? '' }) }}</p>
        </div>
        <footer class="form-actions confirm-actions">
          <BaseButton variant="outline" type="button" @click="closeDeleteConfirm">
            {{ t('components.main.form.actions.cancel') }}
          </BaseButton>
          <BaseButton variant="danger" type="button" @click="confirmDeletePool">
            {{ t('components.main.form.actions.delete') }}
          </BaseButton>
        </footer>
      </BaseModal>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseButton from '../common/BaseButton.vue'
import BaseModal from '../common/BaseModal.vue'
import BaseInput from '../common/BaseInput.vue'
import { Events } from '../../wails-runtime'
import { ListPools, SavePool, DeletePool, SetPoolBinding, ListProviderBlacklistStatus, ClearProviderBlacklist, type ProviderPool, type ProviderPoolMode, type ProviderPoolProviderPenalty } from '../../services/providerPool'
import type { AutomationCard } from '../../data/cards'
import { showToast } from '../../utils/toast'

const { t } = useI18n()

const props = defineProps<{
  platform: string
  providers: AutomationCard[]
  relayKeys: Array<{ id: string; name: string; poolBindings?: Record<string, string> }>
  highlightedProvider: string | null
  resolvedTheme: string
  providerFaviconUrl: (site: string) => string | undefined
  markFaviconFailed: (site: string) => void
  formatOfficialSite: (site: string) => string
  openOfficialSite: (url: string) => void
  providerStatDisplay: (name: string) => any
}>()

const emit = defineEmits<{
  edit: [card: AutomationCard]
  remove: [card: AutomationCard]
  duplicate: [card: AutomationCard]
  addProvider: []
  refresh: []
}>()

const subTab = ref<'providers' | 'pools'>('providers')
const pools = ref<ProviderPool[]>([])
let unsubscribeBlacklistChanged: (() => void) | undefined

// favicon 缓存
const faviconCache = new Map<string, string | undefined>()

// 池子弹窗状态
const poolModalState = reactive({
  open: false,
  editingId: '' as string,
  form: {
    name: '',
    mode: 'managed' as ProviderPoolMode,
    manualProviderId: null as number | null,
    memberProviderIds: [] as number[],
    memberLevels: {} as Record<number, number>,
    autoBlacklistEnabled: false,
    autoBlacklistThreshold: 3,
    autoBlacklistDurationMinutes: 10,
  },
})

// 删除确认状态
const deleteConfirmState = reactive({
  open: false,
  pool: null as ProviderPool | null,
})

// 拉黑状态缓存
const blacklistStatus = ref<Map<string, ProviderPoolProviderPenalty[]>>(new Map())

const loadBlacklistStatus = async () => {
  const statusMap = new Map<string, ProviderPoolProviderPenalty[]>()
  for (const pool of pools.value) {
    try {
      const statuses = await ListProviderBlacklistStatus(props.platform, pool.id)
      statusMap.set(pool.id, statuses)
    } catch (error) {
      console.error('Failed to load blacklist status:', error)
    }
  }
  blacklistStatus.value = statusMap
}

type ProviderBlacklistChangedEvent = {
  platform?: string
  poolID?: string
}

const loadBlacklistStatusForPool = async (poolID: string) => {
  if (!pools.value.some((pool) => pool.id === poolID)) {
    return
  }
  try {
    const statuses = await ListProviderBlacklistStatus(props.platform, poolID)
    const next = new Map(blacklistStatus.value)
    next.set(poolID, statuses)
    blacklistStatus.value = next
  } catch (error) {
    console.error('Failed to load blacklist status:', error)
  }
}

const handleProviderBlacklistChanged = (event: { data: ProviderBlacklistChangedEvent }) => {
  const { platform, poolID } = event.data || {}
  if (platform !== props.platform) {
    return
  }
  if (poolID) {
    void loadBlacklistStatusForPool(poolID)
    return
  }
  void loadBlacklistStatus()
}

const loadPools = async () => {
  try {
    pools.value = await ListPools(props.platform)
    await loadBlacklistStatus()
  } catch (error) {
    console.error('Failed to load pools:', error)
    showToast(t('components.main.pool.loadFailed'), 'error')
  }
}

const normalizeProviderId = (value: number | string | null | undefined): number => {
  const id = Number(value)
  return Number.isFinite(id) ? id : -1
}

const sameProviderId = (a: number | string | null | undefined, b: number | string | null | undefined): boolean =>
  normalizeProviderId(a) === normalizeProviderId(b)

const isProviderIdInList = (list: Array<number | string>, providerId: number | string | null | undefined): boolean =>
  list.some((id) => sameProviderId(id, providerId))

interface PoolMemberWithProvider {
  providerId: number
  name: string
  memberEnabled: boolean
  memberLevel: number
  officialSite: string
  faviconUrl: string | undefined
  tint: string
  accent: string
}

const getPoolMembersWithProviders = (pool: ProviderPool): PoolMemberWithProvider[] => {
  return pool.members
    .map((member) => {
      const providerID = normalizeProviderId(member.providerId)
      const provider = props.providers.find((p) => sameProviderId(p.id, providerID))
      if (!provider) return null
      const site = provider.officialSite
      if (!faviconCache.has(site)) {
        faviconCache.set(site, props.providerFaviconUrl(site))
      }
      return {
        providerId: providerID,
        name: provider.name,
        memberEnabled: member.enabled,
        memberLevel: member.level ?? 1,
        officialSite: site,
        faviconUrl: faviconCache.get(site),
        tint: provider.tint,
        accent: provider.accent,
      }
    })
    .filter((m): m is PoolMemberWithProvider => m !== null)
}

const isManualApplied = (pool: ProviderPool, providerId: number) => {
  return pool.mode === 'manual' && pool.manualProviderId != null && sameProviderId(pool.manualProviderId, providerId)
}

// 获取绑定到指定池子的密钥
const getKeysBoundToPool = (poolID: string) => {
  return props.relayKeys.filter((key) => key.poolBindings?.[props.platform] === poolID)
}

// 未绑定该 platform 任何池子的密钥
const unboundKeys = computed(() => {
  return props.relayKeys.filter((key) => !key.poolBindings?.[props.platform])
})

// 绑定密钥到池子
const bindKeyToPool = async (keyID: string, poolID: string) => {
  if (!poolID) return
  try {
    await SetPoolBinding(keyID, props.platform, poolID)
    showToast(t('components.main.pool.keyBound'), 'success')
    emit('refresh')
  } catch (error: any) {
    console.error('Failed to bind key:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
  }
}

// 解绑密钥
const unbindKey = async (keyID: string, poolID: string) => {
  try {
    await SetPoolBinding(keyID, props.platform, '')
    showToast(t('components.main.pool.keyUnbound'), 'success')
    emit('refresh')
  } catch (error: any) {
    console.error('Failed to unbind key:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
  }
}

const togglePoolMode = async (poolID: string, mode: ProviderPoolMode) => {
  const pool = pools.value.find((p) => p.id === poolID)
  if (!pool) return
  pool.mode = mode
  try {
    await SavePool(pool)
    showToast(t('components.main.pool.poolUpdated'), 'success')
  } catch (error: any) {
    console.error('Failed to toggle pool mode:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
    await loadPools()
  }
}

const setManualProvider = async (poolID: string, providerId: number) => {
  const pool = pools.value.find((p) => p.id === poolID)
  if (!pool) return
  pool.manualProviderId = providerId
  try {
    await SavePool(pool)
    showToast(t('components.main.pool.poolUpdated'), 'success')
  } catch (error: any) {
    console.error('Failed to set manual provider:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
    await loadPools()
  }
}

const toggleMemberEnabled = async (poolID: string, providerId: number, enabled: boolean) => {
  const pool = pools.value.find((p) => p.id === poolID)
  if (!pool) return
  const member = pool.members.find((m) => sameProviderId(m.providerId, providerId))
  if (!member) return
  member.enabled = enabled
  try {
    await SavePool(pool)
    showToast(t('components.main.pool.memberUpdated'), 'success')
  } catch (error: any) {
    console.error('Failed to update member:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
    await loadPools()
  }
}

const updateMemberLevel = async (poolID: string, providerId: number, level: number) => {
  const pool = pools.value.find((p) => p.id === poolID)
  if (!pool) return
  const member = pool.members.find((m) => sameProviderId(m.providerId, providerId))
  if (!member) return
  member.level = level
  try {
    await SavePool(pool)
    showToast(t('components.main.pool.memberUpdated'), 'success')
  } catch (error: any) {
    console.error('Failed to update member level:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
    await loadPools()
  }
}

const openCreatePool = () => {
  poolModalState.editingId = ''
  poolModalState.form = {
    name: '',
    mode: 'managed',
    manualProviderId: null,
    memberProviderIds: [],
    memberLevels: {},
    autoBlacklistEnabled: false,
    autoBlacklistThreshold: 3,
    autoBlacklistDurationMinutes: 10,
  }
  poolModalState.open = true
}

const openEditPool = (pool: ProviderPool) => {
  poolModalState.editingId = pool.id
  const levels: Record<number, number> = {}
  for (const m of pool.members) {
    levels[normalizeProviderId(m.providerId)] = m.level ?? 1
  }
  poolModalState.form = {
    name: pool.name,
    mode: pool.mode,
    manualProviderId: pool.manualProviderId ?? null,
    memberProviderIds: pool.members.map((m) => normalizeProviderId(m.providerId)),
    memberLevels: levels,
    autoBlacklistEnabled: pool.autoBlacklistEnabled ?? false,
    autoBlacklistThreshold: pool.autoBlacklistThreshold || 3,
    autoBlacklistDurationMinutes: pool.autoBlacklistDurationMinutes || 10,
  }
  poolModalState.open = true
}

const isMemberSelected = (providerId: number | string): boolean =>
  isProviderIdInList(poolModalState.form.memberProviderIds, providerId)

const getMemberLevel = (providerId: number | string): number =>
  poolModalState.form.memberLevels[normalizeProviderId(providerId)] ?? 1

const closePoolModal = () => {
  poolModalState.open = false
}

const toggleMemberSelection = (providerId: number, checked: boolean) => {
  const normalizedProviderId = normalizeProviderId(providerId)
  if (checked) {
    if (!isMemberSelected(normalizedProviderId)) {
      poolModalState.form.memberProviderIds.push(normalizedProviderId)
    }
    if (!(normalizedProviderId in poolModalState.form.memberLevels)) {
      poolModalState.form.memberLevels[normalizedProviderId] = 1
    }
  } else {
    poolModalState.form.memberProviderIds = poolModalState.form.memberProviderIds.filter((id) => !sameProviderId(id, normalizedProviderId))
    delete poolModalState.form.memberLevels[normalizedProviderId]
  }
}

const setMemberLevel = (providerId: number, level: number) => {
  poolModalState.form.memberLevels[normalizeProviderId(providerId)] = level
}

const submitPoolModal = async () => {
  const { name, mode, memberProviderIds } = poolModalState.form
  const existingPool = poolModalState.editingId
    ? pools.value.find((pool) => pool.id === poolModalState.editingId)
    : null
  const members = memberProviderIds.map((providerId) => {
    const normalizedProviderId = normalizeProviderId(providerId)
    const existingMember = existingPool?.members.find((member) => sameProviderId(member.providerId, normalizedProviderId))
    return {
      providerId: normalizedProviderId,
      enabled: existingMember?.enabled ?? true,
      level: poolModalState.form.memberLevels[normalizedProviderId] ?? 1,
    }
  })
  const existingManualProviderId = existingPool?.manualProviderId ?? null
  const manualProviderId =
    mode === 'manual'
      ? isProviderIdInList(memberProviderIds, existingManualProviderId)
        ? existingManualProviderId
        : memberProviderIds[0] ?? null
      : null

  const poolData: any = {
    platform: props.platform,
    name,
    mode,
    manualProviderId,
    members,
    autoBlacklistEnabled: poolModalState.form.autoBlacklistEnabled,
    autoBlacklistThreshold: poolModalState.form.autoBlacklistThreshold,
    autoBlacklistDurationMinutes: poolModalState.form.autoBlacklistDurationMinutes,
  }

  if (poolModalState.editingId) {
    poolData.id = poolModalState.editingId
  }

  try {
    await SavePool(poolData)
    showToast(
      poolModalState.editingId
        ? t('components.main.pool.poolUpdated')
        : t('components.main.pool.poolCreated'),
      'success'
    )
    closePoolModal()
    await loadPools()
    emit('refresh')
  } catch (error: any) {
    console.error('Failed to save pool:', error)
    showToast(error?.message || t('components.main.pool.saveFailed'), 'error')
  }
}

const requestDeletePool = (pool: ProviderPool) => {
  deleteConfirmState.pool = pool
  deleteConfirmState.open = true
}

// 解除 provider 拉黑
const unblacklistProvider = async (poolID: string, providerID: number) => {
  try {
    await ClearProviderBlacklist(props.platform, poolID, providerID)
    showToast(t('components.main.pool.unblacklisted'), 'success')
    await loadBlacklistStatus()
  } catch (error: any) {
    console.error('Failed to unblacklist:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
  }
}

// 获取 provider 的拉黑剩余时间
const getBlacklistRemainingMinutes = (penalty: ProviderPoolProviderPenalty): number => {
  if (!penalty.blacklistedUntil) return 0
  const until = new Date(penalty.blacklistedUntil).getTime()
  const now = Date.now()
  const remaining = Math.ceil((until - now) / 60000)
  return Math.max(0, remaining)
}

// 根据 provider ID 获取 provider 名称
const getProviderNameById = (providerID: number): string => {
  const provider = props.providers.find((p) => p.id === providerID)
  return provider?.name ?? `Provider #${providerID}`
}

const closeDeleteConfirm = () => {
  deleteConfirmState.open = false
  deleteConfirmState.pool = null
}

const confirmDeletePool = async () => {
  if (!deleteConfirmState.pool) return
  try {
    await DeletePool(deleteConfirmState.pool.id)
    showToast(t('components.main.pool.poolDeleted'), 'success')
    closeDeleteConfirm()
    await loadPools()
    emit('refresh')
  } catch (error: any) {
    console.error('Failed to delete pool:', error)
    showToast(error?.message || t('components.main.pool.deleteFailed'), 'error')
    closeDeleteConfirm()
  }
}

onMounted(() => {
  loadPools()
  unsubscribeBlacklistChanged = Events.On('provider:blacklist:changed', handleProviderBlacklistChanged)
})

onUnmounted(() => {
  if (unsubscribeBlacklistChanged) {
    unsubscribeBlacklistChanged()
    unsubscribeBlacklistChanged = undefined
  }
})

watch(
  () => props.platform,
  () => {
    loadPools()
  }
)
</script>

<style scoped>
.pool-panel {
  width: 100%;
}

/* 子标签页 */
.pool-sub-tabs {
  display: flex;
  align-items: center;
  gap: 4px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--color-border, #e5e7eb);
  padding-bottom: 8px;
}

.sub-tab-pill {
  padding: 6px 16px;
  border: none;
  background: transparent;
  color: var(--color-text-secondary, #6b7280);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  border-radius: 6px 6px 0 0;
  transition: all 0.15s ease;
  position: relative;
}

.sub-tab-pill:hover {
  color: var(--color-text, #1f2937);
  background: var(--color-bg-hover, rgba(0, 0, 0, 0.04));
}

.sub-tab-pill.active {
  color: var(--color-primary, #3b82f6);
  font-weight: 600;
}

.sub-tab-pill.active::after {
  content: '';
  position: absolute;
  bottom: -9px;
  left: 0;
  right: 0;
  height: 2px;
  background: var(--color-primary, #3b82f6);
  border-radius: 1px;
}

/* 子标签页右侧操作按钮 */
.sub-tab-actions {
  margin-left: auto;
  display: flex;
  gap: 8px;
}

.sub-tab-action-btn {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 14px;
  border: 1px dashed var(--color-border, #d1d5db);
  border-radius: 8px;
  background: transparent;
  color: var(--color-text-secondary, #6b7280);
  font-size: 13px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.sub-tab-action-btn:hover {
  border-color: var(--color-primary, #3b82f6);
  color: var(--color-primary, #3b82f6);
  background: var(--color-primary-bg, rgba(59, 130, 246, 0.06));
}

.sub-tab-action-btn svg {
  width: 16px;
  height: 16px;
}

/* 池子容器（大卡片） */
.pool-container {
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 12px;
  margin-bottom: 12px;
  overflow: visible;
  background: var(--color-bg-surface, rgba(255, 255, 255, 0.6));
  transition: border-color 0.15s ease;
}

.pool-container:hover {
  border-color: var(--color-border-hover, #c4c8d0);
}


.pool-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 16px;
  background: var(--color-bg-header, rgba(0, 0, 0, 0.02));
  border-bottom: 1px solid var(--color-border, #e5e7eb);
  border-radius: 12px 12px 0 0;
}

.pool-header-left {
  display: flex;
  align-items: center;
  gap: 8px;
}

.pool-name {
  font-weight: 600;
  font-size: 14px;
  color: var(--color-text, #1f2937);
}

.pool-header-right {
  display: flex;
  align-items: center;
  gap: 4px;
}

/* 模式开关：双色切换 */
.mode-switch-group {
  display: flex;
  align-items: center;
  gap: 4px;
}

.mode-label {
  font-size: 11px;
  font-weight: 500;
  color: var(--color-text-tertiary, #9ca3af);
  transition: color 0.15s;
}

.mode-label.manual-label.active {
  color: #eab308; /* 黄色 */
}

.mode-label.managed-label.active {
  color: #22c55e; /* 绿色 */
}

.mode-switch {
  position: relative;
  display: inline-block;
  width: 36px;
  height: 20px;
  cursor: pointer;
}

.mode-switch input {
  opacity: 0;
  width: 0;
  height: 0;
  position: absolute;
}

.mode-track {
  position: absolute;
  inset: 0;
  border-radius: 10px;
  background: #eab308; /* 黄色=手动 */
  transition: background 0.2s;
}

.mode-switch input:checked + .mode-track {
  background: #22c55e; /* 绿色=托管 */
}

.mode-track::before {
  content: '';
  position: absolute;
  width: 16px;
  height: 16px;
  border-radius: 8px;
  background: white;
  left: 2px;
  top: 2px;
  transition: transform 0.2s;
}

.mode-switch input:checked + .mode-track::before {
  transform: translateX(16px);
}

/* 手动模式直接应用按钮 */
.manual-apply-btn {
  position: relative;
}

.manual-apply-btn.is-active {
  color: #22c55e;
}

.lightning-icon {
  width: 16px;
  height: 16px;
}

/* 池子成员卡片 */
.pool-members {
  padding: 12px;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.pool-member-card {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 8px;
  background: var(--color-bg, #ffffff);
  min-width: 160px;
  transition: opacity 0.15s ease;
}

.pool-member-card.disabled {
  opacity: 0.5;
}

.pool-member-info {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 1;
  min-width: 0;
}

.pool-member-icon {
  width: 24px;
  height: 24px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  flex-shrink: 0;
}

.pool-member-icon img {
  width: 16px;
  height: 16px;
}

.pool-member-name {
  font-size: 13px;
  font-weight: 500;
  color: var(--color-text, #1f2937);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}


.pool-member-actions {
  flex-shrink: 0;
}

.pool-member-level {
  flex-shrink: 0;
  margin-left: 6px;
}

/* 编辑弹窗中每个成员行 */
.pool-member-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 8px;
  padding: 4px 0;
  width: 100%;
}

.member-level-input {
  display: flex;
  align-items: center;
  gap: 4px;
  flex-shrink: 0;
}

.member-level-label {
  font-size: 11px;
  color: var(--color-text-tertiary, #9ca3af);
}

.level-select-inline {
  font-size: 12px;
  padding: 2px 4px;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 4px;
  background: var(--color-bg, #fff);
  color: var(--color-text, #374151);
}

.level-select-inline:focus {
  outline: none;
  border-color: var(--color-accent, #3b82f6);
}

.pool-empty {
  width: 100%;
  text-align: center;
  padding: 16px;
  color: var(--color-text-tertiary, #9ca3af);
  font-size: 13px;
}

/* 池子内密钥区域 */
.pool-keys-section {
  padding: 8px 16px;
  border-top: 1px solid var(--color-border, #e5e7eb);
}

.pool-keys-header {
  font-size: 11px;
  font-weight: 600;
  color: var(--color-text-secondary, #6b7280);
  margin-bottom: 6px;
}

.pool-keys-list {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}

.pool-key-card {
  display: flex;
  align-items: center;
  padding: 4px 10px;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 6px;
  background: var(--color-bg-key, rgba(59, 130, 246, 0.06));
  font-size: 12px;
}

.pool-key-info {
  display: flex;
  align-items: center;
  gap: 4px;
}

.pool-key-name {
  font-weight: 500;
  color: var(--color-text, #1f2937);
}

.key-icon {
  width: 14px;
  height: 14px;
  color: var(--color-primary, #3b82f6);
}

.key-unbind-btn {
  width: 14px;
  height: 14px;
  padding: 0;
  border: none;
  background: transparent;
  color: var(--color-text-tertiary, #9ca3af);
  cursor: pointer;
  opacity: 0.6;
  transition: opacity 0.15s;
}

.key-unbind-btn:hover {
  opacity: 1;
  color: var(--color-danger, #ef4444);
}

.key-unbind-btn svg {
  width: 12px;
  height: 12px;
}

.pool-no-keys {
  font-size: 11px;
  color: var(--color-text-tertiary, #9ca3af);
}

/* 未绑定密钥区域 */
.unbound-keys-section {
  margin-top: 12px;
  border: 1px dashed var(--color-border, #d1d5db);
  border-radius: 10px;
  padding: 12px;
}

.unbound-keys-header {
  font-size: 12px;
  font-weight: 600;
  color: var(--color-text-secondary, #6b7280);
  margin-bottom: 8px;
}

.unbound-keys-list {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.unbound-key-card {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 12px;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 8px;
  background: var(--color-bg, #ffffff);
}

.unbound-key-info {
  display: flex;
  align-items: center;
  gap: 4px;
}

.unbound-key-name {
  font-size: 13px;
  font-weight: 500;
  color: var(--color-text, #1f2937);
}

.key-bind-select {
  padding: 4px 8px;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 6px;
  background: var(--color-bg-input, #ffffff);
  color: var(--color-text, #1f2937);
  font-size: 12px;
}

.pool-list-empty {
  text-align: center;
  padding: 32px;
  color: var(--color-text-tertiary, #9ca3af);
  font-size: 14px;
}

/* 池子表单样式 */
.pool-mode-selector {
  display: flex;
  gap: 8px;
  margin-top: 4px;
}

.pool-mode-option {
  flex: 1;
  cursor: pointer;
}

.pool-mode-option input {
  display: none;
}

.mode-card {
  padding: 12px;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 8px;
  text-align: center;
  transition: all 0.15s ease;
}

.pool-mode-option.selected .mode-card {
  border-color: var(--color-primary, #3b82f6);
  background: var(--color-primary-bg, rgba(59, 130, 246, 0.06));
}

.mode-title {
  display: block;
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 4px;
  color: var(--color-text, #1f2937);
}

.mode-desc {
  display: block;
  font-size: 11px;
  color: var(--color-text-secondary, #6b7280);
  line-height: 1.4;
}

.pool-provider-select {
  width: 100%;
  padding: 8px 12px;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 8px;
  background: var(--color-bg-input, #ffffff);
  color: var(--color-text, #1f2937);
  font-size: 13px;
  margin-top: 4px;
}

.pool-member-selector {
  max-height: 200px;
  overflow-y: auto;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 8px;
  padding: 8px;
  margin-top: 4px;
}

.pool-member-checkbox {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.1s;
  min-width: 0;
}

.pool-member-checkbox:hover {
  background: var(--color-bg-hover, rgba(0, 0, 0, 0.04));
}

.pool-member-checkbox input {
  accent-color: var(--color-primary, #3b82f6);
}

.member-checkbox-label {
  font-size: 13px;
  color: var(--color-text, #1f2937);
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.pool-member-empty {
  text-align: center;
  padding: 8px;
  color: var(--color-text-tertiary, #9ca3af);
  font-size: 12px;
}

/* 供应商子标签页内的卡片（去掉开关/直接应用按钮） */
.pool-provider-card .card-actions {
  gap: 2px;
}
</style>
