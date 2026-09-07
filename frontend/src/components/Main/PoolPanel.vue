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
              <!-- 普通池模式开关：左=手动(黄色)，右=托管(绿色) -->
              <div v-if="!isAccountPool(pool)" class="mode-switch-group">
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
              <span v-else class="account-managed-badge">
                {{ t('components.main.pool.accountManagedOnly') }}
              </span>
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
          <div v-if="!isAccountPool(pool)" class="pool-members">
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

          <!-- 号池配置摘要 -->
          <div v-else class="account-pool-summary">
            <div class="account-pool-endpoint">
              <span class="account-summary-label">{{ t('components.main.pool.accountPoolBaseUrl') }}</span>
              <span class="account-summary-value">{{ pool.accountPoolConfig?.apiUrl || '-' }}</span>
            </div>
            <div class="account-pool-endpoint">
              <span class="account-summary-label">{{ t('components.main.pool.responsesEndpoint') }}</span>
              <span class="account-summary-value">{{ pool.accountPoolConfig?.responsesEndpoint || '/responses' }}</span>
            </div>
            <div class="account-pool-keys">
              <div class="account-keys-heading">
                <div class="account-keys-heading-main">
                  <span class="account-summary-label">{{ t('components.main.pool.accountPoolKeys') }}</span>
                  <span class="account-key-count">{{ t('components.main.pool.accountKeyCount', { count: pool.accountPoolConfig?.keys?.length || 0 }) }}</span>
                </div>
                <div class="account-keys-heading-actions">
                  <div class="account-key-status" role="status">
                    <span class="account-key-status-available">
                      {{ t('components.main.pool.accountKeyAvailable', { count: getAvailableAccountKeys(pool).length }) }}
                    </span>
                    <span :class="['account-key-status-blacklisted', { active: getBlacklistedAccountKeys(pool).length > 0 }]">
                      {{ t('components.main.pool.accountKeyBlacklisted', { count: getBlacklistedAccountKeys(pool).length }) }}
                    </span>
                  </div>
                  <button
                    v-if="getBlacklistedAccountKeys(pool).length > 0"
                    type="button"
                    class="account-key-clear-blacklists-button"
                    :disabled="isClearingAllBlacklists(pool.id)"
                    @click="clearAllAccountPoolBlacklists(pool)"
                  >
                    {{ t('components.main.pool.clearAllBlacklists') }}
                  </button>
                  <button
                    type="button"
                    class="account-key-collapse-button"
                    :aria-expanded="!isAccountKeysCollapsed(pool.id)"
                    :aria-label="isAccountKeysCollapsed(pool.id) ? t('components.main.pool.expandAccountKeys') : t('components.main.pool.collapseAccountKeys')"
                    :data-tooltip="isAccountKeysCollapsed(pool.id) ? t('components.main.pool.expandAccountKeys') : t('components.main.pool.collapseAccountKeys')"
                    @click="toggleAccountKeysCollapsed(pool.id)"
                  >
                    <svg :class="{ expanded: !isAccountKeysCollapsed(pool.id) }" viewBox="0 0 20 20" aria-hidden="true">
                      <path d="m5 7.5 5 5 5-5" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
                    </svg>
                  </button>
                </div>
              </div>
              <div v-if="!isAccountKeysCollapsed(pool.id)" class="account-key-list">
                <div
                  v-for="key in getAvailableAccountKeys(pool)"
                  :key="key.id"
                  class="account-key-row"
                >
                  <span class="account-key-chip">{{ maskAccountKey(key.apiKey) }}</span>
                </div>
                <div
                  v-for="key in getBlacklistedAccountKeys(pool)"
                  :key="key.id"
                  class="account-key-row account-key-row-blacklisted"
                  :title="getBlacklistPenalty(pool, key.id)?.lastReason || ''"
                >
                  <svg viewBox="0 0 24 24" class="blacklist-key-icon" aria-hidden="true">
                    <path d="M12 2 2 21h20L12 2Z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round" />
                    <path d="M12 9v5m0 3h.01" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" />
                  </svg>
                  <span class="account-key-chip">{{ maskAccountKey(key.apiKey) }}</span>
                  <span class="blacklist-reason-prefix">{{ t('components.main.pool.blacklistReasonPrefix') }}</span>
                  <span class="blacklist-reason">{{ getBlacklistReason(pool, key.id) }}</span>
                  <span class="blacklist-reason-suffix">{{ t('components.main.pool.blacklistReasonSuffix') }}</span>
                  <span class="blacklist-time"><span class="blacklist-minutes">{{ getBlacklistRemainingMinutes(getBlacklistPenalty(pool, key.id)!) }}</span> {{ t('components.main.pool.blacklistMinutes') }}</span>
                  <button class="ghost-icon key-unbind-btn" :data-tooltip="t('components.main.pool.unblacklist')" @click.stop="unblacklistProvider(pool.id, key.id)">
                    <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 18 18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" /></svg>
                  </button>
                </div>
                <span v-if="!(pool.accountPoolConfig?.keys?.length)" class="pool-no-keys">
                  {{ t('components.main.pool.noAccountKeys') }}
                </span>
              </div>
            </div>
          </div>

          <!-- 拉黑状态 -->
          <div v-if="!isAccountPool(pool) && (blacklistStatus.get(pool.id) || []).length > 0" class="pool-blacklist-section">
            <div class="pool-keys-header">
              {{ isAccountPool(pool) ? t('components.main.pool.blacklistedKeys') : t('components.main.pool.blacklistedProviders') }}
            </div>
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
                  <span class="pool-key-name">{{ getBlacklistSubjectName(pool, penalty.providerID) }}</span>
                  <span class="blacklist-reason-prefix">{{ t('components.main.pool.blacklistReasonPrefix') }}</span>
                  <span class="blacklist-reason">{{ getPenaltyReason(pool, penalty) }}</span>
                  <span class="blacklist-reason-suffix">{{ t('components.main.pool.blacklistReasonSuffix') }}</span>
                  <span class="blacklist-time"><span class="blacklist-minutes">{{ getBlacklistRemainingMinutes(penalty) }}</span> {{ t('components.main.pool.blacklistMinutes') }}</span>
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
        :size="poolModalState.form.poolType === 'account' ? 'wide' : 'default'"
        @close="closePoolModal()"
      >
        <form class="vendor-form pool-form" @submit.prevent="submitPoolModal()">
          <label class="form-field">
            <span>{{ t('components.main.pool.poolName') }}</span>
            <BaseInput
              v-model="poolModalState.form.name"
              type="text"
              :placeholder="t('components.main.pool.poolNamePlaceholder')"
              required
            />
          </label>

          <div v-if="props.platform === 'openai-responses'" class="form-field">
            <span>{{ t('components.main.pool.poolType') }}</span>
            <div class="pool-type-selector" :class="{ disabled: !!poolModalState.editingId }">
              <label class="pool-type-option" :class="{ selected: poolModalState.form.poolType === 'normal' }">
                <input
                  v-model="poolModalState.form.poolType"
                  type="radio"
                  value="normal"
                  :disabled="!!poolModalState.editingId"
                />
                <span>{{ t('components.main.pool.poolTypeNormal') }}</span>
              </label>
              <label class="pool-type-option" :class="{ selected: poolModalState.form.poolType === 'account' }">
                <input
                  v-model="poolModalState.form.poolType"
                  type="radio"
                  value="account"
                  :disabled="!!poolModalState.editingId"
                />
                <span>{{ t('components.main.pool.poolTypeAccount') }}</span>
              </label>
            </div>
            <span v-if="poolModalState.editingId" class="form-field-hint">
              {{ t('components.main.pool.poolTypeImmutable') }}
            </span>
          </div>

          <div v-if="poolModalState.form.poolType === 'normal'" class="form-field">
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

          <div v-else class="account-managed-notice">
            <span class="account-managed-dot" aria-hidden="true"></span>
            <span>{{ t('components.main.pool.accountManagedOnly') }}</span>
          </div>

          <!-- 普通池自动拉黑配置（仅 managed 模式） -->
          <div v-if="poolModalState.form.poolType === 'normal' && poolModalState.form.mode === 'managed'" class="form-field">
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

          <!-- 号池上游与密钥配置 -->
          <template v-if="poolModalState.form.poolType === 'account'">
            <label class="form-field">
              <span>{{ t('components.main.pool.accountPoolBaseUrl') }}</span>
              <input
                v-model="poolModalState.form.accountApiUrl"
                class="mac-input"
                type="url"
                :placeholder="t('components.main.pool.accountPoolBaseUrlPlaceholder')"
                required
              />
            </label>

            <label class="form-field">
              <span>{{ t('components.main.pool.responsesEndpoint') }}</span>
              <input
                v-model="poolModalState.form.accountResponsesEndpoint"
                class="mac-input"
                type="text"
                :placeholder="t('components.main.pool.responsesEndpointPlaceholder')"
                required
              />
            </label>

            <label class="form-field">
              <span>{{ t('components.main.pool.accountPoolKeys') }}</span>
              <textarea
                v-model="poolModalState.form.accountKeysText"
                class="mac-input account-keys-textarea"
                :placeholder="t('components.main.pool.accountPoolKeysPlaceholder')"
                autocomplete="off"
                autocapitalize="off"
                spellcheck="false"
                required
              ></textarea>
              <span class="form-field-hint">{{ t('components.main.pool.accountPoolKeysHint') }}</span>
            </label>

            <div class="form-field pool-proxy-section">
              <label class="pool-member-checkbox">
                <input
                  v-model="poolModalState.form.proxyEnabled"
                  type="checkbox"
                  @change="toggleProxyEnabled"
                />
                <span class="member-checkbox-label">{{ t('components.main.pool.useProxy') }}</span>
              </label>
              <span class="form-field-hint">{{ t('components.main.pool.proxySharedHint') }}</span>

              <div v-if="poolModalState.form.proxyEnabled" class="pool-proxy-config">
                <span v-if="!proxyConfigsLoading && !hasProxyNodes" class="form-field-hint pool-proxy-error">
                  {{ t('components.main.pool.proxyConfigRequired') }}
                </span>

                <section class="proxy-strategy-group" :aria-label="t('components.main.pool.proxySelection')">
                  <div class="proxy-strategy-group-heading">
                    <span>{{ t('components.main.pool.proxySelection') }}</span>
                    <span v-if="proxyLastTestedLabel" class="proxy-last-tested">{{ proxyLastTestedLabel }}</span>
                    <button
                      type="button"
                      class="sub-tab-action-btn proxy-bulk-test-button"
                      :disabled="proxyBulkTestLoading || proxyConfigsLoading || proxyUploadLoading || proxySubscriptionImportLoading || proxyConfigActionLoading !== null || !hasProxyNodes"
                      @click="testAllProxyLatencies"
                    >
                      {{ proxyBulkTestLoading ? t('components.main.pool.proxyBulkTesting') : t('components.main.pool.testAllProxyLatencies') }}
                    </button>
                  </div>

                  <div
                    class="proxy-strategy-board"
                    role="radiogroup"
                    :aria-label="t('components.main.pool.proxySelection')"
                    :aria-busy="proxyBulkTestLoading"
                  >
                    <label
                      class="proxy-strategy-card proxy-auto-card"
                      :class="{ selected: poolModalState.form.proxySelection === 'auto', disabled: proxyConfigsLoading || !hasProxyNodes }"
                    >
                      <input
                        class="proxy-strategy-radio"
                        type="radio"
                        name="pool-proxy-selection"
                        :checked="poolModalState.form.proxySelection === 'auto'"
                        :disabled="proxyConfigsLoading || !hasProxyNodes"
                        @change="selectAutoProxy"
                      />
                      <span class="proxy-strategy-card-content">
                        <span class="proxy-strategy-card-name">{{ t('components.main.pool.proxyAuto') }}</span>
                        <span class="proxy-auto-selection">
                          <span class="proxy-auto-selected-node" :title="proxyAutoSelectedNode?.name || ''">
                            {{ proxyAutoSelectedNode?.name || '-' }}
                          </span>
                          <span
                            class="proxy-strategy-latency"
                            :class="proxyAutoLatencyClass"
                            :title="proxyAutoLatencyTooltip"
                          >
                            {{ proxyAutoLatencyLabel }}
                          </span>
                        </span>
                      </span>
                    </label>

                    <section
                      v-for="config in proxyConfigs"
                      :key="config.id"
                      class="proxy-config-section"
                    >
                      <button
                        type="button"
                        class="proxy-config-disclosure"
                        :aria-expanded="isProxyConfigExpanded(config.id)"
                        :aria-controls="isProxyConfigExpanded(config.id) ? proxyConfigNodesRegionID(config.id) : undefined"
                        @click="toggleProxyConfigExpanded(config.id)"
                      >
                        <span class="proxy-config-disclosure-copy">
                          <span class="proxy-config-disclosure-name">{{ proxyConfigFileName(config) }}</span>
                          <span class="proxy-config-disclosure-meta">
                            {{ t('components.main.pool.proxyConfigNodeCount', { count: config.nodes.length }) }}
                          </span>
                        </span>
                        <span
                          class="proxy-config-disclosure-indicator"
                          :class="{ expanded: isProxyConfigExpanded(config.id) }"
                          aria-hidden="true"
                        ></span>
                      </button>

                      <div
                        v-if="isProxyConfigExpanded(config.id)"
                        :id="proxyConfigNodesRegionID(config.id)"
                        class="proxy-node-grid"
                      >
                        <label
                          v-for="node in config.nodes"
                          :key="node.id"
                          class="proxy-strategy-card proxy-node-card"
                          :class="{ selected: isSelectedProxyNode(node.id), disabled: proxyConfigsLoading }"
                          @click="selectProxyNodeIfAvailable(node.id)"
                        >
                          <input
                            class="proxy-strategy-radio"
                            type="radio"
                            name="pool-proxy-selection"
                            :checked="isSelectedProxyNode(node.id)"
                            :disabled="proxyConfigsLoading"
                            @change="selectProxyNode(node.id)"
                          />
                          <span class="proxy-strategy-card-content">
                            <span class="proxy-strategy-card-name">{{ node.originalName || node.name }}</span>
                            <span class="proxy-node-metrics">
                              <span class="proxy-node-metric">
                                <span class="proxy-node-metric-label">{{ t('components.main.pool.localProxyLatency') }}</span>
                                <span class="proxy-strategy-latency" :class="proxyNodeLatencyClass(node.id)" :title="proxyNodeLatencyTooltip(node.id)">
                                  {{ proxyNodeLatencyLabel(node.id) }}
                                </span>
                              </span>
                              <span class="proxy-node-metric">
                                <span class="proxy-node-metric-label">{{ t('components.main.pool.proxiedBaseLatency') }}</span>
                                <span class="proxy-strategy-latency" :class="proxyNodeResponsesClass(node.id)" :title="proxyNodeResponsesTooltip(node.id)">
                                  {{ proxyNodeResponsesLabel(node.id) }}
                                </span>
                              </span>
                            </span>
                          </span>
                        </label>
                      </div>
                    </section>
                  </div>

                  <span v-if="proxyNodeSelectionRequired" class="form-field-hint pool-proxy-error" role="alert">
                    {{ selectedProxyNodeHidden ? t('components.main.pool.proxyNodeHidden') : t('components.main.pool.proxyNodeRequired') }}
                  </span>
                  <label v-if="poolModalState.form.proxySelection === 'auto'" class="pool-member-checkbox proxy-auto-disable-toggle">
                    <input v-model="poolModalState.form.autoDisableProxyWhenNoAvailable" type="checkbox" />
                    <span class="member-checkbox-label">{{ t('components.main.pool.autoDisableProxyWhenNoAvailable') }}</span>
                    <span class="form-field-hint">{{ t('components.main.pool.autoDisableProxyWhenNoAvailableHint') }}</span>
                  </label>
                  <span class="sr-only" aria-live="polite">
                    {{ proxyBulkTestLoading ? t('components.main.pool.proxyBulkTesting') : '' }}
                  </span>
                </section>

                <div class="proxy-upload-row">
                  <label :class="['sub-tab-action-btn', 'proxy-upload-button', proxyUploadLoading || proxySubscriptionImportLoading || proxyBulkTestLoading ? 'disabled' : '']">
                    {{ proxyUploadLoading ? t('components.main.pool.proxyUploading') : t('components.main.pool.uploadProxyConfig') }}
                    <input type="file" accept=".yaml,.yml" :disabled="proxyUploadLoading || proxySubscriptionImportLoading || proxyBulkTestLoading" @change="uploadProxyConfig" />
                  </label>
                  <button type="button" class="sub-tab-action-btn" :disabled="proxyUploadLoading || proxySubscriptionImportLoading || proxyBulkTestLoading || proxyConfigActionLoading !== null" @click="importProxySubscription">
                    {{ proxySubscriptionImportLoading ? t('components.main.pool.proxySubscriptionImporting') : t('components.main.pool.importProxySubscription') }}
                  </button>
                  <button type="button" class="sub-tab-action-btn" :disabled="proxyConfigsLoading || proxyUploadLoading || proxySubscriptionImportLoading || proxyBulkTestLoading || proxyConfigActionLoading !== null" @click="loadProxyConfigs">
                    {{ proxyConfigsLoading ? t('components.main.pool.proxyRefreshing') : t('components.main.pool.refreshProxyConfigs') }}
                  </button>
                </div>

                <div class="proxy-config-list">
                  <div v-for="config in proxyConfigs" :key="config.id" class="proxy-config-item">
                    <div class="proxy-config-details">
                      <span class="proxy-config-name">{{ proxyConfigFileName(config) }}</span>
                      <span class="proxy-config-meta">
                        {{ t('components.main.pool.proxyConfigUploadedBy', { uploader: config.uploader }) }}
                        <span aria-hidden="true">&middot;</span>
                        {{ t('components.main.pool.proxyConfigNodeCount', { count: config.nodes.length }) }}
                      </span>
                    </div>
                    <button
                      v-if="config.isOwner"
                      class="proxy-config-action is-danger"
                      type="button"
                      :data-tooltip="t('components.main.pool.deleteProxyConfig')"
                      :aria-label="t('components.main.pool.deleteProxyConfig')"
                      :disabled="proxyConfigsLoading || proxyUploadLoading || proxySubscriptionImportLoading || proxyBulkTestLoading || proxyConfigActionLoading !== null"
                      @click="deleteProxyConfig(config)"
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M9 3h6m-7 4h8m-6 0v11m4-11v11M5 7h14l-.867 12.138A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.862L5 7z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                      </svg>
                    </button>
                    <button
                      v-else
                      class="proxy-config-action"
                      type="button"
                      :data-tooltip="t('components.main.pool.hideProxyConfig')"
                      :aria-label="t('components.main.pool.hideProxyConfig')"
                      :disabled="proxyConfigsLoading || proxyUploadLoading || proxySubscriptionImportLoading || proxyBulkTestLoading || proxyConfigActionLoading !== null"
                      @click="hideProxyConfig(config)"
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M3 3l18 18M10.584 10.587a2 2 0 002.829 2.829M9.88 4.24A10.94 10.94 0 0112 4c5.5 0 9.27 4.11 10 8-.33 1.76-1.32 3.42-2.82 4.75M6.61 6.61C4.5 8.03 3.3 10.06 2 12c.73 3.89 4.5 8 10 8 1.82 0 3.42-.45 4.75-1.22" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                      </svg>
                    </button>
                  </div>
                  <span v-if="!proxyConfigsLoading && proxyConfigs.length === 0" class="form-field-hint">
                    {{ t('components.main.pool.noProxyConfigs') }}
                  </span>
                </div>

                <div v-if="hiddenProxyConfigs.length > 0" class="proxy-hidden-configs">
                  <span class="proxy-hidden-configs-heading">{{ t('components.main.pool.hiddenProxyConfigs') }}</span>
                  <div v-for="config in hiddenProxyConfigs" :key="config.id" class="proxy-config-item">
                    <div class="proxy-config-details">
                      <span class="proxy-config-name">{{ proxyConfigFileName(config) }}</span>
                      <span class="proxy-config-meta">
                        {{ t('components.main.pool.proxyConfigUploadedBy', { uploader: config.uploader }) }}
                        <span aria-hidden="true">&middot;</span>
                        {{ t('components.main.pool.proxyConfigNodeCount', { count: config.nodes.length }) }}
                      </span>
                    </div>
                    <button
                      class="proxy-config-action"
                      type="button"
                      :data-tooltip="t('components.main.pool.unhideProxyConfig')"
                      :aria-label="t('components.main.pool.unhideProxyConfig')"
                      :disabled="proxyConfigsLoading || proxyUploadLoading || proxySubscriptionImportLoading || proxyBulkTestLoading || proxyConfigActionLoading !== null"
                      @click="unhideProxyConfig(config)"
                    >
                      <svg viewBox="0 0 24 24" aria-hidden="true">
                        <path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12zM12 15a3 3 0 100-6 3 3 0 000 6z" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
                      </svg>
                    </button>
                  </div>
                </div>

              </div>
            </div>

            <div class="form-field">
              <span>{{ t('components.main.pool.autoBlacklist') }}</span>
              <div class="blacklist-config-inputs account-blacklist-inputs">
                <label class="form-field">
                  <span>{{ t('components.main.pool.blacklistThreshold') }}</span>
                  <input
                    v-model.number="poolModalState.form.autoBlacklistThreshold"
                    type="number"
                    :min="1"
                    :max="100"
                    class="mac-input"
                    required
                  />
                </label>
                <label class="form-field">
                  <span>{{ t('components.main.pool.blacklistDuration') }}</span>
                  <input
                    v-model.number="poolModalState.form.autoBlacklistDurationMinutes"
                    type="number"
                    :min="1"
                    :max="1440"
                    class="mac-input"
                    required
                  />
                </label>
              </div>
            </div>
          </template>

          <div
            v-if="poolModalState.form.poolType === 'account' || poolModalState.form.mode === 'managed'"
            class="form-field special-blacklist-rules"
          >
            <div class="special-rules-heading">
              <span>{{ t('components.main.pool.specialBlacklistRules') }}</span>
              <button class="ghost-icon" type="button" :data-tooltip="t('components.main.pool.addSpecialBlacklistRule')" @click="addSpecialBlacklistRule">
                <svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 5v14m-7-7h14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg>
              </button>
            </div>
            <p class="form-field-hint">{{ t('components.main.pool.specialBlacklistRulesHint') }}</p>
            <div v-for="(rule, index) in poolModalState.form.specialBlacklistRules" :key="rule.id || index" class="special-rule-row">
              <label class="form-field"><span>{{ t('components.main.pool.specialRuleName') }}</span><input v-model="rule.name" class="mac-input" type="text" required /></label>
              <label class="form-field"><span>{{ t('components.main.pool.specialRuleHttpStatus') }}</span><input v-model.number="rule.httpStatus" class="mac-input" type="number" min="100" max="599" required /></label>
              <label class="form-field"><span>{{ t('components.main.pool.specialRuleJsonPath') }}</span><input v-model="rule.jsonPath" class="mac-input" type="text" placeholder="error.code" /></label>
              <label class="form-field"><span>{{ t('components.main.pool.specialRuleJsonValue') }}</span><input v-model="rule.expectedJsonValue" class="mac-input" type="text" placeholder='"rate_limit"' /></label>
              <label class="form-field"><span>{{ t('components.main.pool.blacklistThreshold') }}</span><input v-model.number="rule.threshold" class="mac-input" type="number" min="1" max="100" required /></label>
              <label class="form-field">
                <span>{{ t('components.main.pool.specialRuleDurationType') }}</span>
                <select
                  class="mac-select"
                  :value="rule.durationType"
                  @change="rule.durationType = (($event.target as HTMLSelectElement).value as SpecialBlacklistDurationType)"
                >
                  <option value="duration">{{ t('components.main.pool.specialRuleDurationMode') }}</option>
                  <option value="until">{{ t('components.main.pool.specialRuleUntilMode') }}</option>
                </select>
              </label>
              <label v-if="rule.durationType !== 'until'" class="form-field"><span>{{ t('components.main.pool.blacklistDuration') }}</span><input v-model.number="rule.durationMinutes" class="mac-input" type="number" min="1" max="144000" required /></label>
              <template v-else>
                <label class="form-field"><span>{{ t('components.main.pool.specialRuleUntilDayOffset') }}</span><input v-model.number="rule.untilDayOffset" class="mac-input" type="number" min="0" max="99" required /></label>
                <label class="form-field"><span>{{ t('components.main.pool.specialRuleUntilTime') }}</span><input v-model="rule.untilTime" class="mac-input" type="time" required /></label>
              </template>
              <div class="special-rule-actions">
                <button class="ghost-icon" type="button" :disabled="index === 0" :data-tooltip="t('components.main.pool.moveRuleUp')" @click="moveSpecialBlacklistRule(index, -1)"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 14 6-6 6 6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg></button>
                <button class="ghost-icon" type="button" :disabled="index === poolModalState.form.specialBlacklistRules.length - 1" :data-tooltip="t('components.main.pool.moveRuleDown')" @click="moveSpecialBlacklistRule(index, 1)"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 10 6 6 6-6" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" /></svg></button>
                <button class="ghost-icon" type="button" :data-tooltip="t('components.main.pool.deleteSpecialBlacklistRule')" @click="removeSpecialBlacklistRule(index)"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 18 18 6M6 6l12 12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" /></svg></button>
              </div>
            </div>
          </div>

          <div class="form-field">
            <span>{{ t('components.main.pool.firstTextRetry') }}</span>
            <div class="blacklist-config">
              <label class="pool-member-checkbox">
                <input v-model="poolModalState.form.firstTextRetryEnabled" type="checkbox" />
                <span class="member-checkbox-label">{{ t('components.main.pool.firstTextRetryEnable') }}</span>
              </label>
              <div v-if="poolModalState.form.firstTextRetryEnabled" class="blacklist-config-inputs">
                <label class="form-field" style="margin-top: 8px;">
                  <span>{{ t('components.main.pool.firstTextRetryTimeoutSeconds') }}</span>
                  <input
                    v-model.number="poolModalState.form.firstTextRetryTimeoutSeconds"
                    type="number"
                    min="5"
                    max="240"
                    step="1"
                    class="mac-input"
                    required
                  />
                  <span class="form-field-hint">{{ t('components.main.pool.firstTextRetryHint') }}</span>
                </label>
              </div>
            </div>
          </div>

          <div v-if="poolModalState.form.poolType === 'account'" class="account-log-options">
            <label class="pool-member-checkbox account-option-toggle">
              <input v-model="poolModalState.form.excludeFromTotalTraffic" type="checkbox" />
              <span class="member-checkbox-label">{{ t('components.main.pool.excludeFromTotalTraffic') }}</span>
              <span class="form-field-hint">{{ t('components.main.pool.excludeFromTotalTrafficHint') }}</span>
            </label>
            <label class="pool-member-checkbox account-option-toggle">
              <input v-model="poolModalState.form.hideFromLogs" type="checkbox" />
              <span class="member-checkbox-label">{{ t('components.main.pool.hideFromLogs') }}</span>
              <span class="form-field-hint">{{ t('components.main.pool.hideFromLogsHint') }}</span>
            </label>
          </div>

          <!-- 普通池成员供应商 -->
          <div v-if="poolModalState.form.poolType === 'normal'" class="form-field">
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
            <BaseButton variant="outline" type="button" @click="closePoolModal()">
              {{ t('components.main.form.actions.cancel') }}
            </BaseButton>
            <BaseButton type="submit" :disabled="poolSaveLoading || proxyConfigRequired || proxyNodeSelectionRequired">
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
import {
  ListPools,
  SavePool,
  DeletePool,
  SetPoolBinding,
  ListProviderBlacklistStatus,
  ClearProviderBlacklist,
  ClearAllProviderBlacklists,
  ListProxyConfigs,
  RefreshProxyConfigs,
  UploadProxyConfig,
  ImportProxySubscription,
  DeleteProxyConfig,
  HideProxyConfig,
  ListHiddenProxyConfigs,
  UnhideProxyConfig,
  TestProxy,
  GetProxySpeedTests,
  type AccountPoolKey,
  type AccountPoolProxySelection,
  type ProxyConfigSummary,
  type ProxyNode,
  type ProxyNodeLatencyResult,
  type ProxySpeedTestSnapshot,
  type ProviderPool,
  type ProviderPoolMode,
  type ProviderPoolProviderPenalty,
  type ProviderPoolType,
  type SpecialBlacklistDurationType,
  type SpecialBlacklistRule,
} from '../../services/providerPool'
import {
  buildSpecialBlacklistRulesPayload,
  canonicalSpecialRuleDurationType,
  normalizeSpecialRuleForm,
  type SpecialBlacklistRuleError,
} from '../../utils/specialBlacklistRules'
import { fetchAppSettings } from '../../services/appSettings'
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
const expandedAccountPoolKeys = ref<Set<string>>(new Set())
const clearingAllBlacklistsPoolIDs = ref<Set<string>>(new Set())
let poolLoadGeneration = 0
let unsubscribeBlacklistChanged: (() => void) | undefined

// favicon 缓存
const faviconCache = new Map<string, string | undefined>()

// 池子弹窗状态
interface PoolFormState {
  name: string
  poolType: ProviderPoolType
  mode: ProviderPoolMode
  manualProviderId: number | null
  memberProviderIds: number[]
  memberLevels: Record<number, number>
  accountApiUrl: string
  accountResponsesEndpoint: string
  accountKeysText: string
  proxyEnabled: boolean
  proxySelection: AccountPoolProxySelection
  proxyNodeId: string
  autoDisableProxyWhenNoAvailable: boolean
  autoBlacklistEnabled: boolean
  autoBlacklistThreshold: number
  autoBlacklistDurationMinutes: number
  specialBlacklistRules: SpecialBlacklistRule[]
  firstTextRetryEnabled: boolean
  firstTextRetryTimeoutSeconds: number
  excludeFromTotalTraffic: boolean
  hideFromLogs: boolean
}

const createEmptyPoolForm = (): PoolFormState => ({
  name: '',
  poolType: 'normal',
  mode: 'managed',
  manualProviderId: null,
  memberProviderIds: [],
  memberLevels: {},
  accountApiUrl: '',
  accountResponsesEndpoint: '/responses',
  accountKeysText: '',
  proxyEnabled: false,
  proxySelection: 'none',
  proxyNodeId: '',
  autoDisableProxyWhenNoAvailable: false,
  autoBlacklistEnabled: false,
  autoBlacklistThreshold: 3,
  autoBlacklistDurationMinutes: 10,
  specialBlacklistRules: [],
  firstTextRetryEnabled: false,
  firstTextRetryTimeoutSeconds: 100,
  excludeFromTotalTraffic: false,
  hideFromLogs: false,
})

const poolModalState = reactive<{
  open: boolean
  editingId: string
  form: PoolFormState
}>({
  open: false,
  editingId: '',
  form: createEmptyPoolForm(),
})

const proxyConfigs = ref<ProxyConfigSummary[]>([])
const hiddenProxyConfigs = ref<ProxyConfigSummary[]>([])
const proxyConfigsLoading = ref(false)
const proxyUploadLoading = ref(false)
const proxySubscriptionImportLoading = ref(false)
const proxyBulkTestLoading = ref(false)
const proxyBulkTestCompleted = ref(false)
const proxyNodeLatencyResults = ref<Record<string, ProxyNodeLatencyResult>>({})
const proxyLastTestedAt = ref('')
const proxyBulkTestPoolID = ref('')
const proxyBulkTestTargetURL = ref('')
const proxyConfigExpanded = ref<Record<string, boolean>>({})
const proxyConfigActionLoading = ref<string | null>(null)
const poolSaveLoading = ref(false)
const maxProxyConfigSize = 4 * 1024 * 1024
let proxyBulkTestGeneration = 0
let proxyBulkTestAbortController: AbortController | null = null
let proxyConfigLoadGeneration = 0
let poolModalGeneration = 0
const proxyNodes = computed(() => proxyConfigs.value.flatMap((config) => config.nodes))
const hasProxyNodes = computed(() => proxyNodes.value.length > 0)
const proxyConfigRequired = computed(() =>
  poolModalState.form.poolType === 'account' && poolModalState.form.proxyEnabled && !hasProxyNodes.value
)
const proxyNodeSelectionRequired = computed(() =>
  poolModalState.form.poolType === 'account'
  && poolModalState.form.proxyEnabled
  && poolModalState.form.proxySelection === 'node'
  && !proxyNodes.value.some((node) => node.id === poolModalState.form.proxyNodeId)
)

const proxyConfigFileName = (config: ProxyConfigSummary) => config.fileName || config.name
const selectedProxyNodeHidden = computed(() =>
  poolModalState.form.proxySelection === 'node'
  && hiddenProxyConfigs.value.some((config) => config.nodes.some((node) => node.id === poolModalState.form.proxyNodeId))
)
const proxyBulkTestAllVisibleNodesTested = computed(() =>
  proxyBulkTestCompleted.value
  && proxyNodes.value.length > 0
  && proxyNodes.value.every((node) => proxyNodeLatencyResults.value[node.id]?.tested === true)
)
const proxyBulkTestIncomplete = computed(() =>
  proxyBulkTestCompleted.value && !proxyBulkTestAllVisibleNodesTested.value
)
const proxyAutoSelectedNode = computed(() => {
  let selected: ProxyNode | undefined
  let lowest: number | undefined
  for (const node of proxyNodes.value) {
    const result = proxyNodeLatencyResults.value[node.id]
    const latency = result?.tested ? result.responsesLatencyMs : undefined
    if (latency == null || latency <= 0 || (lowest != null && latency >= lowest)) continue
    lowest = latency
    selected = node
  }
  return selected
})
const autoProxyLatency = computed(() => {
  const selected = proxyAutoSelectedNode.value
  return selected ? proxyNodeLatencyResults.value[selected.id]?.responsesLatencyMs : undefined
})
const proxyAutoLatencyLabel = computed(() => {
  if (!proxyBulkTestCompleted.value) return t('components.main.pool.proxyNotTested')
  if (autoProxyLatency.value != null) return `${autoProxyLatency.value} ms`
  return proxyBulkTestAllVisibleNodesTested.value
    ? t('components.main.pool.proxyAllUnavailable')
    : t('components.main.pool.proxyBulkTestIncomplete')
})
const proxyAutoLatencyClass = computed(() => ({
  available: autoProxyLatency.value != null,
  unavailable: proxyBulkTestAllVisibleNodesTested.value && autoProxyLatency.value == null,
  unknown: !proxyBulkTestCompleted.value || proxyBulkTestIncomplete.value,
}))
const proxyAutoLatencyTooltip = computed(() => {
  if (!proxyBulkTestCompleted.value) return t('components.main.pool.proxyNotTested')
  if (autoProxyLatency.value != null) {
    return proxyBulkTestAllVisibleNodesTested.value
      ? t('components.main.pool.proxyAutoLowestLatency', { latency: autoProxyLatency.value })
      : t('components.main.pool.proxyAutoPartialFastestLatency', { latency: autoProxyLatency.value })
  }
  return proxyBulkTestAllVisibleNodesTested.value
    ? t('components.main.pool.proxyAllUnavailable')
    : t('components.main.pool.proxyBulkTestIncomplete')
})
const proxyLastTestedLabel = computed(() => {
  if (!proxyLastTestedAt.value) return ''
  const testedAt = Date.parse(proxyLastTestedAt.value)
  if (Number.isNaN(testedAt)) return ''
  const minutes = Math.max(0, Math.floor((Date.now() - testedAt) / 60_000))
  return t('components.main.pool.proxyLastTested', { minutes })
})

const proxyNodeWasTested = (nodeID: string) => proxyNodeLatencyResults.value[nodeID]?.tested === true

const proxyTestFailureLabel = (error?: string) => {
  const normalized = String(error || '').toLowerCase()
  if (normalized.includes('cloudflare')) {
    return t('components.main.pool.proxyCloudflareBlocked')
  }
  if (normalized.includes('timeout') || normalized.includes('deadline') || normalized.includes('超时')) {
    return t('components.main.pool.proxyTimeout')
  }
  return t('components.main.pool.proxyUnavailable')
}

const proxyNodeLatencyLabel = (nodeID: string) => {
  if (!proxyNodeWasTested(nodeID)) return t('components.main.pool.proxyNotTested')
  const latency = proxyNodeLatencyResults.value[nodeID]?.proxyLatencyMs
  return latency != null && latency > 0
    ? `${latency} ms`
    : proxyTestFailureLabel(proxyNodeLatencyResults.value[nodeID]?.proxyError)
}

const proxyNodeLatencyClass = (nodeID: string) => {
  const tested = proxyNodeWasTested(nodeID)
  const latency = tested ? proxyNodeLatencyResults.value[nodeID]?.proxyLatencyMs : undefined
  return {
    available: latency != null && latency > 0,
    unavailable: tested && (latency == null || latency <= 0),
    unknown: !tested,
  }
}

const proxyNodeLatencyDetail = (nodeID: string) => {
  const result = proxyNodeLatencyResults.value[nodeID]
  if (!result?.tested) return t('components.main.pool.proxyNotTested')
  if (result?.proxyLatencyMs != null && result.proxyLatencyMs > 0) return ''
  return proxyTestFailureLabel(result?.proxyError)
}

const proxyNodeLatencyTooltip = (nodeID: string) => {
  if (!proxyNodeWasTested(nodeID)) return t('components.main.pool.proxyNotTested')
  const detail = proxyNodeLatencyDetail(nodeID)
  return detail || `${proxyNodeLatencyResults.value[nodeID]?.proxyLatencyMs} ms`
}

const proxyNodeResponsesLabel = (nodeID: string) => {
  const result = proxyNodeLatencyResults.value[nodeID]
  if (!result?.tested) return t('components.main.pool.proxyNotTested')
  return result.responsesLatencyMs != null
    ? `${result.responsesLatencyMs} ms`
    : proxyTestFailureLabel(result.responsesError || result.proxyError)
}

const proxyNodeResponsesClass = (nodeID: string) => {
  const result = proxyNodeLatencyResults.value[nodeID]
  return {
    available: result?.responsesLatencyMs != null,
    unavailable: result?.tested === true && result.responsesLatencyMs == null,
    unknown: result?.tested !== true,
  }
}

const proxyNodeResponsesTooltip = (nodeID: string) => {
  const result = proxyNodeLatencyResults.value[nodeID]
  if (!result?.tested) return t('components.main.pool.proxyNotTested')
  if (result.responsesLatencyMs == null) return proxyTestFailureLabel(result.responsesError || result.proxyError)
  return result.responsesStatus ? `HTTP ${result.responsesStatus} - ${result.responsesLatencyMs} ms` : `${result.responsesLatencyMs} ms`
}

const isSelectedProxyNode = (nodeID: string) =>
  poolModalState.form.proxySelection === 'node' && poolModalState.form.proxyNodeId === nodeID

const proxyConfigNodesRegionID = (configID: string) => `proxy-config-nodes-${configID}`
const isProxyConfigExpanded = (configID: string) => proxyConfigExpanded.value[configID] === true
const toggleProxyConfigExpanded = (configID: string) => {
  proxyConfigExpanded.value = {
    ...proxyConfigExpanded.value,
    [configID]: !isProxyConfigExpanded(configID),
  }
}

const syncProxyConfigExpanded = (configs: ProxyConfigSummary[]) => {
  const next: Record<string, boolean> = {}
  for (const config of configs) {
    const includesCurrentSelection = poolModalState.form.proxySelection === 'node'
      && config.nodes.some((node) => node.id === poolModalState.form.proxyNodeId)
    next[config.id] = includesCurrentSelection || proxyConfigExpanded.value[config.id] === true
  }
  proxyConfigExpanded.value = next
}

const invalidateProxyBulkTest = () => {
  proxyBulkTestGeneration += 1
  proxyBulkTestAbortController?.abort()
  proxyBulkTestAbortController = null
  proxyBulkTestLoading.value = false
  proxyBulkTestCompleted.value = false
  proxyNodeLatencyResults.value = {}
  proxyLastTestedAt.value = ''
  proxyBulkTestPoolID.value = ''
  proxyBulkTestTargetURL.value = ''
}

const invalidateAllProxyTests = () => {
  invalidateProxyBulkTest()
}

const selectAutoProxy = () => {
  poolModalState.form.proxySelection = 'auto'
  poolModalState.form.proxyNodeId = ''
}

const selectProxyNode = (nodeID: string) => {
  poolModalState.form.proxySelection = 'node'
  poolModalState.form.proxyNodeId = nodeID
}

const selectProxyNodeIfAvailable = (nodeID: string) => {
  if (proxyConfigsLoading.value) return
  selectProxyNode(nodeID)
}

const toggleProxyEnabled = () => {
  if (poolModalState.form.proxyEnabled && poolModalState.form.proxySelection === 'none') {
    poolModalState.form.proxySelection = 'auto'
  }
  if (!poolModalState.form.proxyEnabled) {
    invalidateProxyBulkTest()
    poolModalState.form.proxySelection = 'none'
    poolModalState.form.proxyNodeId = ''
  }
}

const updateProxyConfigLists = async (loadVisibleConfigs: () => Promise<ProxyConfigSummary[]>) => {
  const generation = ++proxyConfigLoadGeneration
  proxyConfigsLoading.value = true
  try {
    const nextConfigs = await loadVisibleConfigs()
    const nextHiddenConfigs = await ListHiddenProxyConfigs()
    if (generation === proxyConfigLoadGeneration) {
      proxyConfigs.value = nextConfigs
      hiddenProxyConfigs.value = nextHiddenConfigs
      syncProxyConfigExpanded(nextConfigs)
      void loadSharedProxySpeedTests()
    }
  } catch (error) {
    console.error('Failed to load proxy configs:', error)
    if (generation === proxyConfigLoadGeneration) {
      showToast(t('components.main.pool.proxyLoadFailed'), 'error')
    }
  } finally {
    if (generation === proxyConfigLoadGeneration) {
      proxyConfigsLoading.value = false
    }
  }
}

const loadProxyConfigs = () => {
  if (proxyBulkTestLoading.value || proxyUploadLoading.value || proxySubscriptionImportLoading.value || proxyConfigActionLoading.value !== null) return
  invalidateAllProxyTests()
  return updateProxyConfigLists(RefreshProxyConfigs)
}
const listProxyConfigs = () => updateProxyConfigLists(ListProxyConfigs)

const responsesProbeURL = () => {
  const baseURL = poolModalState.form.accountApiUrl.trim()
  const endpoint = poolModalState.form.accountResponsesEndpoint.trim()
  if (!baseURL || !endpoint) return ''
  return `${baseURL.replace(/\/+$/, '')}/${endpoint.replace(/^\/+/, '')}`
}

const loadSharedProxySpeedTests = async (isCurrent = () => true) => {
  const targetURL = responsesProbeURL()
  if (!targetURL) return
  try {
    const snapshot: ProxySpeedTestSnapshot = await GetProxySpeedTests(poolModalState.editingId, targetURL)
    if (!isCurrent() || !poolModalState.open || responsesProbeURL() !== targetURL) return
    const results: Record<string, ProxyNodeLatencyResult> = {}
    for (const result of snapshot.results) {
      results[result.nodeId] = result
    }
    proxyNodeLatencyResults.value = results
    proxyLastTestedAt.value = snapshot.testedAt || ''
    proxyBulkTestCompleted.value = snapshot.results.length > 0
  } catch (error) {
    console.error('Failed to load shared proxy speed tests:', error)
  }
}

const uploadProxyConfig = async (event: Event) => {
  if (proxyBulkTestLoading.value || proxySubscriptionImportLoading.value) return
  const input = event.target as HTMLInputElement
	const file = input.files?.[0]
	input.value = ''
	if (!file) return
	if (file.size === 0 || file.size > maxProxyConfigSize) {
		showToast(t('components.main.pool.proxyUploadTooLarge', { size: 4 }), 'error')
		return
	}
	if (!window.confirm(t('components.main.pool.proxyUploadWarning'))) return
	invalidateAllProxyTests()
	proxyUploadLoading.value = true
	try {
		const content = await file.text()
		await UploadProxyConfig(file.name, content)
		showToast(t('components.main.pool.proxyUploadSuccess'), 'success')
			await listProxyConfigs()
	} catch (error: any) {
    console.error('Failed to upload proxy config:', error)
    showToast(error?.message || t('components.main.pool.proxyUploadFailed'), 'error')
  } finally {
    proxyUploadLoading.value = false
  }
}

const importProxySubscription = async () => {
  if (proxyBulkTestLoading.value || proxyUploadLoading.value || proxySubscriptionImportLoading.value || proxyConfigActionLoading.value !== null) return
  const subscriptionURL = window.prompt(t('components.main.pool.proxySubscriptionURLPrompt'))
  if (!subscriptionURL?.trim()) return
  const subscriptionName = window.prompt(t('components.main.pool.proxySubscriptionNamePrompt'))
  if (subscriptionName === null) return
  if (!window.confirm(t('components.main.pool.proxySubscriptionWarning'))) return

  invalidateAllProxyTests()
  proxySubscriptionImportLoading.value = true
  try {
    await ImportProxySubscription(subscriptionURL.trim(), subscriptionName.trim())
    showToast(t('components.main.pool.proxySubscriptionImportSuccess'), 'success')
    await listProxyConfigs()
  } catch (error: any) {
    console.error('Failed to import proxy subscription:', error)
    showToast(error?.message || t('components.main.pool.proxySubscriptionImportFailed'), 'error')
  } finally {
    proxySubscriptionImportLoading.value = false
  }
}

const deleteProxyConfig = async (config: ProxyConfigSummary) => {
  if (proxyBulkTestLoading.value || proxyUploadLoading.value || proxySubscriptionImportLoading.value) return
  const name = proxyConfigFileName(config)
  if (!window.confirm(t('components.main.pool.deleteProxyConfigConfirm', { name }))) return

  invalidateAllProxyTests()
  proxyConfigActionLoading.value = config.id
  try {
    await DeleteProxyConfig(config.id)
    showToast(t('components.main.pool.proxyConfigDeleted'), 'success')
    await listProxyConfigs()
  } catch (error: any) {
    console.error('Failed to delete proxy config:', error)
    showToast(error?.message || t('components.main.pool.proxyConfigDeleteFailed'), 'error')
  } finally {
    proxyConfigActionLoading.value = null
  }
}

const hideProxyConfig = async (config: ProxyConfigSummary) => {
  if (proxyBulkTestLoading.value || proxyUploadLoading.value || proxySubscriptionImportLoading.value) return
  const name = proxyConfigFileName(config)
  if (!window.confirm(t('components.main.pool.hideProxyConfigConfirm', { name }))) return

  invalidateAllProxyTests()
  proxyConfigActionLoading.value = config.id
  try {
    await HideProxyConfig(config.id)
    showToast(t('components.main.pool.proxyConfigHidden'), 'success')
    await listProxyConfigs()
  } catch (error: any) {
    console.error('Failed to hide proxy config:', error)
    showToast(error?.message || t('components.main.pool.proxyConfigHideFailed'), 'error')
  } finally {
    proxyConfigActionLoading.value = null
  }
}

const unhideProxyConfig = async (config: ProxyConfigSummary) => {
  if (proxyBulkTestLoading.value || proxyUploadLoading.value || proxySubscriptionImportLoading.value) return
  invalidateAllProxyTests()
  proxyConfigActionLoading.value = config.id
  try {
    await UnhideProxyConfig(config.id)
    showToast(t('components.main.pool.proxyConfigUnhidden'), 'success')
    await listProxyConfigs()
  } catch (error: any) {
    console.error('Failed to unhide proxy config:', error)
    showToast(error?.message || t('components.main.pool.proxyConfigUnhideFailed'), 'error')
  } finally {
    proxyConfigActionLoading.value = null
  }
}

const testAllProxyLatencies = async () => {
  if (proxyBulkTestLoading.value || proxySubscriptionImportLoading.value || !hasProxyNodes.value) return
  const targetURL = responsesProbeURL()
  if (!targetURL) {
    showToast(t('components.main.pool.proxyBaseUrlRequired'), 'warning')
    return
  }
  const poolID = poolModalState.editingId
  const generation = ++proxyBulkTestGeneration
  const controller = new AbortController()
  proxyBulkTestAbortController = controller
  proxyBulkTestLoading.value = true
  proxyBulkTestCompleted.value = false
  proxyNodeLatencyResults.value = {}
  proxyLastTestedAt.value = ''
  proxyBulkTestPoolID.value = poolID
  proxyBulkTestTargetURL.value = targetURL
  try {
    const groups = proxyConfigs.value
      .map((config) => [...config.nodes])
      .filter((nodes) => nodes.length > 0)
    let maxWorkers = 1
    try {
      const settings = await fetchAppSettings()
      if (!controller.signal.aborted && settings.enable_proxy_latency_multithreading) {
        maxWorkers = Math.min(4, Math.max(1, Math.trunc(settings.proxy_latency_max_concurrency || 1)))
      }
    } catch (error) {
      console.warn('Failed to load proxy latency test settings; using one worker:', error)
    }
    let nextGroupIndex = 0
    const workerCount = Math.min(maxWorkers, groups.length)
    const workers = Array.from({ length: workerCount }, async () => {
      while (!controller.signal.aborted && generation === proxyBulkTestGeneration && nextGroupIndex < groups.length) {
        const nodes = groups[nextGroupIndex++]
        for (const node of nodes) {
          if (controller.signal.aborted || generation !== proxyBulkTestGeneration) return
          let result: ProxyNodeLatencyResult
          try {
            const speed = await TestProxy(poolID, node.id, targetURL, controller.signal)
            result = {
              nodeId: node.id,
              tested: true,
              proxyLatencyMs: speed.proxyLatencyMs,
              proxyError: speed.proxyError,
              responsesLatencyMs: speed.responsesLatencyMs,
              responsesStatus: speed.responsesStatus,
              responsesError: speed.responsesError,
              responsesCloudflareBlocked: speed.responsesCloudflareBlocked,
            }
          } catch (error: any) {
            if (controller.signal.aborted || generation !== proxyBulkTestGeneration) return
            result = { nodeId: node.id, tested: true, proxyError: error?.message || t('components.main.pool.proxyUnavailable') }
          }
          if (!controller.signal.aborted
            && generation === proxyBulkTestGeneration
            && poolModalState.open
            && poolModalState.editingId === poolID
            && responsesProbeURL() === targetURL) {
            proxyNodeLatencyResults.value = { ...proxyNodeLatencyResults.value, [node.id]: result }
          }
        }
      }
    })
    await Promise.all(workers)
    if (!controller.signal.aborted
      && generation === proxyBulkTestGeneration
      && poolModalState.open
      && poolModalState.editingId === poolID
      && responsesProbeURL() === targetURL) {
      proxyBulkTestCompleted.value = true
      // The latency probes are done. Do not leave the action disabled while
      // the separate shared-cache refresh is still waiting on the server.
      if (proxyBulkTestAbortController === controller) {
        proxyBulkTestAbortController = null
        proxyBulkTestLoading.value = false
        proxyBulkTestPoolID.value = ''
        proxyBulkTestTargetURL.value = ''
      }
      await loadSharedProxySpeedTests(() => !controller.signal.aborted && generation === proxyBulkTestGeneration && responsesProbeURL() === targetURL)
    }
  } finally {
    if (generation === proxyBulkTestGeneration && proxyBulkTestAbortController === controller) {
      proxyBulkTestAbortController = null
      proxyBulkTestLoading.value = false
      proxyBulkTestPoolID.value = ''
      proxyBulkTestTargetURL.value = ''
    }
  }
}

// 删除确认状态
const deleteConfirmState = reactive({
  open: false,
  pool: null as ProviderPool | null,
})

// 拉黑状态缓存
const blacklistStatus = ref<Map<string, ProviderPoolProviderPenalty[]>>(new Map())
const blacklistPoolGenerations = new Map<string, number>()

const nextBlacklistGeneration = (poolID: string) => {
  const next = (blacklistPoolGenerations.get(poolID) || 0) + 1
  blacklistPoolGenerations.set(poolID, next)
  return next
}

const loadBlacklistStatus = async (generation = poolLoadGeneration) => {
  const requestGenerations = new Map<string, number>()
  for (const pool of pools.value) {
    requestGenerations.set(pool.id, nextBlacklistGeneration(pool.id))
  }
  const statusMap = new Map<string, ProviderPoolProviderPenalty[]>()
  for (const pool of pools.value) {
    try {
      const statuses = await ListProviderBlacklistStatus(props.platform, pool.id)
      statusMap.set(pool.id, statuses)
    } catch (error) {
      console.error('Failed to load blacklist status:', error)
    }
    if (generation !== poolLoadGeneration || requestGenerations.get(pool.id) !== blacklistPoolGenerations.get(pool.id)) continue
  }
  if (generation !== poolLoadGeneration) return
  const nextStatus = new Map(blacklistStatus.value)
  for (const [poolID, statuses] of statusMap) {
    if (requestGenerations.get(poolID) === blacklistPoolGenerations.get(poolID)) {
      nextStatus.set(poolID, statuses)
    }
  }
  blacklistStatus.value = nextStatus
}

type ProviderBlacklistChangedEvent = {
  platform?: string
  poolID?: string
}

const loadBlacklistStatusForPool = async (poolID: string, generation = poolLoadGeneration) => {
  const requestGeneration = nextBlacklistGeneration(poolID)
  if (!pools.value.some((pool) => pool.id === poolID)) {
    return
  }
  try {
    const statuses = await ListProviderBlacklistStatus(props.platform, poolID)
    if (generation !== poolLoadGeneration || requestGeneration !== blacklistPoolGenerations.get(poolID)) return
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
    void loadBlacklistStatusForPool(poolID, poolLoadGeneration)
    return
  }
  void loadBlacklistStatus()
}

const loadPools = async () => {
  const generation = ++poolLoadGeneration
  try {
    const nextPools = await ListPools(props.platform)
    if (generation !== poolLoadGeneration) return
    pools.value = nextPools
    await loadBlacklistStatus(generation)
  } catch (error) {
    console.error('Failed to load pools:', error)
    if (generation === poolLoadGeneration) {
      showToast(t('components.main.pool.loadFailed'), 'error')
    }
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

const isAccountPool = (pool: ProviderPool): boolean => pool.poolType === 'account'

const maskAccountKey = (apiKey: string): string => {
  const key = apiKey.trim()
  if (key.length <= 4) return '****'
  return `****${key.slice(-4)}`
}

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
  return (pool.members ?? [])
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
	poolModalGeneration += 1
  invalidateAllProxyTests()
  poolModalState.editingId = ''
  poolModalState.form = createEmptyPoolForm()
  poolModalState.open = true
}

const openEditPool = (pool: ProviderPool) => {
	poolModalGeneration += 1
  const targetURL = pool.accountPoolConfig
    ? `${pool.accountPoolConfig.apiUrl.trim().replace(/\/+$/, '')}/${pool.accountPoolConfig.responsesEndpoint.trim().replace(/^\/+/, '')}`
    : ''
  const resumeBulkTest = proxyBulkTestLoading.value
    && proxyBulkTestPoolID.value === pool.id
    && proxyBulkTestTargetURL.value === targetURL
  if (!resumeBulkTest) invalidateAllProxyTests()
  poolModalState.editingId = pool.id
  const levels: Record<number, number> = {}
  for (const m of pool.members ?? []) {
    levels[normalizeProviderId(m.providerId)] = m.level ?? 1
  }
  poolModalState.form = {
    name: pool.name,
    poolType: isAccountPool(pool) ? 'account' : 'normal',
    mode: isAccountPool(pool) ? 'managed' : pool.mode,
    manualProviderId: pool.manualProviderId ?? null,
    memberProviderIds: (pool.members ?? []).map((m) => normalizeProviderId(m.providerId)),
    memberLevels: levels,
    accountApiUrl: pool.accountPoolConfig?.apiUrl ?? '',
    accountResponsesEndpoint: pool.accountPoolConfig?.responsesEndpoint || '/responses',
    accountKeysText: (pool.accountPoolConfig?.keys ?? []).map((key) => key.apiKey).join('\n'),
    proxyEnabled: pool.proxyConfig?.enabled ?? false,
    proxySelection: pool.proxyConfig?.selection === 'node' ? 'node' : pool.proxyConfig?.enabled ? 'auto' : 'none',
    proxyNodeId: pool.proxyConfig?.proxyNodeId ?? '',
    autoDisableProxyWhenNoAvailable: pool.proxyConfig?.autoDisableWhenNoAvailable ?? false,
    autoBlacklistEnabled: pool.autoBlacklistEnabled ?? false,
    autoBlacklistThreshold: pool.autoBlacklistThreshold || 3,
    autoBlacklistDurationMinutes: pool.autoBlacklistDurationMinutes || 10,
    specialBlacklistRules: (pool.specialBlacklistRules ?? []).map((rule) => normalizeSpecialRuleForm({ ...rule })),
    firstTextRetryEnabled: pool.firstTextRetryEnabled ?? false,
    firstTextRetryTimeoutSeconds: pool.firstTextRetryTimeoutSeconds || 100,
    excludeFromTotalTraffic: pool.excludeFromTotalTraffic ?? false,
    hideFromLogs: pool.hideFromLogs ?? false,
  }
  poolModalState.open = true
  if (resumeBulkTest) void loadSharedProxySpeedTests()
}

const isMemberSelected = (providerId: number | string): boolean =>
  isProviderIdInList(poolModalState.form.memberProviderIds, providerId)

const getMemberLevel = (providerId: number | string): number =>
  poolModalState.form.memberLevels[normalizeProviderId(providerId)] ?? 1

const closePoolModal = async (force = false) => {
	if (!force && poolModalState.editingId) {
		const saved = await submitPoolModal(false)
		if (!saved) return
	}
	poolModalGeneration += 1
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

const parseAccountKeys = (text: string): string[] => {
  const seen = new Set<string>()
  const keys: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const key = line.trim()
    if (!key || seen.has(key)) continue
    seen.add(key)
    keys.push(key)
  }
  return keys
}

const addSpecialBlacklistRule = () => {
  const id = typeof crypto?.randomUUID === 'function'
    ? `rule_${crypto.randomUUID()}`
    : `rule_${Date.now()}_${Math.random().toString(36).slice(2)}`
  poolModalState.form.specialBlacklistRules.push({
    id,
    name: '',
    httpStatus: 429,
    jsonPath: '',
    expectedJsonValue: '',
    threshold: 1,
    durationMinutes: 10,
    durationType: 'duration',
    untilDayOffset: 1,
    untilTime: '00:00',
  })
}

// 兼容旧数据与手工配置的模式归一化、保存校验、载荷清理在 utils/specialBlacklistRules 中
const SPECIAL_RULE_ERROR_KEYS: Record<SpecialBlacklistRuleError, string> = {
  durationType: 'components.main.pool.specialRuleDurationTypeInvalid',
  untilDayOffset: 'components.main.pool.specialRuleUntilDayOffsetInvalid',
  untilTime: 'components.main.pool.specialRuleUntilTimeInvalid',
}

const removeSpecialBlacklistRule = (index: number) => {
  poolModalState.form.specialBlacklistRules.splice(index, 1)
}

const moveSpecialBlacklistRule = (index: number, direction: -1 | 1) => {
  const destination = index + direction
  const rules = poolModalState.form.specialBlacklistRules
  if (destination < 0 || destination >= rules.length) return
  const [rule] = rules.splice(index, 1)
  rules.splice(destination, 0, rule)
}

const poolConfigSignature = (pool: Partial<ProviderPool>) => {
  const poolType = pool.poolType ?? 'normal'
  const members = (pool.members ?? [])
    .map((member) => ({
      providerId: normalizeProviderId(member.providerId),
      enabled: member.enabled !== false,
      level: member.level ?? 1,
    }))
    .sort((left, right) => left.providerId - right.providerId)
  const specialBlacklistRules = (pool.specialBlacklistRules ?? []).map((rule) => {
    const durationType = canonicalSpecialRuleDurationType(rule.durationType)
    return {
      id: rule.id,
      name: rule.name.trim(),
      httpStatus: rule.httpStatus,
      jsonPath: rule.jsonPath ?? '',
      expectedJsonValue: rule.expectedJsonValue ?? '',
      threshold: rule.threshold,
      durationMinutes: rule.durationMinutes,
      durationType,
      untilDayOffset: durationType === 'until' ? (typeof rule.untilDayOffset === 'number' ? rule.untilDayOffset : 0) : 0,
      untilTime: durationType === 'until' ? rule.untilTime ?? '' : '',
    }
  })
  const accountPoolConfig = pool.accountPoolConfig

  return JSON.stringify({
    platform: pool.platform,
    name: pool.name?.trim() ?? '',
    poolType,
    mode: poolType === 'account' ? 'managed' : pool.mode,
    manualProviderId: poolType === 'account' ? null : pool.manualProviderId ?? null,
    members: poolType === 'account' ? [] : members,
    autoBlacklistEnabled: poolType === 'account' ? true : pool.autoBlacklistEnabled ?? false,
    autoBlacklistThreshold: pool.autoBlacklistThreshold ?? 3,
    autoBlacklistDurationMinutes: pool.autoBlacklistDurationMinutes ?? 10,
    specialBlacklistRules,
    firstTextRetryEnabled: pool.firstTextRetryEnabled === true,
    firstTextRetryTimeoutSeconds: pool.firstTextRetryTimeoutSeconds ?? 100,
    excludeFromTotalTraffic: poolType === 'account' ? pool.excludeFromTotalTraffic === true : false,
    hideFromLogs: poolType === 'account' ? pool.hideFromLogs === true : false,
    proxyConfig: poolType === 'account'
      ? {
          enabled: pool.proxyConfig?.enabled === true,
          selection: pool.proxyConfig?.enabled ? (pool.proxyConfig.selection || 'auto') : 'none',
          proxyNodeId: pool.proxyConfig?.enabled && pool.proxyConfig.selection === 'node'
            ? pool.proxyConfig.proxyNodeId ?? ''
            : '',
          autoDisableWhenNoAvailable: pool.proxyConfig?.enabled && pool.proxyConfig.selection !== 'node'
            ? pool.proxyConfig.autoDisableWhenNoAvailable === true
            : false,
        }
      : undefined,
    accountPoolConfig: poolType === 'account'
      ? {
          apiUrl: accountPoolConfig?.apiUrl.trim() ?? '',
          responsesEndpoint: accountPoolConfig?.responsesEndpoint.trim() ?? '',
          keys: (accountPoolConfig?.keys ?? []).map((key) => key.apiKey),
        }
      : undefined,
  })
}

const submitPoolModal = async (closeAfterSave = true): Promise<boolean> => {
	if (poolSaveLoading.value) return false
  const { name, memberProviderIds } = poolModalState.form
  const existingPool = poolModalState.editingId
    ? pools.value.find((pool) => pool.id === poolModalState.editingId)
    : null
  const poolType: ProviderPoolType = props.platform === 'openai-responses'
    ? poolModalState.form.poolType
    : 'normal'

  if (poolType === 'account' && poolModalState.form.proxyEnabled && !hasProxyNodes.value) {
    showToast(t('components.main.pool.proxyConfigRequired'), 'error')
    return false
  }
  if (poolType === 'account' && proxyNodeSelectionRequired.value) {
    showToast(
      selectedProxyNodeHidden.value
        ? t('components.main.pool.proxyNodeHidden')
        : t('components.main.pool.proxyNodeRequired'),
      'error',
    )
    return false
  }

  const payload = buildSpecialBlacklistRulesPayload(poolModalState.form.specialBlacklistRules)
  if (payload.error) {
    showToast(t(SPECIAL_RULE_ERROR_KEYS[payload.error]), 'error')
    return false
  }
  const specialBlacklistRules = payload.rules

  const poolData: any = {
    platform: props.platform,
    name,
    poolType,
    autoBlacklistThreshold: poolModalState.form.autoBlacklistThreshold,
    autoBlacklistDurationMinutes: poolModalState.form.autoBlacklistDurationMinutes,
    specialBlacklistRules,
    firstTextRetryEnabled: poolModalState.form.firstTextRetryEnabled,
    firstTextRetryTimeoutSeconds: Math.min(240, Math.max(5, Math.trunc(poolModalState.form.firstTextRetryTimeoutSeconds || 100))),
  }

  if (poolType === 'account') {
    const parsedKeys = parseAccountKeys(poolModalState.form.accountKeysText)
    if (parsedKeys.length === 0) {
      showToast(t('components.main.pool.accountPoolKeysRequired'), 'error')
      return false
    }

    const existingKeysBySecret = new Map<string, AccountPoolKey>(
      (existingPool?.accountPoolConfig?.keys ?? []).map((key): [string, AccountPoolKey] => [key.apiKey, key])
    )
    poolData.mode = 'managed'
    poolData.manualProviderId = null
    poolData.members = []
    poolData.autoBlacklistEnabled = true
    poolData.excludeFromTotalTraffic = poolModalState.form.excludeFromTotalTraffic
    poolData.hideFromLogs = poolModalState.form.hideFromLogs
    poolData.proxyConfig = poolModalState.form.proxyEnabled
      ? {
          enabled: true,
          selection: poolModalState.form.proxySelection,
          proxyNodeId: poolModalState.form.proxySelection === 'node' ? poolModalState.form.proxyNodeId : '',
          autoDisableWhenNoAvailable: poolModalState.form.proxySelection === 'auto'
            ? poolModalState.form.autoDisableProxyWhenNoAvailable
            : false,
        }
      : { enabled: false, selection: 'none', proxyNodeId: '', autoDisableWhenNoAvailable: false }
    poolData.accountPoolConfig = {
      apiUrl: poolModalState.form.accountApiUrl.trim(),
      responsesEndpoint: poolModalState.form.accountResponsesEndpoint.trim(),
      keys: parsedKeys.map((apiKey) => ({
        id: existingKeysBySecret.get(apiKey)?.id ?? 0,
        apiKey,
      })),
    }
  } else {
    const mode = poolModalState.form.mode
    const members = memberProviderIds.map((providerId) => {
      const normalizedProviderId = normalizeProviderId(providerId)
      const existingMember = existingPool?.members?.find((member) => sameProviderId(member.providerId, normalizedProviderId))
      return {
        providerId: normalizedProviderId,
        enabled: existingMember?.enabled ?? true,
        level: poolModalState.form.memberLevels[normalizedProviderId] ?? 1,
      }
    })
    const existingManualProviderId = existingPool?.manualProviderId ?? null
    poolData.mode = mode
    poolData.manualProviderId = mode === 'manual'
      ? isProviderIdInList(memberProviderIds, existingManualProviderId)
        ? existingManualProviderId
        : memberProviderIds[0] ?? null
      : null
    poolData.members = members
    poolData.autoBlacklistEnabled = poolModalState.form.autoBlacklistEnabled
  }

	if (poolModalState.editingId) {
		poolData.id = poolModalState.editingId
	}
	if (existingPool && poolConfigSignature(existingPool) === poolConfigSignature(poolData)) {
    if (closeAfterSave) await closePoolModal(true)
    return true
  }

	const generation = poolModalGeneration
	const wasEditing = Boolean(poolModalState.editingId)
	poolSaveLoading.value = true
	try {
		await SavePool(poolData)
		if (generation !== poolModalGeneration) {
			await loadPools()
			return false
		}
		showToast(
			wasEditing
        ? t('components.main.pool.poolUpdated')
        : t('components.main.pool.poolCreated'),
      'success'
    )
    if (closeAfterSave) await closePoolModal(true)
    await loadPools()
    emit('refresh')
		return true
	} catch (error: any) {
		console.error('Failed to save pool:', error)
		if (generation === poolModalGeneration) {
			showToast(error?.message || t('components.main.pool.saveFailed'), 'error')
		}
		return false
	} finally {
		poolSaveLoading.value = false
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

const isClearingAllBlacklists = (poolID: string): boolean => clearingAllBlacklistsPoolIDs.value.has(poolID)

const clearAllAccountPoolBlacklists = async (pool: ProviderPool) => {
  if (!window.confirm(t('components.main.pool.clearAllBlacklistsConfirm'))) return

  const pending = new Set(clearingAllBlacklistsPoolIDs.value)
  pending.add(pool.id)
  clearingAllBlacklistsPoolIDs.value = pending
  try {
    await ClearAllProviderBlacklists(props.platform, pool.id)
    showToast(t('components.main.pool.allBlacklistsCleared'), 'success')
    await loadBlacklistStatus()
  } catch (error: any) {
    console.error('Failed to clear account-pool blacklists:', error)
    showToast(error?.message || t('components.main.pool.updateFailed'), 'error')
  } finally {
    const next = new Set(clearingAllBlacklistsPoolIDs.value)
    next.delete(pool.id)
    clearingAllBlacklistsPoolIDs.value = next
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

const getBlacklistPenalty = (pool: ProviderPool, providerID: number): ProviderPoolProviderPenalty | undefined =>
  (blacklistStatus.value.get(pool.id) ?? []).find((penalty) => sameProviderId(penalty.providerID, providerID))

const getBlacklistReason = (pool: ProviderPool, providerID: number): string => {
  return getPenaltyReason(pool, getBlacklistPenalty(pool, providerID))
}

const getPenaltyReason = (pool: ProviderPool, penalty?: ProviderPoolProviderPenalty): string => {
  const reason = penalty?.lastReason?.trim()
  if (!reason) return 'HTTP error'
  if (!isAccountPool(pool)) return reason.match(/HTTP\s+\d{3}/i)?.[0]?.toUpperCase() ?? reason
  const specialRule = (pool.specialBlacklistRules ?? []).find((rule) => rule.name === reason)
  if (specialRule) return specialRule.name
  return reason.match(/HTTP\s+\d{3}/i)?.[0]?.toUpperCase() ?? reason
}

const getAvailableAccountKeys = (pool: ProviderPool): AccountPoolKey[] =>
  (pool.accountPoolConfig?.keys ?? []).filter((key) => !getBlacklistPenalty(pool, key.id))

const getBlacklistedAccountKeys = (pool: ProviderPool): AccountPoolKey[] =>
  (pool.accountPoolConfig?.keys ?? []).filter((key) => getBlacklistPenalty(pool, key.id))

const isAccountKeysCollapsed = (poolID: string): boolean => !expandedAccountPoolKeys.value.has(poolID)

const toggleAccountKeysCollapsed = (poolID: string) => {
  const next = new Set(expandedAccountPoolKeys.value)
  if (next.has(poolID)) {
    next.delete(poolID)
  } else {
    next.add(poolID)
  }
  expandedAccountPoolKeys.value = next
}

// 根据 provider ID 获取 provider 名称
const getProviderNameById = (providerID: number): string => {
  const provider = props.providers.find((p) => sameProviderId(p.id, providerID))
  return provider?.name ?? `Provider #${providerID}`
}

const getBlacklistSubjectName = (pool: ProviderPool, providerID: number): string => {
  if (!isAccountPool(pool)) return getProviderNameById(providerID)
  const key = pool.accountPoolConfig?.keys?.find((item) => sameProviderId(item.id, providerID))
  return key ? maskAccountKey(key.apiKey) : t('components.main.pool.accountKeyFallback', { id: Math.abs(providerID) })
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
  void loadPools()
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
    closePoolModal(true)
    void loadPools()
  }
)

watch(
	() => [poolModalState.open, poolModalState.form.poolType] as const,
	([open, poolType], [previousOpen, previousPoolType]) => {
		if (poolType !== previousPoolType) {
			invalidateAllProxyTests()
		}
		if (open && poolType === 'account' && (!previousOpen || previousPoolType !== 'account')) {
			void loadProxyConfigs()
		}
	}
)

watch(
  () => [poolModalState.form.accountApiUrl, poolModalState.form.accountResponsesEndpoint] as const,
  () => {
    invalidateProxyBulkTest()
  },
)
</script>

<style scoped>
.pool-panel {
  width: 100%;
}

.pool-proxy-section {
  border-top: 1px solid var(--color-border, #e5e7eb);
  padding-top: 12px;
}

.pool-proxy-config {
  display: grid;
  gap: 10px;
  margin-top: 10px;
}

.pool-proxy-error {
  color: var(--color-danger, #b91c1c);
}

.proxy-strategy-group {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.proxy-strategy-group-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  color: var(--color-text, #1f2937);
  font-size: 13px;
  font-weight: 500;
}

.proxy-last-tested {
  margin-left: auto;
  color: var(--color-text-muted, #6b7280);
  font-size: 12px;
  font-weight: 400;
  white-space: nowrap;
}

.proxy-bulk-test-button {
  flex: 0 0 auto;
}

.proxy-strategy-board {
  display: grid;
  gap: 8px;
  min-width: 0;
}

.proxy-strategy-card {
  position: relative;
  display: block;
  min-width: 0;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 6px;
  background: var(--color-bg, #ffffff);
  color: var(--color-text, #1f2937);
  cursor: pointer;
  transition: border-color 0.15s ease, background 0.15s ease;
}

.proxy-strategy-card:hover:not(.disabled) {
  border-color: var(--color-primary, #3b82f6);
  background: var(--color-bg-hover, rgba(0, 0, 0, 0.04));
}

.proxy-strategy-card.selected {
  border-color: var(--color-primary, #3b82f6);
  box-shadow: inset 3px 0 0 var(--color-primary, #3b82f6);
}

.proxy-strategy-card.disabled {
  cursor: default;
  opacity: 0.56;
}

.proxy-strategy-radio {
  position: absolute;
  width: 1px;
  height: 1px;
  margin: -1px;
  overflow: hidden;
  clip: rect(0 0 0 0);
  white-space: nowrap;
}

.proxy-strategy-card-content {
  display: grid;
  grid-template-areas:
    'name latency'
    'meta latency';
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 3px 10px;
  min-height: 58px;
  padding: 9px 10px;
}

.proxy-node-card .proxy-strategy-card-content {
  grid-template-areas: 'name metrics';
  grid-template-columns: minmax(0, 1fr) minmax(168px, auto);
  align-items: center;
}

.proxy-auto-card .proxy-strategy-card-content {
  grid-template-areas: 'name selection';
  grid-template-columns: minmax(0, 1fr) minmax(0, 58%);
  align-items: center;
}

.proxy-auto-selection {
  grid-area: selection;
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: end;
  gap: 8px;
}

.proxy-auto-selected-node {
  min-width: 0;
  overflow: hidden;
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
  text-align: right;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.proxy-node-metrics {
  grid-area: metrics;
  display: grid;
  gap: 4px;
}

.proxy-node-metric {
  display: flex;
  min-width: 0;
  align-items: center;
  justify-content: end;
  gap: 6px;
}

.proxy-node-metric-label {
  min-width: 0;
  overflow: hidden;
  color: var(--color-text-secondary, #6b7280);
  font-size: 11px;
  text-align: right;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.proxy-strategy-radio:focus-visible + .proxy-strategy-card-content {
  outline: 2px solid var(--color-primary, #3b82f6);
  outline-offset: -2px;
}

.proxy-strategy-card-name {
  grid-area: name;
  min-width: 0;
  overflow-wrap: anywhere;
  font-size: 13px;
  font-weight: 600;
}

.proxy-strategy-card-meta {
  grid-area: meta;
  min-width: 0;
  overflow-wrap: anywhere;
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
}

.proxy-strategy-card-meta.is-error {
  color: var(--color-danger, #b91c1c);
}

.proxy-strategy-latency {
  grid-area: latency;
  align-self: center;
  min-width: 54px;
  padding: 3px 7px;
  border-radius: 999px;
  background: var(--color-bg-header, rgba(0, 0, 0, 0.04));
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
  line-height: 1.2;
  text-align: center;
  white-space: nowrap;
}

.proxy-strategy-latency.available {
  color: var(--color-success, #059669);
}

.proxy-strategy-latency.unavailable {
  color: var(--color-danger, #b91c1c);
}

.proxy-strategy-latency.unknown {
  border: 1px dashed var(--color-border, #d1d5db);
  background: transparent;
}

.proxy-auto-card .proxy-strategy-latency {
  flex: none;
}

.proxy-config-section {
  min-width: 0;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 6px;
  background: var(--color-bg, #ffffff);
  overflow: hidden;
}

.proxy-config-disclosure {
  display: flex;
  width: 100%;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 9px 10px;
  border: 0;
  background: transparent;
  color: var(--color-text, #1f2937);
  cursor: pointer;
  text-align: left;
}

.proxy-config-disclosure:hover {
  background: var(--color-bg-hover, rgba(0, 0, 0, 0.04));
}

.proxy-config-disclosure:focus-visible {
  outline: 2px solid var(--color-primary, #3b82f6);
  outline-offset: -2px;
}

.proxy-config-disclosure-copy {
  display: grid;
  min-width: 0;
  gap: 2px;
}

.proxy-config-disclosure-name {
  overflow-wrap: anywhere;
  font-size: 13px;
  font-weight: 600;
}

.proxy-config-disclosure-meta {
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
}

.proxy-config-disclosure-indicator {
  width: 7px;
  height: 7px;
  flex: 0 0 auto;
  border-right: 1.5px solid currentColor;
  border-bottom: 1.5px solid currentColor;
  transform: rotate(45deg) translate(-2px, -2px);
  transition: transform 0.15s ease;
}

.proxy-config-disclosure-indicator.expanded {
  transform: rotate(225deg) translate(-1px, -1px);
}

.proxy-node-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
  gap: 6px;
  max-block-size: 360px;
  overflow: auto;
  padding: 8px 8px 14px;
  box-sizing: border-box;
  border-top: 1px solid var(--color-border, #e5e7eb);
  background: var(--color-bg-header, rgba(0, 0, 0, 0.02));
}

.proxy-test-actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.proxy-upload-row {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.proxy-upload-button {
  position: relative;
  overflow: hidden;
}

.proxy-upload-button input[type='file'] {
  position: absolute;
  inset: 0;
  opacity: 0;
  cursor: pointer;
}

.proxy-upload-button.disabled {
  opacity: 0.6;
  pointer-events: none;
}

.proxy-config-list {
  display: grid;
  gap: 6px;
}

.proxy-hidden-configs {
  display: grid;
  gap: 6px;
  padding-top: 10px;
  border-top: 1px solid var(--color-border, #e5e7eb);
}

.proxy-hidden-configs-heading {
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
  font-weight: 500;
}

.proxy-config-item {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  padding: 8px 10px;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 6px;
  background: var(--color-bg, #ffffff);
}

.proxy-config-details {
  display: grid;
  gap: 2px;
  min-width: 0;
  flex: 1;
}

.proxy-config-name {
  overflow-wrap: anywhere;
  color: var(--color-text, #1f2937);
  font-size: 13px;
  font-weight: 500;
}

.proxy-config-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
}

.proxy-config-action {
  display: inline-flex;
  flex: 0 0 30px;
  width: 30px;
  height: 30px;
  align-items: center;
  justify-content: center;
  border: 1px solid transparent;
  border-radius: 6px;
  background: transparent;
  color: var(--color-text-secondary, #6b7280);
  cursor: pointer;
}

.proxy-config-action:hover:not(:disabled) {
  border-color: var(--color-border, #d1d5db);
  color: var(--color-primary, #3b82f6);
  background: var(--color-bg-hover, rgba(0, 0, 0, 0.04));
}

.proxy-config-action.is-danger:hover:not(:disabled) {
  color: var(--color-danger, #b91c1c);
}

.proxy-config-action:disabled {
  cursor: default;
  opacity: 0.5;
}

.proxy-config-action svg {
  width: 16px;
  height: 16px;
}

.proxy-test-result {
  display: grid;
  gap: 4px;
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
}

.proxy-auto-no-available-nodes {
  color: var(--color-primary, #3b82f6);
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

.account-managed-badge,
.account-managed-notice {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  color: #16803c;
  font-size: 12px;
  font-weight: 600;
}

.account-managed-badge {
  padding: 4px 8px;
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 6px;
  background: rgba(34, 197, 94, 0.08);
}

.account-managed-notice {
  align-self: flex-start;
  padding: 9px 11px;
  border: 1px solid rgba(34, 197, 94, 0.25);
  border-radius: 6px;
  background: rgba(34, 197, 94, 0.06);
}

.account-managed-dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #22c55e;
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

.account-pool-summary {
  display: grid;
  grid-template-columns: minmax(180px, 1fr) minmax(140px, 0.7fr);
  gap: 10px 20px;
  padding: 14px 16px;
}

.account-pool-endpoint,
.account-pool-keys {
  min-width: 0;
}

.account-pool-endpoint {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.account-pool-keys {
  grid-column: 1 / -1;
}

.account-summary-label {
  color: var(--color-text-secondary, #6b7280);
  font-size: 11px;
  font-weight: 600;
}

.account-summary-value {
  color: var(--color-text, #1f2937);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  overflow-wrap: anywhere;
}

.account-keys-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 7px;
}

.account-keys-heading-main,
.account-keys-heading-actions,
.account-key-status {
  display: flex;
  align-items: center;
}

.account-keys-heading-main {
  min-width: 0;
  gap: 8px;
}

.account-keys-heading-actions {
  margin-left: auto;
  gap: 10px;
}

.account-key-status {
  gap: 12px;
  color: var(--color-text-secondary, #6b7280);
  font-size: 11px;
  white-space: nowrap;
}

.account-key-status-available {
  color: var(--color-success, #16803c);
}

.account-key-status-blacklisted.active {
  color: var(--color-danger, #ef4444);
}

.account-key-collapse-button {
  display: inline-flex;
  width: 26px;
  height: 26px;
  align-items: center;
  justify-content: center;
  padding: 0;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 6px;
  background: var(--color-bg, #fff);
  color: var(--color-text-secondary, #6b7280);
  cursor: pointer;
  transition: border-color 0.15s ease, background 0.15s ease, color 0.15s ease;
}

.account-key-clear-blacklists-button {
  border: 0;
  background: transparent;
  color: var(--color-danger, #ef4444);
  font-size: 11px;
  padding: 3px 0;
  cursor: pointer;
}

.account-key-clear-blacklists-button:focus-visible {
  outline: 2px solid var(--color-primary, #3b82f6);
  outline-offset: 2px;
}

.account-key-clear-blacklists-button:disabled {
  cursor: wait;
  opacity: 0.6;
}

.account-key-collapse-button:hover {
  border-color: var(--color-border-hover, #c4c8d0);
  background: var(--color-bg-hover, rgba(0, 0, 0, 0.04));
  color: var(--color-text, #1f2937);
}

.account-key-collapse-button:focus-visible {
  outline: 2px solid var(--color-primary, #3b82f6);
  outline-offset: 2px;
}

.account-key-collapse-button svg {
  width: 15px;
  height: 15px;
  transition: transform 0.15s ease;
}

.account-key-collapse-button svg.expanded {
  transform: rotate(180deg);
}

.account-key-count {
  color: var(--color-text-tertiary, #9ca3af);
  font-size: 11px;
}

.account-key-list {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}

.account-key-row {
  display: flex;
  min-width: 0;
  align-items: center;
}

.account-key-row-blacklisted {
  flex: 0 0 auto;
  gap: 5px;
  padding: 4px 7px;
  border: 1px solid color-mix(in srgb, var(--color-danger, #ef4444) 30%, var(--color-border, #e5e7eb));
  border-radius: 5px;
  background: color-mix(in srgb, var(--color-danger, #ef4444) 5%, transparent);
}

.blacklist-key-icon {
  width: 13px;
  height: 13px;
  flex: 0 0 auto;
  color: var(--color-danger, #ef4444);
}

.account-key-row-blacklisted .account-key-chip {
  padding: 0;
  border: 0;
  background: transparent;
}

.account-key-row-blacklisted .blacklist-time {
  white-space: nowrap;
  color: var(--color-text-secondary, #4b5563);
  font-size: 10px;
}

.blacklist-minutes {
  color: var(--color-danger, #ef4444);
}

.account-key-row-blacklisted .key-unbind-btn {
  flex: 0 0 auto;
  margin-left: 2px;
}

.account-key-chip {
  padding: 4px 8px;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 5px;
  background: var(--color-bg, #fff);
  color: var(--color-text-secondary, #4b5563);
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 11px;
}

.pool-blacklist-section {
  padding: 8px 16px;
  border-top: 1px solid var(--color-border, #e5e7eb);
}

.blacklist-reason {
  color: var(--color-danger, #ef4444);
  font-size: 11px;
  white-space: nowrap;
}

.blacklist-reason-prefix,
.blacklist-reason-suffix {
  color: var(--color-text, #1f2937);
  font-size: 11px;
  white-space: nowrap;
}

.special-blacklist-rules {
  gap: 8px;
}

.special-rules-heading {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.special-rule-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 8px;
  padding: 10px;
  border: 1px solid var(--color-border, #e5e7eb);
  border-radius: 6px;
}

.special-rule-row .form-field {
  margin: 0;
}

.special-rule-actions {
  display: flex;
  align-items: end;
  justify-content: end;
  gap: 4px;
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

.pool-key-card.blacklisted {
  border-color: color-mix(in srgb, var(--color-danger, #ef4444) 30%, var(--color-border, #e5e7eb));
  background: color-mix(in srgb, var(--color-danger, #ef4444) 5%, transparent);
}

.pool-key-card.blacklisted .key-icon {
  color: var(--color-danger, #ef4444) !important;
}

.pool-key-card.blacklisted .pool-key-name,
.pool-key-card.blacklisted .blacklist-reason-prefix,
.pool-key-card.blacklisted .blacklist-reason-suffix {
  color: var(--color-text, #1f2937);
}

.pool-key-card.blacklisted .blacklist-reason,
.pool-key-card.blacklisted .blacklist-minutes {
  color: var(--color-danger, #ef4444);
}

.pool-key-card.blacklisted .blacklist-time {
  color: var(--color-text-secondary, #4b5563);
  font-size: 10px;
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
.pool-type-selector {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 4px;
  padding: 3px;
  margin-top: 4px;
  border: 1px solid var(--color-border, #d1d5db);
  border-radius: 7px;
  background: var(--color-bg-header, rgba(0, 0, 0, 0.03));
}

.pool-type-selector.disabled {
  opacity: 0.75;
}

.pool-type-option {
  cursor: pointer;
}

.pool-type-selector.disabled .pool-type-option {
  cursor: default;
}

.pool-type-option input {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}

.pool-type-option span {
  display: block;
  padding: 7px 10px;
  border-radius: 5px;
  color: var(--color-text-secondary, #6b7280);
  font-size: 12px;
  font-weight: 600;
  text-align: center;
}

.pool-type-option.selected span {
  background: var(--color-bg, #fff);
  color: var(--color-text, #1f2937);
  box-shadow: 0 1px 2px rgba(15, 23, 42, 0.1);
}

.form-field-hint {
  color: var(--color-text-tertiary, #9ca3af);
  font-size: 11px;
  font-weight: 400;
  line-height: 1.45;
}

.account-keys-textarea {
  min-height: 132px;
  resize: vertical;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 12px;
  line-height: 1.55;
}

.account-blacklist-inputs {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px;
  margin-top: 4px;
}

.account-blacklist-inputs .form-field {
  margin: 0;
}

.account-log-options {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  padding-top: 12px;
  border-top: 1px solid var(--color-border, #e5e7eb);
}

.account-option-toggle {
  align-items: flex-start;
  flex-wrap: wrap;
}

.account-option-toggle input {
  flex: 0 0 auto;
  margin-top: 2px;
}

.account-option-toggle .form-field-hint {
  flex-basis: 100%;
  padding-left: 26px;
  margin-top: 2px;
}

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

.proxy-auto-disable-toggle {
  align-items: flex-start;
  flex-wrap: wrap;
}

.proxy-auto-disable-toggle .form-field-hint {
  flex-basis: 100%;
  padding-left: 26px;
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

@media (max-width: 1100px) {
}

@media (max-width: 760px) {
  .account-log-options {
    grid-template-columns: minmax(0, 1fr);
  }

  .proxy-strategy-group-heading {
    align-items: stretch;
    flex-direction: column;
  }

  .proxy-bulk-test-button {
    width: 100%;
    white-space: normal;
  }

  .proxy-node-grid {
    grid-template-columns: minmax(0, 1fr);
  }

  .pool-sub-tabs {
    align-items: stretch;
    gap: 8px;
    overflow-x: auto;
    padding-bottom: 10px;
    scrollbar-width: none;
  }

  .pool-sub-tabs::-webkit-scrollbar {
    display: none;
  }

  .sub-tab-pill,
  .sub-tab-action-btn {
    flex: 0 0 auto;
    min-height: 36px;
    white-space: nowrap;
  }

  .proxy-bulk-test-button {
    white-space: normal;
  }

  .sub-tab-actions {
    margin-left: 0;
  }

  .pool-container {
    border-radius: 14px;
  }

  .pool-header {
    display: grid;
    grid-template-columns: 1fr;
    align-items: stretch;
    gap: 10px;
    padding: 12px;
  }

  .pool-header-left,
  .pool-header-right {
    min-width: 0;
  }

  .pool-name {
    overflow-wrap: anywhere;
  }

  .pool-header-right {
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px;
  }

  .mode-switch-group {
    flex: 1 1 auto;
  }

  .pool-members {
    display: grid;
    grid-template-columns: 1fr;
    padding: 10px;
  }

  .account-pool-summary {
    grid-template-columns: 1fr;
    padding: 12px;
  }

  .account-pool-keys {
    grid-column: auto;
  }

  .account-key-list {
    align-items: stretch;
  }

  .account-key-chip {
    min-width: 0;
    overflow-wrap: anywhere;
  }

  .account-key-row {
    align-items: flex-start;
  }

  .account-key-row-blacklisted {
    flex-basis: 100%;
  }

  .pool-member-card {
    width: 100%;
    min-width: 0;
    box-sizing: border-box;
    justify-content: space-between;
  }

  .pool-member-name,
  .pool-key-name,
  .unbound-key-name,
  .blacklist-time {
    white-space: normal;
    overflow-wrap: anywhere;
  }

  .pool-keys-section,
  .pool-blacklist-section {
    padding: 10px 12px;
  }

  .pool-keys-list,
  .unbound-keys-list {
    display: grid;
    grid-template-columns: 1fr;
  }

  .pool-key-card,
  .unbound-key-card {
    width: 100%;
    box-sizing: border-box;
    justify-content: space-between;
  }

  .pool-key-info,
  .unbound-key-info {
    min-width: 0;
  }

  .key-bind-select {
    width: 100%;
    min-width: 0;
  }

  .pool-mode-selector {
    display: grid;
    grid-template-columns: 1fr;
  }

  .account-blacklist-inputs {
    grid-template-columns: 1fr;
  }

  .special-rule-row {
    grid-template-columns: 1fr;
  }

  .pool-member-row {
    grid-template-columns: 1fr;
  }

  .member-level-input {
    justify-content: space-between;
  }

  .level-select-inline {
    min-height: 30px;
  }
}
</style>
