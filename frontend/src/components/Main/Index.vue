<template>
  <div class="main-shell">
    <div class="global-actions">
      <p class="global-eyebrow">{{ t('components.main.hero.eyebrow') }}</p>
      <button
        class="ghost-icon"
        :data-tooltip="t('components.main.controls.theme')"
        @click="toggleTheme"
      >
        <svg v-if="themeIcon === 'sun'" viewBox="0 0 24 24" aria-hidden="true">
          <circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.5" fill="none" />
          <path
            d="M12 3v2m0 14v2m9-9h-2M5 12H3m14.95 6.95-1.41-1.41M7.46 7.46 6.05 6.05m12.9 0-1.41 1.41M7.46 16.54l-1.41 1.41"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
          />
        </svg>
        <svg v-else viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M21 12.79A9 9 0 1111.21 3a7 7 0 109.79 9.79z"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
      <button
        class="ghost-icon"
        :data-tooltip="t('components.main.controls.settings')"
        @click="goToSettings"
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M12 15a3 3 0 100-6 3 3 0 000 6z"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
            fill="none"
          />
          <path
            d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09a1.65 1.65 0 00-1-1.51 1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09a1.65 1.65 0 001.51-1 1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
            fill="none"
          />
        </svg>
      </button>
    </div>
    <div class="contrib-page">
      <section class="contrib-hero">
        <h1 v-if="showHomeTitle">{{ t('components.main.hero.title') }}</h1>
        <!-- <p class="lead">
          {{ t('components.main.hero.lead') }}
        </p> -->
      </section>

      <section class="automation-section">
      <div class="section-header">
        <div class="tab-group" role="tablist" :aria-label="t('components.main.tabs.ariaLabel')">
          <button
            v-for="tab in orderedTabs"
            :key="tab.id"
            class="tab-pill"
            :class="{ active: activeTab === tab.id, dragging: draggingTab === tab.id }"
            role="tab"
            :aria-selected="activeTab === tab.id"
            type="button"
            draggable="true"
            @click="onTabChange(tab.id)"
            @dragstart="onTabDragStart(tab.id, $event)"
            @dragenter.prevent="onTabDragEnter(tab.id)"
            @dragover.prevent
            @dragend="onTabDragEnd"
            @drop.prevent="onTabDrop(tab.id)"
          >
            {{ tab.label }}
          </button>
        </div>
      </div>

      <!-- 'others' Tab: CLI 工具选择器 -->
      <div v-if="activeTab === 'others'" class="cli-tool-selector">
        <div class="tool-selector-row">
          <select
            v-model="selectedToolId"
            class="tool-select"
            @change="onToolSelect"
          >
            <option v-if="customCliTools.length === 0" value="" disabled>
              {{ t('components.main.customCli.noTools') }}
            </option>
            <option
              v-for="tool in customCliTools"
              :key="tool.id"
              :value="tool.id"
            >
              {{ tool.name }}
            </option>
          </select>
          <button
            class="ghost-icon add-tool-btn"
            :data-tooltip="t('components.main.customCli.addTool')"
            @click="openCliToolModal"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                d="M12 5v14M5 12h14"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
                fill="none"
              />
            </svg>
          </button>
          <button
            v-if="selectedToolId"
            class="ghost-icon"
            :data-tooltip="t('components.main.form.editTitle')"
            @click="editCurrentCliTool"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                d="M11.983 2.25a1.125 1.125 0 011.077.81l.563 2.101a7.482 7.482 0 012.326 1.343l2.08-.621a1.125 1.125 0 011.356.651l1.313 3.207a1.125 1.125 0 01-.442 1.339l-1.86 1.205a7.418 7.418 0 010 2.686l1.86 1.205a1.125 1.125 0 01.442 1.339l-1.313 3.207a1.125 1.125 0 01-1.356.651l-2.08-.621a7.482 7.482 0 01-2.326 1.343l-.563 2.101a1.125 1.125 0 01-1.077.81h-2.634a1.125 1.125 0 01-1.077-.81l-.563-2.101a7.482 7.482 0 01-2.326-1.343l-2.08.621a1.125 1.125 0 01-1.356-.651l-1.313-3.207a1.125 1.125 0 01.442-1.339l1.86-1.205a7.418 7.418 0 010-2.686l-1.86-1.205a1.125 1.125 0 01-.442-1.339l1.313-3.207a1.125 1.125 0 011.356-.651l2.08.621a7.482 7.482 0 012.326-1.343l.563-2.101a1.125 1.125 0 011.077-.81h2.634z"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
              <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </button>
          <button
            v-if="selectedToolId"
            class="ghost-icon"
            :data-tooltip="t('components.main.form.actions.delete')"
            @click="deleteCurrentCliTool"
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                d="M9 3h6m-7 4h8m-6 0v11m4-11v11M5 7h14l-.867 12.138A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.862L5 7z"
                fill="none"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
          </button>
        </div>
        <p v-if="customCliTools.length === 0" class="no-tools-hint">
          {{ t('components.main.customCli.noTools') }} - {{ t('components.main.customCli.addTool') }}
        </p>
      </div>

	      <!-- 供应商/池子子标签页（claude/openai-responses/openai-chat） -->
	      <PoolPanel
	        v-if="activeTab !== 'others'"
	        :platform="activeTab"
	        :providers="activeCards"
	        :highlighted-provider="highlightedProvider"
	        :resolved-theme="resolvedTheme"
	        :provider-favicon-url="providerFaviconUrl"
	        :mark-favicon-failed="markFaviconFailed"
	        :format-official-site="formatOfficialSite"
	        :open-official-site="openOfficialSite"
	        :provider-stat-display="providerStatDisplay"
	        :relay-keys="relayKeys"
	        @edit="configure"
	        @remove="requestRemove"
	        @duplicate="handleDuplicate"
	        @add-provider="openCreateModal"
	        @refresh="refreshAllData"
	      />

      <!-- others Tab: 原有卡片列表 -->
      <div v-if="activeTab === 'others'" class="automation-list" @dragover.prevent>
        <article
          v-for="card in activeCards"
          :key="card.id"
          :ref="el => { if (card.name === highlightedProvider) scrollToCard(el as HTMLElement) }"
          :class="[
            'automation-card',
            { dragging: draggingId === card.id },
            { 'is-last-used': isLastUsedProvider(card.name) },
            { 'is-highlighted': highlightedProvider === card.name }
          ]"
          draggable="true"
          @dragstart="onDragStart(card.id)"
          @dragend="onDragEnd"
          @drop="onDrop(card.id)"
        >
          <!-- 正在使用标签 -->
          <span v-if="isLastUsedProvider(card.name)" class="last-used-badge">
            ✓ {{ t('components.main.providers.lastUsed') }}
          </span>
          <div class="card-leading">
            <div
              :class="['card-icon', { empty: !providerFaviconUrl(card.officialSite) }]"
              :style="{ backgroundColor: providerFaviconUrl(card.officialSite) ? card.tint : 'transparent', color: card.accent }"
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
            <button class="ghost-icon" :data-tooltip="t('components.main.form.editTitle')" @click="configure(card)">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  d="M11.983 2.25a1.125 1.125 0 011.077.81l.563 2.101a7.482 7.482 0 012.326 1.343l2.08-.621a1.125 1.125 0 011.356.651l1.313 3.207a1.125 1.125 0 01-.442 1.339l-1.86 1.205a7.418 7.418 0 010 2.686l1.86 1.205a1.125 1.125 0 01.442 1.339l-1.313 3.207a1.125 1.125 0 01-1.356.651l-2.08-.621a7.482 7.482 0 01-2.326 1.343l-.563 2.101a1.125 1.125 0 01-1.077.81h-2.634a1.125 1.125 0 01-1.077-.81l-.563-2.101a7.482 7.482 0 01-2.326-1.343l-2.08.621a1.125 1.125 0 01-1.356-.651l-1.313-3.207a1.125 1.125 0 01.442-1.339l1.86-1.205a7.418 7.418 0 010-2.686l-1.86-1.205a1.125 1.125 0 01-.442-1.339l1.313-3.207a1.125 1.125 0 011.356-.651l2.08.621a7.482 7.482 0 012.326-1.343l.563-2.101a1.125 1.125 0 011.077-.81h2.634z"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
                <path d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </button>
            <button class="ghost-icon" :data-tooltip="t('components.main.controls.duplicate')" @click="handleDuplicate(card)">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </button>
            <button class="ghost-icon" :data-tooltip="t('components.main.form.actions.delete')" @click="requestRemove(card)">
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  d="M9 3h6m-7 4h8m-6 0v11m4-11v11M5 7h14l-.867 12.138A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.862L5 7z"
                  fill="none"
                  stroke="currentColor"
                  stroke-width="1.5"
                  stroke-linecap="round"
                  stroke-linejoin="round"
                />
              </svg>
            </button>
          </div>
        </article>
      </div>

      <!-- 自定义 CLI 工具配置文件编辑器 -->
      <CustomCliConfigEditor
        v-if="activeTab === 'others' && selectedToolId && selectedCustomCliTool"
        :tool-id="selectedToolId"
        :tool-name="selectedCustomCliTool.name"
        :config-files="selectedCustomCliTool.configFiles"
        @saved="onConfigFileSaved"
      />
      </section>

      <BaseModal
      :open="modalState.open"
      :title="modalState.editingId ? t('components.main.form.editTitle') : t('components.main.form.createTitle')"
      @close="closeModal"
    >
      <form class="vendor-form" @submit.prevent="submitModal">
                <label class="form-field">
                  <span>{{ t('components.main.form.labels.name') }}</span>
                  <BaseInput
                    v-model="modalState.form.name"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.name')"
                    required
                    :disabled="Boolean(modalState.editingId)"
                  />
                </label>

                <label class="form-field">
                  <span class="label-row">
                    {{ t('components.main.form.labels.apiUrl') }}
                    <span v-if="modalState.errors.apiUrl" class="field-error">
                      {{ modalState.errors.apiUrl }}
                    </span>
                  </span>
                  <BaseInput
                    v-model="modalState.form.apiUrl"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.apiUrl')"
                    required
                    :class="{ 'has-error': !!modalState.errors.apiUrl, 'shake-error': shakeFields.apiUrl }"
                  />
                </label>

                <label class="form-field">
                  <span>{{ t('components.main.form.labels.officialSite') }}</span>
                  <BaseInput
                    v-model="modalState.form.officialSite"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.officialSite')"
                  />
                </label>

                <label class="form-field">
                  <span>{{ t('components.main.form.labels.apiKey') }}</span>
                  <BaseInput
                    v-model="modalState.form.apiKey"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.apiKey')"
                    :class="{ 'has-error': !!modalState.errors.apiKey, 'shake-error': shakeFields.apiKey }"
                  />
                </label>

                <!-- 协议端点（按平台互斥显示）-->
                <label v-if="showMessagesEndpointField" class="form-field">
                  <div class="label-with-hint">{{ t('components.main.form.labels.messagesEndpoint') }} <HelpHint :text="t('components.main.form.hints.messagesEndpoint')" /></div>
                  <BaseInput
                    v-model="modalState.form.apiEndpoint"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.messagesEndpoint')"
                    :class="{ 'has-error': !!modalState.errors.protocolEndpoint, 'shake-error': shakeFields.protocolEndpoint }"
                  />
                </label>

                <label v-if="showResponsesEndpointField" class="form-field">
                  <div class="label-with-hint">{{ t('components.main.form.labels.responsesEndpoint') }} <HelpHint :text="t('components.main.form.hints.responsesEndpoint')" /></div>
                  <BaseInput
                    v-model="modalState.form.responsesEndpoint"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.responsesEndpoint')"
                    :class="{ 'has-error': !!modalState.errors.protocolEndpoint, 'shake-error': shakeFields.protocolEndpoint }"
                  />
                </label>

                <label v-if="showChatEndpointField" class="form-field">
                  <div class="label-with-hint">{{ t('components.main.form.labels.chatEndpoint') }} <HelpHint :text="t('components.main.form.hints.chatEndpoint')" /></div>
                  <BaseInput
                    v-model="modalState.form.chatEndpoint"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.chatEndpoint')"
                    :class="{ 'has-error': !!modalState.errors.protocolEndpoint, 'shake-error': shakeFields.protocolEndpoint }"
                  />
                </label>

                <label class="form-field">
                  <div class="label-with-hint">{{ t('components.main.form.labels.modelsEndpoint') }} <HelpHint :text="t('components.main.form.hints.modelsEndpoint')" /></div>
                  <BaseInput
                    v-model="modalState.form.modelsEndpoint"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.modelsEndpoint')"
                    :class="{ 'has-error': !!modalState.errors.modelsEndpoint, 'shake-error': shakeFields.modelsEndpoint }"
                  />
                </label>

                <!-- 认证方式 -->
                <div class="form-field">
                  <div class="label-with-hint">{{ t('components.main.form.labels.connectivityAuthType') }} <HelpHint :text="t('components.main.form.hints.connectivityAuthType')" /></div>
                  <Listbox v-model="selectedAuthType" v-slot="{ open }">
                    <div class="level-select">
                      <ListboxButton class="level-select-button">
                        <span class="level-label">
                          {{ authTypeOptions.find((item) => item.value === selectedAuthType)?.label || selectedAuthType }}
                        </span>
                        <svg viewBox="0 0 20 20" aria-hidden="true">
                          <path d="M6 8l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" fill="none" />
                        </svg>
                      </ListboxButton>
                      <ListboxOptions v-if="open" class="level-select-options">
                        <ListboxOption
                          v-for="option in authTypeOptions"
                          :key="option.value"
                          :value="option.value"
                          v-slot="{ active, selected }"
                        >
                          <div :class="['level-option', { active, selected }]">
                            <span class="level-name">{{ option.label }}</span>
                          </div>
                        </ListboxOption>
                      </ListboxOptions>
                    </div>
                  </Listbox>
                  <BaseInput
                    v-model="customAuthHeader"
                    type="text"
                    :placeholder="t('components.main.form.placeholders.customAuthHeader')"
                    class="mt-2"
                  />
                                  </div>


                <div class="form-field">
                  <ModelWhitelistEditor v-model="modalState.form.supportedModels" />
                </div>

                <div class="form-field">
                  <ModelMappingEditor v-model="modalState.form.modelMapping" />
                </div>

                <!-- 可用性监控配置 -->
                <div class="form-field switch-field">
                  <div class="label-with-hint">{{ t('components.main.form.labels.availabilityMonitor') }} <HelpHint :text="t('components.main.form.hints.availabilityMonitor')" /></div>
                  <div class="switch-inline">
                    <label class="mac-switch">
                      <input type="checkbox" v-model="modalState.form.availabilityMonitorEnabled" />
                      <span></span>
                    </label>
                    <span class="switch-text">
                      {{ modalState.form.availabilityMonitorEnabled ? t('components.main.form.switch.on') : t('components.main.form.switch.off') }}
                    </span>
                  </div>
                                  </div>

	                <!-- 高级配置提示 -->
                <div v-if="modalState.form.availabilityMonitorEnabled" class="form-field">
                                  </div>

                <section class="endpoint-test-panel">
                  <label class="form-field">
                    <span>{{ t('components.main.form.labels.testModel') }}</span>
                    <div class="field-with-action field-with-dropdown-action">
                      <div class="provider-model-combobox">
                        <input
                          v-model.trim="providerTestModel"
                          class="base-input"
                          :class="{ 'has-error': !!modalState.errors.testModel, 'shake-error': shakeFields.testModel }"
                          :placeholder="providerModelsLoading ? t('components.main.form.connectivity.loadingModels') : t('components.main.form.placeholders.testModel')"
                          @focus="providerModelDropdownOpen = true"
                          @blur="providerModelDropdownOpen = false"
                        />
                        <button
                          class="provider-model-toggle"
                          type="button"
                          @mousedown.prevent
                          @click="toggleProviderModelDropdown"
                        >
                          <svg viewBox="0 0 20 20" aria-hidden="true">
                            <path d="M6 8l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
                          </svg>
                        </button>
                        <div v-if="providerModelDropdownOpen" class="provider-model-options">
                          <button
                            v-for="model in combinedProviderModelOptions"
                            :key="model"
                            class="provider-model-option"
                            type="button"
                            @mousedown.prevent="selectProviderTestModel(model)"
                          >
                            {{ model }}
                          </button>
                          <div v-if="providerModelsLoading" class="provider-model-empty">
                            {{ t('components.main.form.connectivity.loadingModels') }}
                          </div>
                          <div v-else-if="!providerModelOptions.length" class="provider-model-empty">
                            {{ t('components.main.form.connectivity.noModelOptions') }}
                          </div>
                        </div>
                      </div>
                      <button class="field-test-btn field-test-btn-tight" type="button" :disabled="testingModelsEndpoint" @click="handleTestModelsEndpoint">
                        {{ testingModelsEndpoint ? t('components.main.form.connectivity.testing') : t('components.main.form.connectivity.testModels') }}
                      </button>
                    </div>
                  </label>
                  <label class="form-field">
                    <span>{{ t('components.main.form.labels.testMessage') }}</span>
                    <div class="field-with-action">
                      <BaseInput
                        v-model="providerTestMessage"
                        type="text"
                        :placeholder="t('components.main.form.placeholders.testMessage')"
                      />
                      <button class="field-test-btn" type="button" :disabled="testingProtocolEndpoint" @click="handleTestProtocolEndpoint">
                        {{ testingProtocolEndpoint ? t('components.main.form.connectivity.testing') : t('components.main.form.connectivity.sendTestMessage') }}
                      </button>
                    </div>
                  </label>
                  <div v-if="protocolEndpointTestResult" class="field-test-output-group">
                    <div class="field-test-output">
                      <div class="field-test-output-title">{{ t('components.main.form.connectivity.httpResponse') }}</div>
                      <pre>{{ protocolEndpointTestResult.httpResponse || protocolEndpointTestResult.message }}</pre>
                    </div>
                    <div class="field-test-output">
                      <div class="field-test-output-title">{{ t('components.main.form.connectivity.rawResult') }}</div>
                      <ReadOnlyJsonEditor
                        :value="protocolEndpointTestResult.rawResult || protocolEndpointTestResult.message"
                        height="260px"
                      />
                    </div>
                  </div>
                  <p v-if="modelsEndpointTestResult" :class="['field-test-result', modelsEndpointTestResult.success ? 'success' : 'error']">
                    {{ modelsEndpointTestResult.message }}
                  </p>
                </section>

                <footer class="form-actions">
                  <BaseButton variant="outline" type="button" @click="closeModal">
                    {{ t('components.main.form.actions.cancel') }}
                  </BaseButton>
                  <BaseButton type="submit">
                    {{ t('components.main.form.actions.save') }}
                  </BaseButton>
                </footer>
      </form>
      </BaseModal>
      <BaseModal
      :open="confirmState.open"
      :title="t('components.main.form.confirmDeleteTitle')"
      variant="confirm"
      @close="closeConfirm"
    >
      <div class="confirm-body">
        <p>
          {{ t('components.main.form.confirmDeleteMessage', { name: confirmState.card?.name ?? '' }) }}
        </p>
      </div>
      <footer class="form-actions confirm-actions">
        <BaseButton variant="outline" type="button" @click="closeConfirm">
          {{ t('components.main.form.actions.cancel') }}
        </BaseButton>
        <BaseButton variant="danger" type="button" @click="confirmRemove">
          {{ t('components.main.form.actions.delete') }}
        </BaseButton>
      </footer>
      </BaseModal>

      <!-- CLI 工具配置模态框 -->
      <BaseModal
        :open="cliToolModalState.open"
        :title="cliToolModalState.editingId ? t('components.main.customCli.editTitle') : t('components.main.customCli.createTitle')"
        @close="closeCliToolModal"
      >
        <form class="vendor-form cli-tool-form" @submit.prevent="submitCliToolModal">
          <label class="form-field">
            <span>{{ t('components.main.customCli.toolName') }}</span>
            <BaseInput
              v-model="cliToolModalState.form.name"
              type="text"
              :placeholder="t('components.main.customCli.toolNamePlaceholder')"
              required
            />
          </label>

          <!-- 配置文件列表 -->
          <div class="form-field">
            <div class="field-header">
              <span>{{ t('components.main.customCli.configFiles') }}</span>
              <button type="button" class="add-btn" @click="addConfigFile">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
                </svg>
              </button>
            </div>
            <div class="config-files-list">
              <div
                v-for="(cf, idx) in cliToolModalState.form.configFiles"
                :key="cf.id"
                class="config-file-item"
              >
                <div class="config-file-row">
                  <BaseInput
                    v-model="cf.label"
                    class="config-label-input"
                    :placeholder="t('components.main.customCli.labelPlaceholder')"
                  />
                  <select v-model="cf.format" class="config-format-select">
                    <option value="json">JSON</option>
                    <option value="toml">TOML</option>
                    <option value="env">ENV</option>
                  </select>
                  <label class="primary-checkbox">
                    <input type="checkbox" v-model="cf.isPrimary" />
                    <span>{{ t('components.main.customCli.primary') }}</span>
                  </label>
                  <button
                    type="button"
                    class="remove-btn"
                    :disabled="cliToolModalState.form.configFiles.length <= 1"
                    @click="removeConfigFile(idx)"
                  >
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
                    </svg>
                  </button>
                </div>
                <BaseInput
                  v-model="cf.path"
                  class="config-path-input"
                  :placeholder="t('components.main.customCli.pathPlaceholder')"
                />
              </div>
            </div>
          </div>

          <!-- 代理注入配置 -->
          <div class="form-field">
            <div class="field-header">
              <span>{{ t('components.main.customCli.proxySettings') }}</span>
              <button type="button" class="add-btn" @click="addProxyInjection">
                <svg viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 5v14M5 12h14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
                </svg>
              </button>
            </div>
            <div class="proxy-injection-list">
              <div
                v-for="(pi, idx) in cliToolModalState.form.proxyInjection"
                :key="idx"
                class="proxy-injection-item"
              >
                <div class="proxy-injection-row">
                  <select v-model="pi.targetFileId" class="target-file-select">
                    <option value="">{{ t('components.main.customCli.selectConfigFile') }}</option>
                    <option
                      v-for="cf in cliToolModalState.form.configFiles"
                      :key="cf.id"
                      :value="cf.id"
                    >
                      {{ cf.label || cf.path || t('components.main.customCli.unnamed') }}
                    </option>
                  </select>
                  <button
                    type="button"
                    class="remove-btn"
                    :disabled="cliToolModalState.form.proxyInjection.length <= 1"
                    @click="removeProxyInjection(idx)"
                  >
                    <svg viewBox="0 0 24 24" aria-hidden="true">
                      <path d="M6 18L18 6M6 6l12 12" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" fill="none" />
                    </svg>
                  </button>
                </div>
                <div class="proxy-fields-row">
                  <BaseInput
                    v-model="pi.baseUrlField"
                    class="proxy-field-input"
                    :placeholder="t('components.main.customCli.baseUrlFieldPlaceholder')"
                  />
                  <BaseInput
                    v-model="pi.authTokenField"
                    class="proxy-field-input"
                    :placeholder="t('components.main.customCli.authTokenFieldPlaceholder')"
                  />
                </div>
              </div>
            </div>
            <HelpHint :text="t('components.main.customCli.proxyHint')" />
          </div>

          <footer class="form-actions">
            <BaseButton variant="outline" type="button" @click="closeCliToolModal">
              {{ t('components.main.form.actions.cancel') }}
            </BaseButton>
            <BaseButton type="submit">
              {{ t('components.main.form.actions.save') }}
            </BaseButton>
          </footer>
        </form>
      </BaseModal>

      <!-- CLI 工具删除确认框 -->
      <BaseModal
        :open="cliToolConfirmState.open"
        :title="t('components.main.customCli.deleteTitle')"
        variant="confirm"
        @close="closeCliToolConfirm"
      >
        <div class="confirm-body">
          <p>{{ t('components.main.customCli.deleteMessage', { name: cliToolConfirmState.tool?.name ?? '' }) }}</p>
        </div>
        <footer class="form-actions confirm-actions">
          <BaseButton variant="outline" type="button" @click="closeCliToolConfirm">
            {{ t('components.main.form.actions.cancel') }}
          </BaseButton>
          <BaseButton variant="danger" type="button" @click="confirmDeleteCliTool">
            {{ t('components.main.form.actions.delete') }}
          </BaseButton>
        </footer>
      </BaseModal>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Listbox, ListboxButton, ListboxOptions, ListboxOption } from '@headlessui/vue'
import { Browser, Call, Events } from '@wailsio/runtime'
import { automationCardGroups, createAutomationCards, type AutomationCard } from '../../data/cards'
import BaseButton from '../common/BaseButton.vue'
import BaseModal from '../common/BaseModal.vue'
import BaseInput from '../common/BaseInput.vue'
import ReadOnlyJsonEditor from '../common/ReadOnlyJsonEditor.vue'
import ModelWhitelistEditor from '../common/ModelWhitelistEditor.vue'
import HelpHint from '../common/HelpHint.vue'
import ModelMappingEditor from '../common/ModelMappingEditor.vue'
import CustomCliConfigEditor from '../common/CustomCliConfigEditor.vue'
import PoolPanel from './PoolPanel.vue'
import { ListRelayKeys, type RelayKeyItem } from '../../services/providerPool'
import { RELAY_KEYS_UPDATED_EVENT } from '../../events/relayKeys'
import { LoadProviders, SaveProviders } from '../../../bindings/codeswitch/services/providerservice'
import { fetchProxyStatus, enableProxy, disableProxy } from '../../services/claudeSettings'
import { fetchProviderDailyStats, type ProviderDailyStat } from '../../services/logs'
import { fetchCurrentVersion } from '../../services/version'
import { fetchAppSettings, type AppSettings } from '../../services/appSettings'
import { getCurrentTheme, setTheme, type ThemeMode } from '../../utils/ThemeManager'
import { useRouter } from 'vue-router'
import { showToast } from '../../utils/toast'
import { extractErrorMessage } from '../../utils/error'
import {
  listCustomCliTools,
  createCustomCliTool,
  updateCustomCliTool,
  deleteCustomCliTool,
  getCustomCliProxyStatus,
  enableCustomCliProxy,
  disableCustomCliProxy,
  type CustomCliTool,
  type ConfigFile,
  type ProxyInjection,
} from '../../services/customCliService'
import {
  getConnectivityResults,
  StatusAvailable,
  StatusDegraded,
  StatusUnavailable,
  StatusMissing,
  getStatusColorClass,
  type ConnectivityResult,
} from '../../services/connectivity'
import {
  getLatestResults,
  HealthStatus,
  type ProviderTimeline,
} from '../../services/healthcheck'

const { t } = useI18n()
const router = useRouter()
const themeMode = ref<ThemeMode>(getCurrentTheme())
const resolvedTheme = computed(() => {
  if (themeMode.value === 'systemdefault') {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }
  return themeMode.value
})
const themeIcon = computed(() => (resolvedTheme.value === 'dark' ? 'moon' : 'sun'))

const proxyStates = reactive<Record<ProviderTab, boolean>>({
  claude: false,
  'openai-responses': false,
  'openai-chat': false,
  others: false,
})
const proxyBusy = reactive<Record<ProviderTab, boolean>>({
  claude: false,
  'openai-responses': false,
  'openai-chat': false,
  others: false,
})

// 直连应用状态
const directAppliedIds = reactive<Record<ProviderTab, string | number | null>>({
  claude: null,
  'openai-responses': null,
  'openai-chat': null,
  others: null,
})

const supportsDirectApply = (tab: ProviderTab) =>
  tab !== 'others' && tab !== 'openai-chat'

const refreshDirectAppliedStatus = async (tab: ProviderTab = activeTab.value) => {
  if (!supportsDirectApply(tab)) return

  try {
    let id: string | number | null = null
    if (tab === 'claude') {
      id = await Call.ByName('codeswitch/services.ClaudeSettingsService.GetDirectAppliedProviderID')
    } else if (tab === 'openai-responses') {
      id = await Call.ByName('codeswitch/services.CodexSettingsService.GetDirectAppliedProviderID')
    }
    directAppliedIds[tab] = id
  } catch (error) {
    console.error(`Failed to get direct applied status for ${tab}`, error)
  }
}

const handleDirectApply = async (card: AutomationCard) => {
  if (activeProxyState.value) return
  const tab = activeTab.value
  try {
    if (tab === 'claude') {
      await Call.ByName('codeswitch/services.ClaudeSettingsService.ApplySingleProvider', card.id)
    } else if (tab === 'openai-responses') {
      await Call.ByName('codeswitch/services.CodexSettingsService.ApplySingleProvider', card.id)
    }
    await refreshDirectAppliedStatus(tab)
    showToast(t('components.main.directApply.success', { name: card.name }), 'success')
  } catch (error) {
    console.error('Direct apply failed', error)
    showToast(t('components.main.directApply.failed'), 'error')
  }
}

const isDirectApplied = (card: AutomationCard) => {
  const appliedId = directAppliedIds[activeTab.value]
  if (appliedId === null) return false

  return card.id === appliedId
}

const providerSwitchDependsOnManagedProxy = () =>
  activeTab.value === 'openai-responses' || activeTab.value === 'openai-chat'

const isProviderSwitchDisabled = () =>
  providerSwitchDependsOnManagedProxy() && !activeProxyState.value

const providerSwitchTitle = () =>
  isProviderSwitchDisabled() ? t('components.main.providers.codexSwitchDisabled') : ''

const handleProviderSwitchChange = () => {
  if (isProviderSwitchDisabled()) return
  void persistProviders(activeTab.value)
}

const providerStatsMap = reactive<Record<ProviderTab, Record<string, ProviderDailyStat>>>({
  claude: {},
  'openai-responses': {},
  'openai-chat': {},
  others: {},
})
const providerStatsLoading = reactive<Record<ProviderTab, boolean>>({
  claude: false,
  'openai-responses': false,
  'openai-chat': false,
  others: false,
})
const providerStatsLoaded = reactive<Record<ProviderTab, boolean>>({
  claude: false,
  'openai-responses': false,
  'openai-chat': false,
  others: false,
})
let providerStatsTimer: number | undefined
const showHomeTitle = ref(true)
const appVersion = ref('')

// 自定义 CLI 工具状态
const customCliTools = ref<CustomCliTool[]>([])
const selectedToolId = ref<string | null>(null)
const customCliProxyStates = reactive<Record<string, boolean>>({})  // toolId -> enabled

// 当前选中的 CLI 工具（计算属性）
const selectedCustomCliTool = computed(() => {
  if (!selectedToolId.value) return null
  return customCliTools.value.find(t => t.id === selectedToolId.value) || null
})

// 配置文件保存成功后的回调
const onConfigFileSaved = () => {
  // 配置文件保存成功，可以在这里添加额外逻辑（如刷新状态）
  console.log('[CustomCliConfigEditor] Config file saved')
}

// 可用性旧结果（已废弃，保留用于兼容）
const connectivityResultsMap = reactive<Record<ProviderTab, Record<number, ConnectivityResult>>>({
  claude: {},
  'openai-responses': {},
  'openai-chat': {},
  others: {},
})

// 可用性监控状态（新）
const availabilityResultsMap = reactive<Record<ProviderTab, Record<number, ProviderTimeline>>>({
  claude: {},
  'openai-responses': {},
  'openai-chat': {},
  others: {},
})

// 最后使用的供应商（用于高亮显示）
// @author sm
interface LastUsedProvider {
  platform: string
  pool_id?: string
  provider_name: string
  updated_at: number
}
const lastUsedProviders = reactive<Record<string, LastUsedProvider | null>>({
  claude: null,
  'openai-responses': null,
  'openai-chat': null,
  others: null,
})
// 高亮闪烁的供应商名称
const highlightedProvider = ref<string | null>(null)
let highlightTimer: number | undefined

const formatMetric = (value: number) => value.toLocaleString()

/**
 * 格式化 token 数值，支持 k/M/B 单位换算
 * @author sm
 */
const formatTokenNumber = (value: number) => {
  if (value >= 1_000_000_000) {
    return `${(value / 1_000_000_000).toFixed(2)}B`
  }
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(2)}M`
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(2)}k`
  }
  return value.toLocaleString()
}

const clamp = (value: number, min: number, max: number) => {
  if (max <= min) return min
  return Math.min(Math.max(value, min), max)
}

const loadAppSettings = async () => {
  try {
    const data: AppSettings = await fetchAppSettings()
    showHomeTitle.value = data?.show_home_title ?? true
  } catch (error) {
    console.error('failed to load app settings', error)
    showHomeTitle.value = true
    // 加载应用设置失败时提示用户
    showToast(t('components.main.errors.loadAppSettingsFailed'), 'warning')
  }
}

const loadAppVersion = async () => {
  try {
    const version = await fetchCurrentVersion()
    appVersion.value = version || ''
  } catch (error) {
    console.error('failed to load app version', error)
  }
}

const handleAppSettingsUpdated = () => {
  void loadAppSettings()
}

const normalizeProviderKey = (value: string) => value?.trim().toLowerCase() ?? ''

const normalizeVersion = (value: string) => value.replace(/^v/i, '').trim()

const compareVersions = (current: string, remote: string) => {
  const curParts = normalizeVersion(current).split('.').map((part) => parseInt(part, 10) || 0)
  const remoteParts = normalizeVersion(remote).split('.').map((part) => parseInt(part, 10) || 0)
  const maxLen = Math.max(curParts.length, remoteParts.length)
  for (let i = 0; i < maxLen; i++) {
    const cur = curParts[i] ?? 0
    const rem = remoteParts[i] ?? 0
    if (cur === rem) continue
    return cur < rem ? -1 : 1
  }
  return 0
}

const tabs = [
  { id: 'claude', label: 'Claude Code' },
  { id: 'openai-responses', label: 'OpenAI Responses' },
  { id: 'openai-chat', label: 'OpenAI Chat' },
  { id: 'others', label: '其他' },
] as const
type ProviderTab = (typeof tabs)[number]['id']
const providerTabIds = tabs.map((tab) => tab.id) as ProviderTab[]
const defaultTabOrder = [...providerTabIds]
const tabOrderStorageKey = 'code-switch-main-tab-order'
const tabById = Object.fromEntries(tabs.map((tab) => [tab.id, tab])) as Record<ProviderTab, (typeof tabs)[number]>

const normalizeTabOrder = (value: unknown): ProviderTab[] => {
  if (!Array.isArray(value)) return [...defaultTabOrder]
  const seen = new Set<ProviderTab>()
  const normalized = value.filter((id): id is ProviderTab => {
    if (!providerTabIds.includes(id as ProviderTab) || seen.has(id as ProviderTab)) return false
    seen.add(id as ProviderTab)
    return true
  })
  defaultTabOrder.forEach((id) => {
    if (!seen.has(id)) normalized.push(id)
  })
  return normalized
}

const loadTabOrder = (): ProviderTab[] => {
  try {
    const raw = window.localStorage.getItem(tabOrderStorageKey)
    return normalizeTabOrder(raw ? JSON.parse(raw) : null)
  } catch {
    return [...defaultTabOrder]
  }
}

const saveTabOrder = (order: ProviderTab[]) => {
  try {
    window.localStorage.setItem(tabOrderStorageKey, JSON.stringify(order))
  } catch (error) {
    console.error('Failed to save tab order', error)
  }
}

const cards = reactive<Record<ProviderTab, AutomationCard[]>>({
  claude: [],
  'openai-responses': [],
  'openai-chat': [],
  others: [],
})
const draggingId = ref<number | null>(null)
const draggingTab = ref<ProviderTab | null>(null)
const tabOrder = ref<ProviderTab[]>(loadTabOrder())
const orderedTabs = computed(() => tabOrder.value.map((id) => tabById[id]))
const providerCacheStorageKey = 'code-switch-provider-cache-v1'

type ProviderCache = Partial<Record<ProviderTab, AutomationCard[]>>

const loadProviderCache = (): ProviderCache => {
  try {
    const raw = window.localStorage.getItem(providerCacheStorageKey)
    if (!raw) return {}
    const parsed = JSON.parse(raw)
    return parsed && typeof parsed === 'object' ? parsed as ProviderCache : {}
  } catch {
    return {}
  }
}

const saveProviderCache = (cache: ProviderCache) => {
  try {
    window.localStorage.setItem(providerCacheStorageKey, JSON.stringify(cache))
  } catch (error) {
    console.error('Failed to save provider cache', error)
  }
}

const cacheProviders = (tabId: ProviderTab, providers: AutomationCard[]) => {
  if (tabId === 'others') return
  const cache = loadProviderCache()
  cache[tabId] = serializeProviders(providers)
  saveProviderCache(cache)
}

const loadInitialProviders = (tabId: Exclude<ProviderTab, 'others'>): AutomationCard[] => {
  const cached = loadProviderCache()[tabId]
  if (Array.isArray(cached)) {
    return createAutomationCards(cached)
  }
  return []
}

const serializeProviders = (providers: AutomationCard[]) =>
  providers.map((provider) => ({
    ...provider,
    // 确保可用性配置正确序列化
    availabilityMonitorEnabled: !!provider.availabilityMonitorEnabled,
    availabilityConfig: provider.availabilityConfig
      ? {
          testModel: provider.availabilityConfig.testModel || '',
          testEndpoint: provider.availabilityConfig.testEndpoint || '',
          timeout: provider.availabilityConfig.timeout || 15000,
        }
      : undefined,
    // 清除旧可用性字段（避免再次写入配置文件）
    connectivityCheck: false,
    connectivityTestModel: '',
    connectivityTestEndpoint: '',
    // 保留认证方式配置（已从废弃字段升级为活跃字段）
    connectivityAuthType: provider.connectivityAuthType || '',
  }))

cards.claude.splice(0, cards.claude.length, ...loadInitialProviders('claude'))
cards['openai-responses'].splice(0, cards['openai-responses'].length, ...loadInitialProviders('openai-responses'))
cards['openai-chat'].splice(0, cards['openai-chat'].length, ...loadInitialProviders('openai-chat'))

// 生成 custom CLI 工具的 provider kind（后端需要 "custom:{toolId}" 格式）
const getCustomProviderKind = (toolId: string): string => `custom:${toolId}`

const persistProviders = async (tabId: ProviderTab): Promise<{ ok: boolean; error?: string }> => {
  try {
    if (tabId === 'others') {
      // 'others' Tab 需要使用 "custom:{toolId}" 格式
      if (!selectedToolId.value) {
        showToast(t('components.main.customCli.selectToolFirst'), 'error')
        return { ok: false, error: t('components.main.customCli.selectToolFirst') }
      }
      await SaveProviders(getCustomProviderKind(selectedToolId.value), serializeProviders(cards.others))
    } else {
      await SaveProviders(tabId, serializeProviders(cards[tabId]))
    }
    cacheProviders(tabId, cards[tabId])
    return { ok: true }
  } catch (error) {
    console.error('Failed to save providers', error)
    const errorMsg = extractErrorMessage(error)
    showToast(t('components.main.form.saveFailed') + ': ' + errorMsg, 'error')
    return { ok: false, error: errorMsg }
  }
}

const replaceProviders = (tabId: ProviderTab, data: AutomationCard[]) => {
  cards[tabId].splice(0, cards[tabId].length, ...createAutomationCards(data))
}

const loadProvidersFromDisk = async () => {
  for (const tab of providerTabIds) {
    try {
      if (tab === 'others') {
        // 'others' Tab: 先加载自定义 CLI 工具列表，再加载每个工具的 providers
        await loadCustomCliTools()
      } else {
        const saved = await LoadProviders(tab)
        if (Array.isArray(saved)) {
          replaceProviders(tab, saved as AutomationCard[])
          sortProvidersByLevel(cards[tab])  // 初始排序：启用优先，Level 升序
          cacheProviders(tab, cards[tab])
        } else {
          await persistProviders(tab)
        }
      }
    } catch (error) {
      console.error('Failed to load providers', error)
      // 加载供应商失败时提示用户
      showToast(t('components.main.errors.loadProvidersFailed', { tab }), 'error')
    }
  }
}

// 加载自定义 CLI 工具列表
const loadCustomCliTools = async () => {
  try {
    const tools = await listCustomCliTools()
    customCliTools.value = tools

    // 自动选择第一个工具（如果有）
    if (tools.length > 0 && !selectedToolId.value) {
      selectedToolId.value = tools[0].id
    }

    // 为每个工具加载代理状态
    for (const tool of tools) {
      try {
        const status = await getCustomCliProxyStatus(tool.id)
        customCliProxyStates[tool.id] = Boolean(status?.enabled)
      } catch (err) {
        customCliProxyStates[tool.id] = false
      }
    }

    // 如果当前选中了工具，更新 'others' Tab 的代理状态并加载 providers
    if (selectedToolId.value) {
      proxyStates.others = customCliProxyStates[selectedToolId.value] ?? false
      await loadCustomCliProviders(selectedToolId.value)
    }
  } catch (error) {
    console.error('Failed to load custom CLI tools', error)
    customCliTools.value = []
  }
}

// 加载特定 CLI 工具的 providers
const loadCustomCliProviders = async (toolId: string) => {
  if (!toolId) return
  try {
    const kind = getCustomProviderKind(toolId)
    const saved = await LoadProviders(kind)
    if (Array.isArray(saved)) {
      cards.others.splice(0, cards.others.length, ...createAutomationCards(saved as AutomationCard[]))
      sortProvidersByLevel(cards.others)
    } else {
      // 如果没有保存的数据，清空列表
      cards.others.splice(0, cards.others.length)
    }
  } catch (error) {
    console.error(`Failed to load providers for tool ${toolId}`, error)
    cards.others.splice(0, cards.others.length)
  }
}

const refreshProxyState = async (tab: ProviderTab) => {
  try {
    if (tab === 'others') {
      // 'others' Tab 的代理状态依赖于选中的 CLI 工具
      if (selectedToolId.value) {
        const status = await getCustomCliProxyStatus(selectedToolId.value)
        customCliProxyStates[selectedToolId.value] = Boolean(status?.enabled)
        proxyStates[tab] = Boolean(status?.enabled)
      } else {
        proxyStates[tab] = false
      }
    } else {
      const status = await fetchProxyStatus(tab as 'claude' | 'openai-responses' | 'openai-chat')
      proxyStates[tab] = Boolean(status?.enabled)
    }
  } catch (error) {
    console.error(`Failed to fetch proxy status for ${tab}`, error)
    proxyStates[tab] = false
  }
}

const onProxyToggle = async () => {
  const tab = activeTab.value
  if (proxyBusy[tab]) return
  proxyBusy[tab] = true
  const nextState = !proxyStates[tab]
  try {
    if (tab === 'others') {
      // 'others' Tab 需要选中工具才能切换代理
      if (!selectedToolId.value) {
        showToast(t('components.main.customCli.selectToolFirst'), 'error')
        return
      }
      if (nextState) {
        await enableCustomCliProxy(selectedToolId.value)
      } else {
        await disableCustomCliProxy(selectedToolId.value)
      }
      customCliProxyStates[selectedToolId.value] = nextState
    } else {
      if (nextState) {
        await enableProxy(tab as 'claude' | 'openai-responses' | 'openai-chat')
      } else {
        await disableProxy(tab as 'claude' | 'openai-responses' | 'openai-chat')
      }
    }
    proxyStates[tab] = nextState
  } catch (error) {
    console.error(`Failed to toggle proxy for ${tab}`, error)
  } finally {
    proxyBusy[tab] = false
  }
}

const loadProviderStats = async (tab: ProviderTab) => {
  // 'others' Tab 暂不加载统计数据（自定义 CLI 工具统计需要后续实现）
  if (tab === 'others') {
    providerStatsLoaded[tab] = true
    return
  }

  providerStatsLoading[tab] = true
  try {
    const stats = await fetchProviderDailyStats(tab as 'claude' | 'openai-responses' | 'openai-chat')
    const mapped: Record<string, ProviderDailyStat> = {}
    ;(stats ?? []).forEach((stat) => {
      mapped[normalizeProviderKey(stat.provider)] = stat
    })
    providerStatsMap[tab] = mapped
    providerStatsLoaded[tab] = true
  } catch (error) {
    console.error(`Failed to load provider stats for ${tab}`, error)
    if (!providerStatsLoaded[tab]) {
      providerStatsLoaded[tab] = true
    }
  } finally {
    providerStatsLoading[tab] = false
  }
}

// 加载旧可用性测试结果（已废弃，保留兼容）
const loadConnectivityResults = async (tab: ProviderTab) => {
  // 'others' Tab 暂不加载旧可用性结果
  if (tab === 'others') {
    return
  }

  try {
    const results = await getConnectivityResults(tab)
    const map: Record<number, ConnectivityResult> = {}
    results.forEach((result) => {
      map[result.providerId] = result
    })
    connectivityResultsMap[tab] = map
  } catch (err) {
    console.error(`加载 ${tab} 可用性结果失败:`, err)
  }
}

// 加载可用性监控结果（新）
const loadAvailabilityResults = async () => {
  try {
    const allResults = await getLatestResults()

    // 转换为按平台和 ID 索引的格式
    for (const platform of Object.keys(allResults)) {
      const timelines = allResults[platform] || []
      const map: Record<number, ProviderTimeline> = {}
      timelines.forEach((timeline) => {
        map[timeline.providerId] = timeline
      })
      availabilityResultsMap[platform as ProviderTab] = map
    }
  } catch (err) {
    console.error('加载可用性监控结果失败:', err)
  }
}

// 获取 provider 旧可用性状态（已废弃）
const getProviderConnectivityResult = (providerId: number): ConnectivityResult | null => {
  return connectivityResultsMap[activeTab.value][providerId] || null
}

// 获取 provider 可用性状态（新）
const getProviderAvailabilityResult = (providerId: number): ProviderTimeline | null => {
  return availabilityResultsMap[activeTab.value][providerId] || null
}

// 获取可用性状态指示器样式
const getConnectivityIndicatorClass = (providerId: number): string => {
  const result = getProviderAvailabilityResult(providerId)
  if (!result || !result.latest) return 'connectivity-gray'

  // 根据可用性监控状态返回样式
  switch (result.latest.status) {
    case HealthStatus.OPERATIONAL:
      return 'connectivity-green'
    case HealthStatus.DEGRADED:
      return 'connectivity-yellow'
    case HealthStatus.FAILED:
    case HealthStatus.VALIDATION_ERROR:
      return 'connectivity-red'
    default:
      return 'connectivity-gray'
  }
}

// 获取可用性状态提示文本
const getConnectivityTooltip = (providerId: number): string => {
  const result = getProviderAvailabilityResult(providerId)
  if (!result || !result.latest) return t('components.main.connectivity.noData')

  let statusText = ''
  switch (result.latest.status) {
    case HealthStatus.OPERATIONAL:
      statusText = t('components.main.connectivity.available')
      break
    case HealthStatus.DEGRADED:
      statusText = t('components.main.connectivity.degraded')
      break
    case HealthStatus.FAILED:
    case HealthStatus.VALIDATION_ERROR:
      statusText = t('components.main.connectivity.unavailable')
      break
    default:
      statusText = t('components.main.connectivity.noData')
  }

  const latencyText = result.latest.latencyMs > 0 ? ` (${result.latest.latencyMs}ms)` : ''
  const uptimeText = result.uptime > 0 ? ` - ${result.uptime.toFixed(1)}%` : ''
  return statusText + latencyText + uptimeText
}

// 刷新所有数据
const refreshing = ref(false)
const relayKeys = ref<RelayKeyItem[]>([])

const loadRelayKeys = async () => {
  try {
    relayKeys.value = await ListRelayKeys()
  } catch (error) {
    console.error('Failed to load relay keys', error)
  }
}
const refreshAllData = async () => {
  if (refreshing.value) return
  refreshing.value = true
  try {
    await Promise.all([
      loadProvidersFromDisk(),
      ...providerTabIds.map(refreshProxyState),
      ...providerTabIds.map((tab) => refreshDirectAppliedStatus(tab)),
      ...providerTabIds.map((tab) => loadProviderStats(tab)),
      loadAvailabilityResults(), // 同步刷新可用性监控状态（改用新服务）
      loadRelayKeys(),
    ])
  } catch (error) {
    console.error('Failed to refresh data', error)
  } finally {
    refreshing.value = false
  }
}

type ProviderStatDisplay =
  | { state: 'loading' | 'empty'; message: string }
  | {
	      state: 'ready'
	      requests: string
	      tokens: string
	      successRateLabel: string
	      successRateClass: string
    }

const SUCCESS_RATE_THRESHOLDS = {
  healthy: 0.95,
  warning: 0.8,
} as const

const formatSuccessRateLabel = (value: number) => {
  const percent = clamp(value, 0, 1) * 100
  const decimals = percent >= 99.5 || percent === 0 ? 0 : 1
  return `${t('components.main.providers.successRate')}: ${percent.toFixed(decimals)}%`
}

const successRateClassName = (value: number) => {
  const rate = clamp(value, 0, 1)
  if (rate >= SUCCESS_RATE_THRESHOLDS.healthy) {
    return 'success-good'
  }
  if (rate >= SUCCESS_RATE_THRESHOLDS.warning) {
    return 'success-warn'
  }
  return 'success-bad'
}

const providerStatDisplay = (providerName: string): ProviderStatDisplay => {
  const tab = activeTab.value
  if (!providerStatsLoaded[tab]) {
    return { state: 'loading', message: t('components.main.providers.loading') }
  }
  const stat = providerStatsMap[tab]?.[normalizeProviderKey(providerName)]
  if (!stat) {
    return { state: 'empty', message: t('components.main.providers.noData') }
  }
  const totalTokens = stat.input_tokens + stat.output_tokens
  const successRateValue = Number.isFinite(stat.success_rate) ? clamp(stat.success_rate, 0, 1) : null
  const successRateLabel = successRateValue !== null ? formatSuccessRateLabel(successRateValue) : ''
  const successRateClass = successRateValue !== null ? successRateClassName(successRateValue) : ''
  return {
	    state: 'ready',
	    requests: `${t('components.main.providers.requests')}: ${formatMetric(stat.total_requests)}`,
	    tokens: `${t('components.main.providers.tokens')}: ${formatTokenNumber(totalTokens)}`,
	    successRateLabel,
    successRateClass,
  }
}

const normalizeUrlWithScheme = (value: string) => {
  if (!value) return ''
  try {
    const url = new URL(value)
    return url.toString()
  } catch {
    return `https://${value}`
  }
}

const openOfficialSite = (site: string) => {
  const target = normalizeUrlWithScheme(site)
  if (!target) return
  Browser.OpenURL(target).catch(() => {
    console.error('failed to open link', target)
  })
}

const formatOfficialSite = (site: string) => {
  if (!site) return ''
  try {
    const url = new URL(normalizeUrlWithScheme(site))
    return url.hostname.replace(/^www\./, '')
  } catch {
    return site
  }
}

const startProviderStatsTimer = () => {
  stopProviderStatsTimer()
  providerStatsTimer = window.setInterval(() => {
    providerTabIds.forEach((tab) => {
      void loadProviderStats(tab)
    })
    void loadAvailabilityResults() // 同步刷新可用性监控状态（改用新服务）
  }, 60_000)
}

const stopProviderStatsTimer = () => {
  if (providerStatsTimer) {
    clearInterval(providerStatsTimer)
    providerStatsTimer = undefined
  }
}

// 加载最后使用的供应商
// @author sm
const loadLastUsedProviders = async () => {
  try {
    const result = await Call.ByName('codeswitch/services.ProviderRelayService.GetAllLastUsedProviders')
    if (result) {
      Object.keys(lastUsedProviders).forEach(platform => {
        lastUsedProviders[platform] = null
      })

      if (Array.isArray(result)) {
        result.forEach((item: LastUsedProvider) => {
          const platform = item?.platform
          if (!platform || !(platform in lastUsedProviders)) return

          const current = lastUsedProviders[platform]
          if (!current || (item.updated_at || 0) >= (current.updated_at || 0)) {
            lastUsedProviders[platform] = item
          }
        })
      } else {
        Object.keys(result).forEach(platform => {
          if (platform in lastUsedProviders && result[platform]) {
            lastUsedProviders[platform] = result[platform]
          }
        })
      }
    }
  } catch (err) {
    console.error('加载最后使用的供应商失败:', err)
  }
}

// 切换到指定平台的 Tab 并高亮供应商
// @author sm
const switchToTabAndHighlight = (platform: string, providerName: string) => {
  // 切换到对应的 Tab
  if (providerTabIds.includes(platform as ProviderTab) && selectedTab.value !== platform) {
    selectedTab.value = platform as ProviderTab
  }

  // 更新最后使用的供应商
  lastUsedProviders[platform] = {
    platform,
    provider_name: providerName,
    updated_at: Date.now(),
  }

  // 高亮闪烁供应商卡片
  highlightedProvider.value = providerName

  // 清除之前的高亮计时器
  if (highlightTimer) {
    clearTimeout(highlightTimer)
  }

  // 3 秒后取消高亮
  highlightTimer = window.setTimeout(() => {
    highlightedProvider.value = null
  }, 3000)

}

// 处理供应商切换事件
// @author sm
const handleProviderSwitched = (event: { data: { platform: string; toProvider: string } }) => {
  const { platform, toProvider } = event.data
  console.log('[Event] provider:switched', platform, toProvider)
  switchToTabAndHighlight(platform, toProvider)
}

// 判断供应商是否是最后使用的
// @author sm
const isLastUsedProvider = (providerName: string): boolean => {
  const lastUsed = lastUsedProviders[activeTab.value]
  return lastUsed?.provider_name === providerName
}

// 滚动到指定卡片
// @author sm
const scrollToCard = (el: HTMLElement | null) => {
  if (el) {
    el.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }
}

// 事件取消订阅函数
let unsubscribeSwitched: (() => void) | undefined

onMounted(async () => {
  await loadProvidersFromDisk()
  await Promise.all(providerTabIds.map(refreshProxyState))
  await Promise.all(providerTabIds.map((tab) => refreshDirectAppliedStatus(tab)))
  await Promise.all(providerTabIds.map((tab) => loadProviderStats(tab)))
  await loadRelayKeys()
  await loadAppSettings()
  await loadAppVersion()
  startProviderStatsTimer()

  // 加载初始可用性监控结果（改用新服务）
  await loadAvailabilityResults()

  window.addEventListener('app-settings-updated', handleAppSettingsUpdated)

  // 监听可用性页面的 Provider 更新事件
  const handleProvidersUpdated = () => {
    void loadProvidersFromDisk()
  }
  window.addEventListener('providers-updated', handleProvidersUpdated)
  ;(window as any).__handleProvidersUpdated = handleProvidersUpdated

  window.addEventListener(RELAY_KEYS_UPDATED_EVENT, loadRelayKeys)

  // 加载最后使用的供应商
  await loadLastUsedProviders()

  // 监听供应商切换事件
  unsubscribeSwitched = Events.On('provider:switched', handleProviderSwitched as Events.Callback)
})

onUnmounted(() => {
  stopProviderStatsTimer()
  window.removeEventListener('app-settings-updated', handleAppSettingsUpdated)

  if ((window as any).__handleProvidersUpdated) {
    window.removeEventListener('providers-updated', (window as any).__handleProvidersUpdated)
  }

  // 清理高亮计时器
  if (highlightTimer) {
    clearTimeout(highlightTimer)
  }

  window.removeEventListener(RELAY_KEYS_UPDATED_EVENT, loadRelayKeys)

  // 取消事件订阅
  if (unsubscribeSwitched) {
    unsubscribeSwitched()
  }
})

const firstOrderedTab = (): ProviderTab => tabOrder.value[0] ?? defaultTabOrder[0]
const selectedTab = ref<ProviderTab>(firstOrderedTab())
const activeTab = computed<ProviderTab>(() => selectedTab.value)
const activeCards = computed(() => cards[activeTab.value] ?? [])

// 可用性测试模型选项（根据平台）
const connectivityTestModelOptions = computed(() => {
  const options: Record<string, string[]> = {
    claude: ['claude-haiku-4-5-20251001', 'claude-sonnet-4-5-20250929'],
    'openai-responses': ['gpt-5.1', 'gpt-5.1-codex'],
    'openai-chat': ['gpt-5.1', 'gpt-5.1-mini'],
  }
  return options[modalState.tabId] || options.claude
})

// 可用性测试端点选项
const connectivityEndpointOptions = [
  { value: '/v1/messages', label: '/v1/messages (Anthropic)' },
  { value: '/chat/completions', label: '/chat/completions (OpenAI Chat)' },
  { value: '/responses', label: '/responses (Codex)' },
]

// 可用性测试状态
const testingConnectivity = ref(false)
const connectivityTestResult = ref<{ success: boolean; message: string } | null>(null)
const testingProtocolEndpoint = ref(false)
const testingModelsEndpoint = ref(false)
const defaultTestMessage = '这是一条测试消息，请回复"yes"'
const defaultTestModel = 'gpt-5.5'
const providerTestMessage = ref(defaultTestMessage)
type ProtocolEndpointTestResult = {
  success: boolean
  message: string
  rawResult: string
  httpResponse: string
  httpCode?: number
}
const protocolEndpointTestResult = ref<ProtocolEndpointTestResult | null>(null)
const modelsEndpointTestResult = ref<{ success: boolean; message: string } | null>(null)
const providerTestModel = ref('')
const providerModelOptions = ref<string[]>([])
const providerModelsLoading = ref(false)
const providerModelDropdownOpen = ref(false)
const shakeFields = reactive({
  apiUrl: false,
  apiKey: false,
  protocolEndpoint: false,
  modelsEndpoint: false,
  testModel: false,
})

// 获取平台默认端点
const getDefaultEndpoint = (platform: string) => {
  const defaults: Record<string, string> = {
    claude: '/v1/messages',
    'openai-responses': '/responses',
    'openai-chat': '/chat/completions',
  }
  return defaults[platform] || '/chat/completions'
}

const getDefaultProtocolEndpoint = (platform: string) => {
  const defaults: Record<string, string> = {
    claude: '/messages',
    'openai-responses': '/responses',
    'openai-chat': '/chat/completions',
  }
  return defaults[platform] || '/chat/completions'
}

const currentProtocolEndpoint = () => {
  if (modalState.tabId === 'claude') {
    return modalState.form.apiEndpoint || ''
  }
  if (modalState.tabId === 'openai-responses') {
    return modalState.form.responsesEndpoint || ''
  }
  return modalState.form.chatEndpoint || ''
}

const triggerFieldShake = (field: keyof typeof shakeFields) => {
  shakeFields[field] = false
  window.setTimeout(() => {
    shakeFields[field] = true
    window.setTimeout(() => {
      shakeFields[field] = false
    }, 450)
  }, 0)
}

const clearEndpointTestErrors = () => {
  modalState.errors.apiUrl = ''
  modalState.errors.apiKey = ''
  modalState.errors.protocolEndpoint = ''
  modalState.errors.modelsEndpoint = ''
  modalState.errors.testModel = ''
}

const combinedProviderModelOptions = computed(() => {
  const models = new Set<string>()
  providerModelOptions.value.forEach((model) => models.add(model))
  Object.keys(modalState.form.supportedModels || {}).forEach((model) => {
    if (!model.includes('*')) models.add(model)
  })
  Object.entries(modalState.form.modelMapping || {}).forEach(([source, target]) => {
    if (source && !source.includes('*')) models.add(source)
    if (target && !target.includes('*')) models.add(target)
  })
  return Array.from(models).sort((a, b) => a.localeCompare(b))
})

const loadProviderModelsForForm = async () => {
  const apiUrl = ensureTestBaseURL()
  if (!apiUrl) return
  providerModelsLoading.value = true
  try {
    const result = await Call.ByName(
      'codeswitch/services.ConnectivityTestService.ListModelsEndpointManual',
      apiUrl,
      modalState.form.apiKey.trim(),
      modalState.form.modelsEndpoint || '/v1/models',
      resolveEffectiveAuthType(),
      modalState.tabId
    )
    providerModelOptions.value = result.models || []
    if (!providerTestModel.value) {
      providerTestModel.value = defaultTestModel
    }
  } catch (error) {
    console.warn('Failed to load provider models for form:', error)
    providerModelOptions.value = []
  } finally {
    providerModelsLoading.value = false
  }
}

const toggleProviderModelDropdown = async () => {
  providerModelDropdownOpen.value = !providerModelDropdownOpen.value
  if (providerModelDropdownOpen.value && !providerModelOptions.value.length) {
    await loadProviderModelsForForm()
  }
}

const selectProviderTestModel = (model: string) => {
  providerTestModel.value = model
  providerModelDropdownOpen.value = false
}

const ensureTestBaseURL = () => {
  const apiUrl = modalState.form.apiUrl.trim()
  if (!apiUrl) {
    modalState.errors.apiUrl = t('components.main.form.errors.required')
    triggerFieldShake('apiUrl')
    return ''
  }
  try {
    const parsed = new URL(apiUrl)
    if (!/^https?:/.test(parsed.protocol)) throw new Error('protocol')
  } catch {
    modalState.errors.apiUrl = t('components.main.form.errors.invalidUrl')
    triggerFieldShake('apiUrl')
    return ''
  }
  modalState.errors.apiUrl = ''
  return apiUrl
}

// 获取平台默认认证方式（默认 Bearer，与 v2.2.x 保持一致）
const getDefaultAuthType = (_platform: string) => 'bearer'

const handleTestProtocolEndpoint = async () => {
  clearEndpointTestErrors()
  protocolEndpointTestResult.value = null
  const apiUrl = ensureTestBaseURL()
  const apiKey = modalState.form.apiKey.trim()
  const endpoint = currentProtocolEndpoint()
  const testMessage = providerTestMessage.value.trim() || defaultTestMessage
  if (!apiUrl) return
  if (!apiKey) {
    modalState.errors.apiKey = t('components.main.form.errors.required')
    triggerFieldShake('apiKey')
    return
  }
  if (!endpoint.trim()) {
    modalState.errors.protocolEndpoint = t('components.main.form.errors.required')
    triggerFieldShake('protocolEndpoint')
    return
  }
  if (!providerTestModel.value.trim()) {
    modalState.errors.testModel = t('components.main.form.errors.required')
    triggerFieldShake('testModel')
    return
  }

  testingProtocolEndpoint.value = true
  try {
    const result = await Call.ByName(
      'codeswitch/services.ConnectivityTestService.TestProviderManualWithMessage',
      modalState.tabId,
      apiUrl,
      apiKey,
      providerTestModel.value.trim(),
      endpoint,
      resolveEffectiveAuthType(),
      testMessage
    )
    protocolEndpointTestResult.value = {
      success: !!result.success,
      message: result.success
        ? t('components.main.form.connectivity.serviceSuccess', { latency: result.latencyMs, code: result.httpCode || 200 })
        : result.message || t('components.main.form.connectivity.failed'),
      rawResult: result.rawResult || '',
      httpResponse: result.httpResponse || '',
      httpCode: result.httpCode || 0,
    }
  } catch (error) {
    protocolEndpointTestResult.value = {
      success: false,
      message: t('components.main.form.connectivity.error', { error: extractErrorMessage(error) }),
      rawResult: '',
      httpResponse: '',
    }
  } finally {
    testingProtocolEndpoint.value = false
  }
}

const handleTestModelsEndpoint = async () => {
  clearEndpointTestErrors()
  modelsEndpointTestResult.value = null
  const apiUrl = ensureTestBaseURL()
  if (!apiUrl) return

  testingModelsEndpoint.value = true
  try {
    const result = await Call.ByName(
      'codeswitch/services.ConnectivityTestService.ListModelsEndpointManual',
      apiUrl,
      modalState.form.apiKey.trim(),
      modalState.form.modelsEndpoint || '/v1/models',
      resolveEffectiveAuthType(),
      modalState.tabId
    )
    providerModelOptions.value = result.models || []
    if (!providerTestModel.value && providerModelOptions.value.length) {
      providerTestModel.value = providerModelOptions.value[0]
    }
    modelsEndpointTestResult.value = {
      success: true,
      message: t('components.main.form.connectivity.modelsSuccess', { count: providerModelOptions.value.length }),
    }
  } catch (error) {
    modelsEndpointTestResult.value = {
      success: false,
      message: t('components.main.form.connectivity.error', { error: extractErrorMessage(error) }),
    }
  } finally {
    testingModelsEndpoint.value = false
  }
}

// 手动测试可用性
const handleTestConnectivity = async () => {
  testingConnectivity.value = true
  connectivityTestResult.value = null

  try {
    const platform = modalState.tabId
    const result = await Call.ByName(
      'codeswitch/services.ConnectivityTestService.TestProviderManual',
      platform,
      modalState.form.apiUrl,
      modalState.form.apiKey,
      modalState.form.connectivityTestModel || '',
      modalState.form.connectivityTestEndpoint || getDefaultEndpoint(platform),
      resolveEffectiveAuthType()
    )

    connectivityTestResult.value = {
      success: result.success,
      message: result.success
        ? t('components.main.form.connectivity.success', { latency: result.latencyMs })
        : result.message || t('components.main.form.connectivity.failed')
    }
  } catch (error) {
    connectivityTestResult.value = {
      success: false,
      message: t('components.main.form.connectivity.error', { error: extractErrorMessage(error) })
    }
  } finally {
    testingConnectivity.value = false
  }
}

const currentProxyLabel = computed(() => {
  const tab = activeTab.value
  if (tab === 'claude') {
    return t('components.main.relayToggle.hostClaude')
  } else if (tab === 'openai-responses') {
    return t('components.main.relayToggle.hostCodex')
  } else if (tab === 'others') {
    // 显示选中的工具名称
    const tool = customCliTools.value.find(t => t.id === selectedToolId.value)
    return tool?.name || t('components.main.relayToggle.hostOthers')
  }
  return t('components.main.relayToggle.hostCodex')
})
const activeProxyState = computed(() => proxyStates[activeTab.value])
const activeProxyBusy = computed(() => proxyBusy[activeTab.value])

const goToLogs = () => {
  router.push('/logs')
}

const goToSettings = () => {
  router.push('/settings')
}

const toggleTheme = () => {
  const next = resolvedTheme.value === 'dark' ? 'light' : 'dark'
  themeMode.value = next
  setTheme(next)
}

const syncDefaultTestEndpoint = (
  platform: string,
  previousPlatform: string
) => {
  const availabilityConfig = modalState.form.availabilityConfig
  if (!availabilityConfig) return

  const previousDefault = getDefaultEndpoint(previousPlatform)
  const nextDefault = getDefaultEndpoint(platform)
  const currentValue = availabilityConfig.testEndpoint || ''

  if (!currentValue || currentValue === previousDefault) {
    availabilityConfig.testEndpoint = nextDefault
  }
}

type VendorForm = {
  name: string
  apiUrl: string
  apiKey: string
  officialSite: string
  icon: string
  enabled: boolean
  supportedModels?: Record<string, boolean>
  modelMapping?: Record<string, string>
  level?: number
  apiEndpoint?: string
  responsesEndpoint?: string
  chatEndpoint?: string
  modelsEndpoint?: string
  // === 可用性监控配置（新） ===
  availabilityMonitorEnabled?: boolean
  availabilityConfig?: {
    testModel?: string
    testEndpoint?: string
    timeout?: number
  }
  // === 旧可用性字段（已废弃） ===
  /** @deprecated */
  connectivityCheck?: boolean
  /** @deprecated */
  connectivityTestModel?: string
  /** @deprecated */
  connectivityTestEndpoint?: string
  /** @deprecated */
  connectivityAuthType?: string
}

const failedFaviconSites = reactive<Record<string, boolean>>({})

const normalizeFaviconSite = (site?: string) => site?.trim() ?? ''

const providerFaviconUrl = (site?: string) => {
  const normalized = normalizeFaviconSite(site)
  if (!normalized || failedFaviconSites[normalized]) return ''
  return `/provider-favicon?url=${encodeURIComponent(normalized)}`
}

const markFaviconFailed = (site?: string) => {
  const normalized = normalizeFaviconSite(site)
  if (normalized) {
    failedFaviconSites[normalized] = true
  }
}

const defaultFormValues = (platform?: string): VendorForm => ({
  name: '',
  apiUrl: '',
  apiKey: '',
  officialSite: '',
  icon: '',
  enabled: true,
  supportedModels: {},
  modelMapping: {},
  apiEndpoint: platform === 'claude' ? getDefaultProtocolEndpoint('claude') : '',
  responsesEndpoint: platform === 'openai-responses' ? getDefaultProtocolEndpoint('openai-responses') : '',
  chatEndpoint: platform === 'openai-chat' ? getDefaultProtocolEndpoint('openai-chat') : '',
  modelsEndpoint: '',
  // 可用性监控配置（新）
  availabilityMonitorEnabled: false,
  availabilityConfig: {
    testModel: '',
    testEndpoint: getDefaultEndpoint(platform || 'claude'),
    timeout: 15000,
  },
  // 旧可用性字段（已废弃，置空）
  connectivityCheck: false,
  connectivityTestModel: '',
  connectivityTestEndpoint: '',
  connectivityAuthType: '',
})

// Level 描述文本映射（1-10）
const getLevelDescription = (level: number) => {
  const descriptions: Record<number, string> = {
    1: t('components.main.levelDesc.highest'),
    2: t('components.main.levelDesc.high'),
    3: t('components.main.levelDesc.mediumHigh'),
    4: t('components.main.levelDesc.medium'),
    5: t('components.main.levelDesc.normal'),
    6: t('components.main.levelDesc.mediumLow'),
    7: t('components.main.levelDesc.low'),
    8: t('components.main.levelDesc.lower'),
    9: t('components.main.levelDesc.veryLow'),
    10: t('components.main.levelDesc.lowest'),
  }
  return descriptions[level] || t('components.main.levelDesc.normal')
}

const isResponsesEndpointValue = (value?: string) => {
  const normalized = value?.trim().toLowerCase() ?? ''
  return normalized.includes('/responses')
}

const isChatEndpointValue = (value?: string) => {
  const normalized = value?.trim().toLowerCase() ?? ''
  return normalized.includes('/chat/completions')
}

const legacyResponsesEndpoint = (card: AutomationCard) =>
  card.responsesEndpoint || (isResponsesEndpointValue(card.apiEndpoint) ? card.apiEndpoint : '')

const legacyChatEndpoint = (card: AutomationCard) =>
  card.chatEndpoint || (isChatEndpointValue(card.apiEndpoint) ? card.apiEndpoint : '')

// 归一化 level：空/非法视为 1（最高优先级），范围限制 1-10
const normalizeLevel = (level: number | string | undefined): number => {
  const num = Number(level)
  if (!Number.isFinite(num) || num < 1) return 1
  if (num > 10) return 10
  return Math.floor(num)  // 确保返回整数
}

// 按名称排序
const sortProvidersByLevel = (list: AutomationCard[]) => {
  if (!Array.isArray(list)) return
  list.sort((a, b) => a.name.localeCompare(b.name))
}

const modalState = reactive({
  open: false,
  tabId: tabs[0].id as ProviderTab,
  editingId: null as number | null,
  form: defaultFormValues(),
  errors: {
    apiUrl: '',
    apiKey: '',
    protocolEndpoint: '',
    modelsEndpoint: '',
    testModel: '',
  },
})

// 认证方式相关状态
const selectedAuthType = ref<string>('bearer')
const customAuthHeader = ref<string>('')
const authTypeOptions = computed(() => [
  { value: 'bearer', label: 'Bearer' },
  { value: 'x-api-key', label: 'X-API-Key' },
])

const showMessagesEndpointField = computed(() => modalState.tabId === 'claude')
const showResponsesEndpointField = computed(() => modalState.tabId === 'openai-responses')
const showChatEndpointField = computed(() => modalState.tabId === 'openai-chat')

const protocolEndpointsForSave = () => ({
  apiEndpoint: modalState.tabId === 'claude'
    ? modalState.form.apiEndpoint || ''
    : '',
  responsesEndpoint: modalState.tabId === 'openai-responses'
    ? modalState.form.responsesEndpoint || ''
    : '',
  chatEndpoint: modalState.tabId === 'openai-chat'
    ? modalState.form.chatEndpoint || ''
    : '',
})

const resolveEffectiveAuthType = () =>
  customAuthHeader.value.trim() || selectedAuthType.value || getDefaultAuthType(modalState.tabId)

const editingCard = ref<AutomationCard | null>(null)
const confirmState = reactive({ open: false, card: null as AutomationCard | null, tabId: tabs[0].id as ProviderTab })

const openCreateModal = () => {
  modalState.tabId = activeTab.value
  modalState.editingId = null
  editingCard.value = null
  Object.assign(modalState.form, defaultFormValues(activeTab.value))
  providerTestModel.value = defaultTestModel
  providerTestMessage.value = defaultTestMessage
  providerModelOptions.value = []
  providerModelDropdownOpen.value = false
  // 初始化认证方式为平台默认
  selectedAuthType.value = getDefaultAuthType(activeTab.value)
  customAuthHeader.value = ''
  connectivityTestResult.value = null
  protocolEndpointTestResult.value = null
  modelsEndpointTestResult.value = null
  clearEndpointTestErrors()
  modalState.open = true
}

const openEditModal = (card: AutomationCard) => {
  modalState.tabId = activeTab.value
  modalState.editingId = card.id
  editingCard.value = card
  Object.assign(modalState.form, {
    name: card.name,
    apiUrl: card.apiUrl,
    apiKey: card.apiKey,
    officialSite: card.officialSite,
    icon: card.icon,
    level: card.level || 1,
    enabled: card.enabled,
    supportedModels: card.supportedModels || {},
    modelMapping: card.modelMapping || {},
    apiEndpoint: card.apiEndpoint || '',
    responsesEndpoint: legacyResponsesEndpoint(card),
    chatEndpoint: legacyChatEndpoint(card),
    modelsEndpoint: card.modelsEndpoint || '',
    // 可用性监控配置（新）- 兼容从旧字段迁移
    availabilityMonitorEnabled:
      card.availabilityMonitorEnabled ?? card.connectivityCheck ?? false,
    availabilityConfig: {
      testModel:
        card.availabilityConfig?.testModel || card.connectivityTestModel || '',
      testEndpoint:
        card.availabilityConfig?.testEndpoint ||
        card.connectivityTestEndpoint ||
        getDefaultEndpoint(activeTab.value),
      timeout: card.availabilityConfig?.timeout || 15000,
    },
    // 旧可用性字段不再写入表单
    connectivityCheck: false,
    connectivityTestModel: '',
    connectivityTestEndpoint: '',
    connectivityAuthType: card.connectivityAuthType || '',
  })
  providerTestModel.value =
    card.availabilityConfig?.testModel ||
    card.connectivityTestModel ||
    defaultTestModel
  providerTestMessage.value = defaultTestMessage
  providerModelOptions.value = []
  providerModelDropdownOpen.value = false
  // 初始化认证方式状态
  const storedAuth = (card.connectivityAuthType || '').trim()
  const lower = storedAuth.toLowerCase()
  if (!storedAuth) {
    selectedAuthType.value = getDefaultAuthType(activeTab.value)
    customAuthHeader.value = ''
  } else if (lower === 'bearer' || lower === 'x-api-key') {
    selectedAuthType.value = lower
    customAuthHeader.value = ''
  } else {
    // 自定义 Header 名
    selectedAuthType.value = getDefaultAuthType(activeTab.value)
    customAuthHeader.value = storedAuth
  }
  connectivityTestResult.value = null
  protocolEndpointTestResult.value = null
  modelsEndpointTestResult.value = null
  clearEndpointTestErrors()
  modalState.open = true
}

watch(
  () => [modalState.open, modalState.tabId] as const,
  ([open, platform], [prevOpen, prevPlatform]) => {
    if (!open) return
    const previousPlatform = prevOpen ? prevPlatform : platform
    syncDefaultTestEndpoint(platform, previousPlatform)
  }
)

const closeModal = () => {
  modalState.open = false
}

const closeConfirm = () => {
  confirmState.open = false
  confirmState.card = null
}

const submitModal = async (): Promise<boolean> => {
  const list = cards[modalState.tabId]
  if (!list) return false
  const name = modalState.form.name.trim()
  const apiUrl = modalState.form.apiUrl.trim()
  const apiKey = modalState.form.apiKey.trim()
  const officialSite = modalState.form.officialSite.trim()
  modalState.errors.apiUrl = ''
  try {
    const parsed = new URL(apiUrl)
    if (!/^https?:/.test(parsed.protocol)) throw new Error('protocol')
  } catch {
    modalState.errors.apiUrl = t('components.main.form.errors.invalidUrl')
    return false
  }

  const protocolEndpoints = protocolEndpointsForSave()

  if (editingCard.value) {
    Object.assign(editingCard.value, {
      apiUrl: apiUrl || editingCard.value.apiUrl,
      apiKey,
      officialSite,
      icon: '',
      enabled: true,
      supportedModels: modalState.form.supportedModels || {},
      modelMapping: modalState.form.modelMapping || {},
      apiEndpoint: protocolEndpoints.apiEndpoint,
      responsesEndpoint: protocolEndpoints.responsesEndpoint,
      chatEndpoint: protocolEndpoints.chatEndpoint,
      modelsEndpoint: modalState.form.modelsEndpoint || '',
      // 可用性监控配置（新）
      availabilityMonitorEnabled: !!modalState.form.availabilityMonitorEnabled,
      availabilityConfig: {
        testModel: modalState.form.availabilityConfig?.testModel || '',
        testEndpoint:
          modalState.form.availabilityConfig?.testEndpoint ||
          getDefaultEndpoint(modalState.tabId),
        timeout: modalState.form.availabilityConfig?.timeout || 15000,
      },
      // 旧可用性字段清空（避免再次写入）
      connectivityCheck: false,
      connectivityTestModel: '',
      connectivityTestEndpoint: '',
      connectivityAuthType: resolveEffectiveAuthType(),
    })
    const saveResult = await persistProviders(modalState.tabId)
    if (!saveResult.ok) {
      // 保存失败，不关闭弹窗，让用户修正配置
      return false
    }
  } else {
    const newCard: AutomationCard = {
      id: Date.now(),
      name: name || 'Untitled vendor',
      apiUrl,
      apiKey,
      officialSite,
      icon: '',
      accent: '#0a84ff',
      tint: 'rgba(15, 23, 42, 0.12)',
      enabled: modalState.form.enabled ?? true,
      supportedModels: modalState.form.supportedModels || {},
      modelMapping: modalState.form.modelMapping || {},
      apiEndpoint: protocolEndpoints.apiEndpoint,
      responsesEndpoint: protocolEndpoints.responsesEndpoint,
      chatEndpoint: protocolEndpoints.chatEndpoint,
      modelsEndpoint: modalState.form.modelsEndpoint || '',
      // 可用性监控配置（新）
      availabilityMonitorEnabled: !!modalState.form.availabilityMonitorEnabled,
      availabilityConfig: {
        testModel: modalState.form.availabilityConfig?.testModel || '',
        testEndpoint:
          modalState.form.availabilityConfig?.testEndpoint ||
          getDefaultEndpoint(modalState.tabId),
        timeout: modalState.form.availabilityConfig?.timeout || 15000,
      },
      // 旧可用性字段清空
      connectivityCheck: false,
      connectivityTestModel: '',
      connectivityTestEndpoint: '',
      connectivityAuthType: resolveEffectiveAuthType(),
    }
    list.push(newCard)
    sortProvidersByLevel(list)
    const saveResult = await persistProviders(modalState.tabId)
    if (!saveResult.ok) {
      // 保存失败，从列表中移除刚添加的卡片，不关闭弹窗
      const idx = list.indexOf(newCard)
      if (idx !== -1) list.splice(idx, 1)
      return false
    }
  }

  closeModal()

  // 通知可用性页面刷新
  window.dispatchEvent(new CustomEvent('providers-updated'))
  return true
}

// 保存并应用：先保存供应商配置，再直连应用到 CLI
const submitAndApplyModal = async () => {
  // 1. 执行普通保存逻辑
  const editingId = modalState.editingId
  const tabId = modalState.tabId as ProviderTab
  if (!editingId || !supportsDirectApply(tabId)) return

  // 获取当前编辑的卡片
  const editingCard = cards[tabId]?.find(c => c.id === editingId)
  if (!editingCard) return

  // 调用标准保存流程
  const saved = await submitModal()
  if (!saved) {
    // 保存失败，不继续应用
    return
  }

  // 2. 保存成功后，应用到 CLI（直连模式）
  try {
    if (tabId === 'claude') {
      await Call.ByName('codeswitch/services.ClaudeSettingsService.ApplySingleProvider', editingId)
    } else if (tabId === 'openai-responses') {
      await Call.ByName('codeswitch/services.CodexSettingsService.ApplySingleProvider', editingId)
    }
    await refreshDirectAppliedStatus(tabId)
    showToast(t('components.main.directApply.success', { name: editingCard.name }), 'success')
  } catch (error) {
    console.error('Apply after save failed', error)
    showToast(t('components.main.directApply.failed'), 'error')
  }
}

const configure = (card: AutomationCard) => {
  openEditModal(card)
}

const remove = async (id: number, tabId: ProviderTab = activeTab.value) => {
  const list = cards[tabId]
  if (!list) return
  const index = list.findIndex((card) => card.id === id)
  if (index > -1) {
    list.splice(index, 1)
    await persistProviders(tabId)
  }
}

const requestRemove = (card: AutomationCard) => {
  confirmState.card = card
  confirmState.tabId = activeTab.value
  confirmState.open = true
}

// 复制供应商：打开新建表单并预填源供应商数据
const handleDuplicate = (card: AutomationCard) => {
  modalState.tabId = activeTab.value
  modalState.editingId = null // 创建模式（非编辑）
  editingCard.value = null

  const sourceName = card.name?.trim() || '未命名供应商'
  Object.assign(modalState.form, {
    name: `${sourceName}（副本）`,
    apiUrl: card.apiUrl,
    apiKey: card.apiKey,
    officialSite: card.officialSite,
    icon: card.icon,
    level: card.level || 1,
    enabled: card.enabled,
    supportedModels: card.supportedModels ? { ...card.supportedModels } : {},
    modelMapping: card.modelMapping ? { ...card.modelMapping } : {},
    apiEndpoint: card.apiEndpoint || '',
    responsesEndpoint: legacyResponsesEndpoint(card),
    chatEndpoint: legacyChatEndpoint(card),
    modelsEndpoint: card.modelsEndpoint || '',
    availabilityMonitorEnabled:
      card.availabilityMonitorEnabled ?? card.connectivityCheck ?? false,
    availabilityConfig: {
      testModel:
        card.availabilityConfig?.testModel || card.connectivityTestModel || '',
      testEndpoint:
        card.availabilityConfig?.testEndpoint ||
        card.connectivityTestEndpoint ||
        getDefaultEndpoint(activeTab.value),
      timeout: card.availabilityConfig?.timeout || 15000,
    },
    connectivityCheck: false,
    connectivityTestModel: '',
    connectivityTestEndpoint: '',
    connectivityAuthType: card.connectivityAuthType || '',
  })
  providerTestModel.value =
    card.availabilityConfig?.testModel ||
    card.connectivityTestModel ||
    defaultTestModel
  providerTestMessage.value = defaultTestMessage
  providerModelOptions.value = []
  providerModelDropdownOpen.value = false

  // 初始化认证方式状态
  const storedAuth = (card.connectivityAuthType || '').trim()
  const lower = storedAuth.toLowerCase()
  if (!storedAuth) {
    selectedAuthType.value = getDefaultAuthType(activeTab.value)
    customAuthHeader.value = ''
  } else if (lower === 'bearer' || lower === 'x-api-key') {
    selectedAuthType.value = lower
    customAuthHeader.value = ''
  } else {
    selectedAuthType.value = getDefaultAuthType(activeTab.value)
    customAuthHeader.value = storedAuth
  }

  connectivityTestResult.value = null
  protocolEndpointTestResult.value = null
  modelsEndpointTestResult.value = null
  clearEndpointTestErrors()
  modalState.open = true
}

const confirmRemove = async () => {
  if (!confirmState.card) return
  await remove(confirmState.card.id, confirmState.tabId)
  closeConfirm()
}

const onDragStart = (id: number) => {
  draggingId.value = id
}

const onDrop = async (targetId: number) => {
  if (draggingId.value === null || draggingId.value === targetId) return
  const currentTab = activeTab.value
  const list = cards[currentTab]
  if (!list) return
  const fromIndex = list.findIndex((card) => card.id === draggingId.value)
  const toIndex = list.findIndex((card) => card.id === targetId)
  if (fromIndex === -1 || toIndex === -1) return
  const [moved] = list.splice(fromIndex, 1)
  const newIndex = fromIndex < toIndex ? toIndex - 1 : toIndex
  list.splice(newIndex, 0, moved)
  draggingId.value = null
  await persistProviders(currentTab)
}

const onDragEnd = () => {
  draggingId.value = null
}

const reorderTabs = (targetTab: ProviderTab) => {
  const sourceTab = draggingTab.value
  if (!sourceTab || sourceTab === targetTab) return

  const fromIndex = tabOrder.value.indexOf(sourceTab)
  const toIndex = tabOrder.value.indexOf(targetTab)
  if (fromIndex < 0 || toIndex < 0) return

  const nextOrder = [...tabOrder.value]
  nextOrder.splice(fromIndex, 1)
  nextOrder.splice(toIndex, 0, sourceTab)
  tabOrder.value = nextOrder
  saveTabOrder(nextOrder)
}

const onTabChange = (tabId: ProviderTab) => {
  selectedTab.value = tabId
  void refreshProxyState(tabId)
  void refreshDirectAppliedStatus(tabId)
  void loadProviderStats(tabId)
}

const onTabDragStart = (tabId: ProviderTab, event: DragEvent) => {
  draggingTab.value = tabId
  event.dataTransfer?.setData('text/plain', tabId)
  if (event.dataTransfer) {
    event.dataTransfer.effectAllowed = 'move'
  }
}

const onTabDragEnter = (tabId: ProviderTab) => {
  reorderTabs(tabId)
}

const onTabDrop = (tabId: ProviderTab) => {
  reorderTabs(tabId)
  draggingTab.value = null
}

const onTabDragEnd = () => {
  draggingTab.value = null
}

// ========== 自定义 CLI 工具管理 ==========

// CLI 工具模态框状态
const cliToolModalState = reactive({
  open: false,
  editingId: null as string | null,
  form: {
    name: '',
    configFiles: [] as Array<{
      id: string
      label: string
      path: string
      format: 'json' | 'toml' | 'env'
      isPrimary: boolean
    }>,
    proxyInjection: [] as Array<{
      targetFileId: string
      baseUrlField: string
      authTokenField: string
    }>,
  },
})

// CLI 工具删除确认状态
const cliToolConfirmState = reactive({
  open: false,
  tool: null as CustomCliTool | null,
})

// 切换选中的 CLI 工具
const onToolSelect = async () => {
  if (selectedToolId.value) {
    // 更新当前 tab 的代理状态
    proxyStates.others = customCliProxyStates[selectedToolId.value] ?? false
    // 加载该工具的 providers 列表
    await loadCustomCliProviders(selectedToolId.value)
  } else {
    // 未选中任何工具，清空 providers 列表
    cards.others.splice(0, cards.others.length)
  }
}

// 仅在只有一个配置文件时自动选中，避免多配置场景下造成"意外选择"
const getAutoSelectedProxyTargetFileId = () => {
  const files = cliToolModalState.form.configFiles
  if (files.length === 1) return files[0].id
  return ''
}

// 打开新建 CLI 工具模态框
const openCliToolModal = () => {
  cliToolModalState.editingId = null
  cliToolModalState.form.name = ''
  cliToolModalState.form.configFiles = [{
    id: `cfg-${Date.now()}`,
    label: t('components.main.customCli.primaryConfig'),
    path: '',
    format: 'json',
    isPrimary: true,
  }]
  // 默认占位行保持全空，允许用户选择不配置代理注入
  // 保存时会自动补齐 targetFileId（如果用户填写了字段且只有一个配置文件）
  cliToolModalState.form.proxyInjection = [{
    targetFileId: '',
    baseUrlField: '',
    authTokenField: '',
  }]
  cliToolModalState.open = true
}

// 编辑当前选中的 CLI 工具
const editCurrentCliTool = async () => {
  if (!selectedToolId.value) return
  const tool = customCliTools.value.find(t => t.id === selectedToolId.value)
  if (!tool) return

  cliToolModalState.editingId = tool.id
  cliToolModalState.form.name = tool.name
  cliToolModalState.form.configFiles = tool.configFiles.length > 0
    ? tool.configFiles.map(cf => ({
        id: cf.id,
        label: cf.label,
        path: cf.path,
        format: cf.format,
        isPrimary: cf.isPrimary ?? false,
      }))
    : [{
        id: `cfg-${Date.now()}`,
        label: t('components.main.customCli.primaryConfig'),
        path: '',
        format: 'json' as const,
        isPrimary: true,
      }]
  // 加载已有的代理注入配置，默认占位行保持全空
  // 保存时会自动补齐 targetFileId（如果用户填写了字段且只有一个配置文件）
  cliToolModalState.form.proxyInjection = tool.proxyInjection && tool.proxyInjection.length > 0
    ? tool.proxyInjection.map(pi => ({
        targetFileId: pi.targetFileId ?? '',
        baseUrlField: pi.baseUrlField ?? '',
        authTokenField: pi.authTokenField ?? '',
      }))
    : [{
        targetFileId: '',
        baseUrlField: '',
        authTokenField: '',
      }]
  cliToolModalState.open = true
}

// 请求删除当前选中的 CLI 工具
const deleteCurrentCliTool = () => {
  if (!selectedToolId.value) return
  const tool = customCliTools.value.find(t => t.id === selectedToolId.value)
  if (!tool) return
  cliToolConfirmState.tool = tool
  cliToolConfirmState.open = true
}

// 关闭 CLI 工具模态框
const closeCliToolModal = () => {
  cliToolModalState.open = false
}

// 关闭 CLI 工具删除确认框
const closeCliToolConfirm = () => {
  cliToolConfirmState.open = false
  cliToolConfirmState.tool = null
}

// 添加配置文件
const addConfigFile = () => {
  cliToolModalState.form.configFiles.push({
    id: `cfg-${Date.now()}`,
    label: '',
    path: '',
    format: 'json',
    isPrimary: false,
  })
}

// 删除配置文件
const removeConfigFile = (index: number) => {
  if (cliToolModalState.form.configFiles.length <= 1) return
  cliToolModalState.form.configFiles.splice(index, 1)
}

// 添加代理注入配置
const addProxyInjection = () => {
  cliToolModalState.form.proxyInjection.push({
    targetFileId: getAutoSelectedProxyTargetFileId(),
    baseUrlField: '',
    authTokenField: '',
  })
}

// 删除代理注入配置
const removeProxyInjection = (index: number) => {
  if (cliToolModalState.form.proxyInjection.length <= 1) return
  cliToolModalState.form.proxyInjection.splice(index, 1)
}

// 提交 CLI 工具模态框
const submitCliToolModal = async () => {
  const name = cliToolModalState.form.name.trim()
  if (!name) {
    showToast(t('components.main.customCli.nameRequired'), 'error')
    return
  }

  // 过滤掉空的配置文件
  const validConfigFiles = cliToolModalState.form.configFiles.filter(cf => cf.path.trim())
  if (validConfigFiles.length === 0) {
    showToast(t('components.main.customCli.configRequired'), 'error')
    return
  }

  // 验证至少有一个主配置文件
  const hasPrimary = validConfigFiles.some(cf => cf.isPrimary)
  if (!hasPrimary) {
    // 如果没有选中主配置文件，自动将第一个设为主配置
    validConfigFiles[0].isPrimary = true
  }

  // 代理注入配置：允许全空（表示不使用），但不允许"半填"
  // 单一配置文件时，自动选中作为代理注入目标（避免用户忘记选择）
  const autoTargetFileId = validConfigFiles.length === 1 ? validConfigFiles[0].id : ''

  const proxyInjectionsToSave = cliToolModalState.form.proxyInjection
    .map(pi => {
      const baseUrlField = pi.baseUrlField.trim()
      const authTokenField = pi.authTokenField.trim()
      // 如果用户填写了字段但忘记选择目标文件，且只有一个配置文件，自动补充
      const targetFileId = pi.targetFileId.trim() || ((baseUrlField || authTokenField) ? autoTargetFileId : '')
      return { targetFileId, baseUrlField, authTokenField }
    })
    .filter(pi => pi.targetFileId || pi.baseUrlField || pi.authTokenField)

  const hasIncompleteProxyInjection = proxyInjectionsToSave.some(
    pi => !pi.targetFileId || !pi.baseUrlField
  )
  if (hasIncompleteProxyInjection) {
    showToast(t('components.main.customCli.proxyInjectionIncomplete'), 'error')
    return
  }

  // 先校验"目标 ID 是否存在"，再校验"目标文件路径是否有效"，避免报错信息误导
  const allFileIds = new Set(cliToolModalState.form.configFiles.map(cf => cf.id))
  const validFileIds = new Set(validConfigFiles.map(cf => cf.id))

  const hasInvalidProxyTarget = proxyInjectionsToSave.some(pi => !allFileIds.has(pi.targetFileId))
  if (hasInvalidProxyTarget) {
    showToast(t('components.main.customCli.invalidProxyTarget'), 'error')
    return
  }

  const hasProxyTargetPathMissing = proxyInjectionsToSave.some(pi => !validFileIds.has(pi.targetFileId))
  if (hasProxyTargetPathMissing) {
    showToast(t('components.main.customCli.proxyTargetPathRequired'), 'error')
    return
  }

  try {
    if (cliToolModalState.editingId) {
      // 更新现有工具
      await updateCustomCliTool(cliToolModalState.editingId, {
        id: cliToolModalState.editingId,
        name,
        configFiles: validConfigFiles,
        proxyInjection: proxyInjectionsToSave,
      })
      showToast(t('components.main.customCli.updateSuccess'), 'success')
    } else {
      // 创建新工具
      const newTool = await createCustomCliTool({
        name,
        configFiles: validConfigFiles,
        proxyInjection: proxyInjectionsToSave,
      })
      selectedToolId.value = newTool.id
      showToast(t('components.main.customCli.createSuccess'), 'success')
    }

    // 刷新工具列表
    await loadCustomCliTools()
    closeCliToolModal()
  } catch (error) {
    console.error('Failed to save CLI tool', error)
    // 处理各种错误类型：Error 对象、字符串、其他
    const msg = error instanceof Error ? error.message : String(error ?? '')
    if (msg.includes('ERR_CUSTOM_CLI_PROXY_INJECTION_INCOMPLETE')) {
      showToast(t('components.main.customCli.proxyInjectionIncomplete'), 'error')
      return
    }
    if (msg.includes('ERR_CUSTOM_CLI_INVALID_PROXY_TARGET')) {
      showToast(t('components.main.customCli.invalidProxyTarget'), 'error')
      return
    }
    showToast(t('components.main.customCli.saveFailed'), 'error')
  }
}

// 确认删除 CLI 工具
const confirmDeleteCliTool = async () => {
  if (!cliToolConfirmState.tool) return
  try {
    await deleteCustomCliTool(cliToolConfirmState.tool.id)
    showToast(t('components.main.customCli.deleteSuccess'), 'success')

    // 如果删除的是当前选中的工具，清空选择
    if (selectedToolId.value === cliToolConfirmState.tool.id) {
      selectedToolId.value = null
      proxyStates.others = false
    }

    // 刷新工具列表
    await loadCustomCliTools()
    closeCliToolConfirm()
  } catch (error) {
    console.error('Failed to delete CLI tool', error)
    showToast(t('components.main.customCli.deleteFailed'), 'error')
  }
}
</script>

<style scoped>
/* 正在使用的供应商卡片样式 */
/* @author sm */
.automation-card.is-last-used {
  position: relative;
  border: 2px solid rgb(16, 185, 129);
  box-shadow: 0 0 8px rgba(16, 185, 129, 0.3);
}

/* 正在使用标签 */
.last-used-badge {
  position: absolute;
  top: -10px;
  right: 12px;
  background: rgb(16, 185, 129);
  color: white;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 8px;
  border-radius: 4px;
  z-index: 1;
}

/* 高亮闪烁的供应商卡片（切换时） */
.automation-card.is-highlighted {
  animation: highlight-pulse 0.6s ease-in-out 3;
  border-color: rgb(245, 158, 11);
  box-shadow: 0 0 12px rgba(245, 158, 11, 0.5);
}

@keyframes highlight-pulse {
  0%, 100% {
    box-shadow: 0 0 8px rgba(245, 158, 11, 0.3);
  }
  50% {
    box-shadow: 0 0 20px rgba(245, 158, 11, 0.7);
  }
}

/* 暗色模式适配 */
:global(.dark) .automation-card.is-last-used {
  border-color: rgb(52, 211, 153);
  box-shadow: 0 0 8px rgba(52, 211, 153, 0.3);
}

:global(.dark) .last-used-badge {
  background: rgb(52, 211, 153);
  color: rgb(6, 78, 59);
}

:global(.dark) .automation-card.is-highlighted {
  border-color: rgb(251, 191, 36);
  box-shadow: 0 0 12px rgba(251, 191, 36, 0.5);
}

.global-actions .ghost-icon svg.rotating {
  animation: import-spin 0.9s linear infinite;
}

@keyframes import-spin {
  from {
    transform: rotate(0deg);
  }

  to {
    transform: rotate(360deg);
  }
}

/* Level Badge 样式 */
.level-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 32px;
  height: 22px;
  padding: 0 7px;
  border-radius: 8px;
  font-size: 11px;
  font-weight: 600;
  line-height: 1;
  letter-spacing: 0.03em;
  text-align: center;
  transition: all 0.2s ease;
}

/* Card title row badge 定位 */
.card-title-row .level-badge {
  margin-left: 8px;
}

/* Level 配色方案：从绿色（高优先级）到红色（低优先级）*/
.level-badge.level-1 {
  background: rgba(16, 185, 129, 0.12);
  color: rgb(5, 150, 105);
}

.level-badge.level-2 {
  background: rgba(34, 197, 94, 0.12);
  color: rgb(22, 163, 74);
}

.level-badge.level-3 {
  background: rgba(132, 204, 22, 0.12);
  color: rgb(101, 163, 13);
}

.level-badge.level-4 {
  background: rgba(234, 179, 8, 0.12);
  color: rgb(161, 98, 7);
}

.level-badge.level-5 {
  background: rgba(245, 158, 11, 0.12);
  color: rgb(180, 83, 9);
}

.level-badge.level-6 {
  background: rgba(249, 115, 22, 0.12);
  color: rgb(194, 65, 12);
}

.level-badge.level-7 {
  background: rgba(239, 68, 68, 0.12);
  color: rgb(185, 28, 28);
}

.level-badge.level-8 {
  background: rgba(220, 38, 38, 0.12);
  color: rgb(153, 27, 27);
}

.level-badge.level-9 {
  background: rgba(190, 18, 60, 0.12);
  color: rgb(136, 19, 55);
}

.level-badge.level-10 {
  background: rgba(159, 18, 57, 0.12);
  color: rgb(112, 26, 52);
}

/* 暗色模式适配 */
:global(.dark) .level-badge.level-1 {
  background: rgba(16, 185, 129, 0.18);
  color: rgb(52, 211, 153);
}

:global(.dark) .level-badge.level-2 {
  background: rgba(34, 197, 94, 0.18);
  color: rgb(74, 222, 128);
}

:global(.dark) .level-badge.level-3 {
  background: rgba(132, 204, 22, 0.18);
  color: rgb(163, 230, 53);
}

:global(.dark) .level-badge.level-4 {
  background: rgba(234, 179, 8, 0.18);
  color: rgb(250, 204, 21);
}

:global(.dark) .level-badge.level-5 {
  background: rgba(245, 158, 11, 0.18);
  color: rgb(251, 191, 36);
}

:global(.dark) .level-badge.level-6 {
  background: rgba(249, 115, 22, 0.18);
  color: rgb(251, 146, 60);
}

:global(.dark) .level-badge.level-7 {
  background: rgba(239, 68, 68, 0.18);
  color: rgb(248, 113, 113);
}

:global(.dark) .level-badge.level-8 {
  background: rgba(220, 38, 38, 0.18);
  color: rgb(239, 68, 68);
}

:global(.dark) .level-badge.level-9 {
  background: rgba(190, 18, 60, 0.18);
  color: rgb(244, 63, 94);
}

:global(.dark) .level-badge.level-10 {
  background: rgba(159, 18, 57, 0.18);
  color: rgb(236, 72, 153);
}

/* Level Select Dropdown 样式 */
.level-select {
  position: relative;
}

.level-select-button {
  display: flex;
  align-items: center;
  gap: 8px;
  width: 100%;
  padding: 8px 12px;
  background: var(--color-bg-secondary);
  border: 1px solid var(--color-border);
  border-radius: 8px;
  font-size: 14px;
  color: var(--color-text-primary);
  cursor: pointer;
  transition: all 0.2s ease;
}

.level-select-button:hover {
  border-color: var(--color-border-hover);
  background: var(--color-bg-tertiary);
}

.level-select-button:focus {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

.level-select-button svg {
  width: 16px;
  height: 16px;
  margin-left: auto;
  opacity: 0.5;
}

.level-label {
  flex: 1;
  text-align: left;
}

.level-select-options {
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  max-height: 280px;
  overflow-y: auto;
  background: var(--mac-surface);
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
  z-index: 50;
  padding: 4px;
}

:global(.dark) .level-select-options {
  background: var(--mac-surface);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
}

.level-option {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 10px;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.level-option:hover,
.level-option.active {
  background: var(--mac-surface-strong);
}

.level-option.selected {
  background: rgba(10, 132, 255, 0.12); /* fallback for old WebKit */
  background: color-mix(in srgb, var(--mac-accent) 12%, transparent);
  font-weight: 500;
}

.level-option .level-name {
  flex: 1;
  font-size: 14px;
  color: var(--mac-text);
}

.level-option.selected .level-name {
  color: var(--mac-accent);
}

/* 可用性状态指示器 */
.connectivity-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-left: 6px;
  flex-shrink: 0;
  transition: background-color 0.2s ease;
}

.connectivity-dot.connectivity-green {
  background-color: #22c55e;
  box-shadow: 0 0 4px rgba(34, 197, 94, 0.5);
}

.connectivity-dot.connectivity-yellow {
  background-color: #eab308;
  box-shadow: 0 0 4px rgba(234, 179, 8, 0.5);
}

.connectivity-dot.connectivity-red {
  background-color: #ef4444;
  box-shadow: 0 0 4px rgba(239, 68, 68, 0.5);
}

.connectivity-dot.connectivity-gray {
  background-color: #9ca3af;
}

:global(.dark) .connectivity-dot.connectivity-green {
  background-color: #4ade80;
  box-shadow: 0 0 6px rgba(74, 222, 128, 0.6);
}

:global(.dark) .connectivity-dot.connectivity-yellow {
  background-color: #facc15;
  box-shadow: 0 0 6px rgba(250, 204, 21, 0.6);
}

:global(.dark) .connectivity-dot.connectivity-red {
  background-color: #f87171;
  box-shadow: 0 0 6px rgba(248, 113, 113, 0.6);
}

:global(.dark) .connectivity-dot.connectivity-gray {
  background-color: #6b7280;
}

/* 测试可用性按钮 */
.test-connectivity-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  width: 100%;
  padding: 10px 16px;
  background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
}

.test-connectivity-btn:hover:not(:disabled) {
  filter: brightness(1.1);
}

.test-connectivity-btn:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.field-with-action {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 8px;
  align-items: center;
}

.field-with-dropdown-action {
  grid-template-columns: minmax(0, 1fr) auto;
}

.field-with-dropdown-action .provider-model-combobox {
  min-width: 0;
}

.field-test-output-group {
  display: grid;
  gap: 8px;
}

.field-test-output {
  display: grid;
  gap: 8px;
}

.field-test-output-title {
  font-size: 0.75rem;
  font-weight: 600;
  color: var(--mac-text-secondary);
}

.field-test-btn {
  min-height: 36px;
  padding: 0 12px;
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: var(--mac-surface);
  color: var(--mac-text);
  cursor: pointer;
  font-size: 0.86rem;
  white-space: nowrap;
}

.field-test-btn:hover:not(:disabled) {
  background: rgba(59, 130, 246, 0.1);
  border-color: rgba(59, 130, 246, 0.45);
}

.field-test-btn:disabled {
  cursor: not-allowed;
  opacity: 0.55;
}

.field-test-btn-tight {
  min-width: 112px;
  flex-shrink: 0;
}

.field-test-result {
  margin: -4px 0 4px;
  padding: 7px 10px;
  border-radius: 6px;
  font-size: 0.82rem;
}

.field-test-result.success {
  background: rgba(34, 197, 94, 0.1);
  color: #15803d;
}

.field-test-result.error {
  background: rgba(239, 68, 68, 0.1);
  color: #dc2626;
}

.endpoint-test-panel {
  display: grid;
  gap: 10px;
  padding: 12px;
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: rgba(15, 23, 42, 0.03);
}

:global(.dark) .endpoint-test-panel {
  background: rgba(255, 255, 255, 0.04);
}

.provider-model-combobox {
  position: relative;
}

.provider-model-combobox .base-input {
  width: 100%;
  padding-right: 34px;
}

.provider-model-toggle {
  position: absolute;
  top: 1px;
  right: 1px;
  width: 32px;
  height: 32px;
  border: 0;
  border-left: 1px solid var(--mac-border);
  border-radius: 0 8px 8px 0;
  background: transparent;
  color: var(--mac-text-secondary);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.provider-model-toggle svg {
  width: 16px;
  height: 16px;
}

.provider-model-options {
  position: absolute;
  z-index: 30;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  max-height: 220px;
  overflow-y: auto;
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: var(--mac-surface);
  box-shadow: 0 12px 32px rgba(15, 23, 42, 0.16);
  padding: 4px;
}

.provider-model-option {
  width: 100%;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--mac-text);
  cursor: pointer;
  display: block;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.82rem;
  padding: 7px 8px;
  text-align: left;
}

.provider-model-option:hover,
.provider-model-option:focus {
  background: rgba(59, 130, 246, 0.12);
  outline: none;
}

.provider-model-empty {
  color: var(--mac-text-secondary);
  font-size: 0.82rem;
  padding: 9px 8px;
}

:global(.base-input.has-error) {
  border-color: rgba(255, 59, 48, 0.9);
  box-shadow: 0 0 0 2px rgba(255, 59, 48, 0.14);
}

:global(.base-input.shake-error) {
  animation: field-shake 0.42s ease;
}

@keyframes field-shake {
  0%, 100% { transform: translateX(0); }
  18% { transform: translateX(-5px); }
  36% { transform: translateX(5px); }
  54% { transform: translateX(-4px); }
  72% { transform: translateX(4px); }
}

.btn-spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255, 255, 255, 0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}

.test-result {
  margin-top: 8px;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 13px;
}

.test-result.success {
  background: rgba(34, 197, 94, 0.1);
  color: #16a34a;
  border-left: 3px solid #22c55e;
}

.test-result.error {
  background: rgba(239, 68, 68, 0.1);
  color: #dc2626;
  border-left: 3px solid #ef4444;
}

:global(.dark) .test-result.success {
  background: rgba(34, 197, 94, 0.15);
  color: #4ade80;
}

:global(.dark) .test-result.error {
  background: rgba(239, 68, 68, 0.15);
  color: #f87171;
}

/* ========== CLI 工具选择器样式 ========== */
.cli-tool-selector {
  padding: 12px 16px;
  background: var(--mac-surface);
  border-radius: 8px;
  margin-bottom: 16px;
  border: 1px solid var(--mac-border);
}

.tool-selector-row {
  display: flex;
  align-items: center;
  gap: 8px;
}

.tool-select {
  flex: 1;
  padding: 8px 12px;
  background: var(--color-bg-secondary);
  border: 1px solid var(--color-border);
  border-radius: 6px;
  font-size: 14px;
  color: var(--color-text-primary);
  cursor: pointer;
  transition: all 0.2s ease;
}

.tool-select:hover {
  border-color: var(--color-border-hover);
}

.tool-select:focus {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

.add-tool-btn {
  flex-shrink: 0;
}

.no-tools-hint {
  margin-top: 8px;
  font-size: 13px;
  color: var(--mac-text-secondary);
  text-align: center;
}

/* ========== CLI 工具表单样式 ========== */
.cli-tool-form .field-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.cli-tool-form .field-header span {
  font-size: 14px;
  font-weight: 500;
  color: var(--mac-text);
}

.cli-tool-form .add-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  background: var(--mac-accent);
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.cli-tool-form .add-btn:hover {
  filter: brightness(1.1);
}

.cli-tool-form .add-btn svg {
  width: 16px;
  height: 16px;
}

.cli-tool-form .remove-btn {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  background: transparent;
  color: var(--mac-text-secondary);
  border: 1px solid var(--mac-border);
  border-radius: 6px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.cli-tool-form .remove-btn:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.1);
  border-color: #ef4444;
  color: #ef4444;
}

.cli-tool-form .remove-btn:disabled {
  opacity: 0.4;
  cursor: not-allowed;
}

.cli-tool-form .remove-btn svg {
  width: 14px;
  height: 14px;
}

/* ========== 配置文件列表样式 ========== */
.config-files-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.config-file-item {
  padding: 12px;
  background: var(--mac-surface-strong);
  border: 1px solid var(--mac-border);
  border-radius: 8px;
}

.config-file-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.config-label-input {
  flex: 1;
  min-width: 0;
}

.config-format-select {
  width: 80px;
  padding: 6px 8px;
  background: var(--color-bg-secondary);
  border: 1px solid var(--color-border);
  border-radius: 6px;
  font-size: 13px;
  color: var(--color-text-primary);
  cursor: pointer;
}

.config-format-select:focus {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

.primary-checkbox {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--mac-text-secondary);
  white-space: nowrap;
  cursor: pointer;
}

.primary-checkbox input {
  width: 14px;
  height: 14px;
  accent-color: var(--mac-accent);
  cursor: pointer;
}

.config-path-input {
  width: 100%;
}

/* ========== 代理注入配置样式 ========== */
.proxy-injection-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.proxy-injection-item {
  padding: 12px;
  background: var(--mac-surface-strong);
  border: 1px solid var(--mac-border);
  border-radius: 8px;
}

.proxy-injection-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.target-file-select {
  flex: 1;
  padding: 8px 12px;
  background: var(--color-bg-secondary);
  border: 1px solid var(--color-border);
  border-radius: 6px;
  font-size: 13px;
  color: var(--color-text-primary);
  cursor: pointer;
}

.target-file-select:focus {
  outline: 2px solid var(--color-accent);
  outline-offset: 2px;
}

.proxy-fields-row {
  display: flex;
  gap: 8px;
}

.proxy-field-input {
  flex: 1;
  min-width: 0;
}

/* 暗色模式适配 */
:global(.dark) .cli-tool-selector {
  background: var(--mac-surface);
  border-color: var(--mac-border);
}

:global(.dark) .config-file-item,
:global(.dark) .proxy-injection-item {
  background: rgba(255, 255, 255, 0.03);
  border-color: rgba(255, 255, 255, 0.08);
}

:global(.dark) .tool-select,
:global(.dark) .config-format-select,
:global(.dark) .target-file-select {
  background: rgba(255, 255, 255, 0.05);
  border-color: rgba(255, 255, 255, 0.1);
  color: var(--mac-text);
}

:global(.dark) .tool-select:hover,
:global(.dark) .config-format-select:hover,
:global(.dark) .target-file-select:hover {
  border-color: rgba(255, 255, 255, 0.2);
}

/* 直连应用按钮 */
.direct-apply-btn {
  position: relative;
  transition: all 0.2s ease;
  color: var(--mac-text-secondary);
  min-width: 32px;
  display: flex;
  align-items: center;
  justify-content: center;
}

.direct-apply-btn .lightning-icon {
  width: 16px;
  height: 16px;
}

.direct-apply-btn:not(:disabled):not(.is-active):hover {
  color: #f59e0b;
  background: rgba(245, 158, 11, 0.1);
}

.direct-apply-btn:disabled {
  opacity: 0.3;
  cursor: not-allowed;
  filter: grayscale(100%);
}

.direct-apply-btn.is-active {
  border: 1px solid #10b981;
  background: rgba(16, 185, 129, 0.1);
  color: #10b981;
  width: auto;
  padding: 0 8px;
  border-radius: 6px;
  gap: 4px;
}

.direct-apply-btn .apply-text {
  font-size: 11px;
  font-weight: 600;
  white-space: nowrap;
}

:global(.dark) .direct-apply-btn.is-active {
  border-color: #34d399;
  background: rgba(52, 211, 153, 0.15);
  color: #34d399;
}

/* 当前使用徽章 */
.current-use-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 6px;
  margin-left: 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 600;
  background: linear-gradient(135deg, #10b981 0%, #059669 100%);
  color: white;
  box-shadow: 0 2px 4px rgba(16, 185, 129, 0.2);
}

:global(.dark) .current-use-badge {
  background: linear-gradient(135deg, #059669 0%, #047857 100%);
}
</style>
