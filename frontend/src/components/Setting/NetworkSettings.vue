<template>
  <div class="network-settings">
    <section>
      <h2 class="mac-section-title">{{ t('settings.network.title') }}</h2>
      <div class="mac-panel">
        <ListItem :label="t('settings.network.listenMode')">
          <select
            v-model="listenMode"
            class="mac-select"
            @change="handleListenModeChange"
          >
            <option value="localhost">{{ t('settings.network.modes.localhost') }}</option>
            <option value="lan">{{ t('settings.network.modes.lan') }}</option>
            <option value="custom">{{ t('settings.network.modes.custom') }}</option>
          </select>
        </ListItem>

        <ListItem
          v-if="listenMode === 'custom'"
          :label="t('settings.network.customAddress')"
        >
          <input
            v-model="customAddress"
            type="text"
            class="mac-input"
            placeholder="0.0.0.0:18100"
            @blur="handleCustomAddressChange"
          />
        </ListItem>

        <div v-if="listenMode === 'lan'" class="security-warning">
          <div class="warning-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div class="warning-content">
            <p class="warning-title">{{ t('settings.network.lanWarningTitle') }}</p>
            <p class="warning-text">{{ t('settings.network.lanWarningText') }}</p>
          </div>
        </div>

        <ListItem :label="t('settings.network.currentAddress')">
          <span class="address-display">{{ currentListenAddress }}</span>
        </ListItem>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { Call } from '@wailsio/runtime'
import ListItem from './ListRow.vue'
import { showToast } from '../../utils/toast'

const { t } = useI18n()

type ListenMode = 'localhost' | 'lan' | 'custom'

const listenMode = ref<ListenMode>('localhost')
const customAddress = ref('')
const currentListenAddress = ref('127.0.0.1:18100')

const normalizeListenMode = (value?: string): ListenMode => {
  if (value === 'lan' || value === 'custom') return value
  return 'localhost'
}

const computeListenAddress = (): string => {
  switch (listenMode.value) {
    case 'localhost':
      return '127.0.0.1:18100'
    case 'lan':
      return '0.0.0.0:18100'
    case 'custom':
      return customAddress.value || '0.0.0.0:18100'
    default:
      return '127.0.0.1:18100'
  }
}

const loadSettings = async () => {
  try {
    const settings = await Call.ByName('codeswitch/services.NetworkService.GetNetworkSettings')
    if (settings) {
      listenMode.value = normalizeListenMode(settings.listenMode)
      customAddress.value = settings.customAddress || ''
      currentListenAddress.value = settings.currentAddress || computeListenAddress()
    }
  } catch (error) {
    console.error('Failed to load network settings:', error)
  }
}

const saveSettings = async () => {
  try {
    await Call.ByName('codeswitch/services.NetworkService.SaveNetworkSettings', {
      listenMode: listenMode.value,
      customAddress: customAddress.value,
    })
  } catch (error) {
    console.error('Failed to save network settings:', error)
    showToast(t('settings.network.saveFailed'), 'error')
  }
}

const handleListenModeChange = async () => {
  currentListenAddress.value = computeListenAddress()
  await saveSettings()
}

const handleCustomAddressChange = async () => {
  if (listenMode.value === 'custom') {
    currentListenAddress.value = customAddress.value || '0.0.0.0:18100'
    await saveSettings()
  }
}

onMounted(async () => {
  await loadSettings()
})
</script>

<style scoped>
.network-settings {
  margin-top: 24px;
}

.security-warning {
  display: flex;
  gap: 12px;
  padding: 12px 16px;
  margin: 8px 0;
  background: rgba(245, 158, 11, 0.1);
  border: 1px solid rgba(245, 158, 11, 0.3);
  border-radius: 8px;
}

.warning-icon {
  flex-shrink: 0;
  width: 24px;
  height: 24px;
  color: #f59e0b;
}

.warning-icon svg {
  width: 100%;
  height: 100%;
}

.warning-content {
  flex: 1;
}

.warning-title {
  margin: 0 0 4px;
  font-weight: 600;
  color: #92400e;
}

.warning-text {
  margin: 0;
  font-size: 13px;
  color: #78350f;
  line-height: 1.4;
}

.address-display {
  font-family: monospace;
  font-size: 13px;
  color: var(--mac-text-secondary);
  background: var(--mac-bg-secondary);
  padding: 4px 8px;
  border-radius: 4px;
}

:global(.dark) .security-warning {
  background: rgba(245, 158, 11, 0.15);
  border-color: rgba(245, 158, 11, 0.4);
}

:global(.dark) .warning-title {
  color: #fbbf24;
}

:global(.dark) .warning-text {
  color: #fcd34d;
}
</style>
