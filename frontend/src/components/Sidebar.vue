<script setup lang="ts">
import { computed, ref, onBeforeUnmount, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { fetchCurrentVersion } from '../services/version'

const router = useRouter()
const route = useRoute()
const { t } = useI18n()

// 动态版本号（从后端获取）
const appVersion = ref('...')
const isMobile = ref(false)
let mobileQuery: MediaQueryList | null = null
let handleMobileChange: (() => void) | null = null
onMounted(async () => {
  try {
    appVersion.value = await fetchCurrentVersion()
  } catch {
    appVersion.value = 'v?.?.?'
  }
})

// 侧边栏收起状态
const SIDEBAR_COLLAPSED_KEY = 'sidebar-collapsed'
const isCollapsed = ref(false)

onMounted(() => {
  const saved = localStorage.getItem(SIDEBAR_COLLAPSED_KEY)
  if (saved !== null) {
    isCollapsed.value = saved === 'true'
  }

  mobileQuery = window.matchMedia('(max-width: 760px)')
  handleMobileChange = () => {
    isMobile.value = Boolean(mobileQuery?.matches)
  }
  handleMobileChange()
  mobileQuery.addEventListener('change', handleMobileChange)
})

onBeforeUnmount(() => {
  if (mobileQuery && handleMobileChange) {
    mobileQuery.removeEventListener('change', handleMobileChange)
  }
})

const toggleCollapse = () => {
  isCollapsed.value = !isCollapsed.value
  localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(isCollapsed.value))
}

interface NavItem {
  path: string
  icon: string
  labelKey: string
}

const navItems: NavItem[] = [
  { path: '/', icon: 'home', labelKey: 'sidebar.home' },
  { path: '/logs', icon: 'bar-chart', labelKey: 'sidebar.logs' },
  { path: '/model-monitor', icon: 'activity', labelKey: 'sidebar.modelMonitor' },
  { path: '/console', icon: 'terminal', labelKey: 'sidebar.console' },
  { path: '/keys', icon: 'key', labelKey: 'sidebar.keys' },
  { path: '/settings', icon: 'settings', labelKey: 'sidebar.settings' },
]

const currentPath = computed(() => route.path)

const navigate = (path: string) => {
  router.push(path)
}
</script>

<template>
  <nav class="mac-sidebar" :class="{ collapsed: isCollapsed && !isMobile }">
    <div class="sidebar-header">
      <span class="sidebar-title" v-if="!isCollapsed || isMobile">Code Switch R</span>
      <button class="collapse-btn" @click="toggleCollapse" :title="isCollapsed ? 'Expand' : 'Collapse'">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline v-if="isCollapsed" points="9 18 15 12 9 6"></polyline>
          <polyline v-else points="15 18 9 12 15 6"></polyline>
        </svg>
      </button>
    </div>

    <div class="nav-list">
      <button
        v-for="item in navItems"
        :key="item.path"
        class="nav-item"
        :class="{ active: currentPath === item.path }"
        :title="isCollapsed ? t(item.labelKey) : ''"
        @click="navigate(item.path)"
      >
        <!-- Home -->
        <svg v-if="item.icon === 'home'" class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path>
          <polyline points="9 22 9 12 15 12 15 22"></polyline>
        </svg>

        <!-- Bar Chart -->
        <svg v-else-if="item.icon === 'bar-chart'" class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <line x1="12" y1="20" x2="12" y2="10"></line>
          <line x1="18" y1="20" x2="18" y2="4"></line>
          <line x1="6" y1="20" x2="6" y2="16"></line>
        </svg>

        <!-- Activity -->
        <svg v-else-if="item.icon === 'activity'" class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
        </svg>

        <!-- Terminal -->
        <svg v-else-if="item.icon === 'terminal'" class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="4 17 10 11 4 5"></polyline>
          <line x1="12" y1="19" x2="20" y2="19"></line>
        </svg>

        <!-- Key -->
        <svg v-else-if="item.icon === 'key'" class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="7.5" cy="14.5" r="3.5"></circle>
          <path d="M10 12l8-8"></path>
          <path d="M15 5l3 3"></path>
          <path d="M13 7l2 2"></path>
        </svg>

        <!-- Settings -->
        <svg v-else-if="item.icon === 'settings'" class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="12" cy="12" r="3"></circle>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
        </svg>

        <span class="nav-label" v-if="!isCollapsed || isMobile">{{ t(item.labelKey) }}</span>
      </button>
    </div>

    <div class="sidebar-footer" v-if="!isCollapsed && !isMobile">
      <span class="version">{{ appVersion }}</span>
    </div>
  </nav>
</template>

<style scoped>
.mac-sidebar {
  width: 200px;
  min-width: 200px;
  background: var(--mac-surface);
  border-right: 1px solid var(--mac-border);
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
  transition: width 0.2s ease, min-width 0.2s ease;
}

.mac-sidebar.collapsed {
  width: 48px;
  min-width: 48px;
}

.sidebar-header {
  /* macOS 红绿灯按钮区域约 52px 高，添加额外 padding */
  padding: 52px 16px 16px;
  border-bottom: 1px solid var(--mac-border);
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  align-items: center;
  justify-items: center;
  gap: 8px;
  /* 拖拽区域 */
  -webkit-app-region: drag;
}

.sidebar-header * {
  /* 按钮等元素需要可点击 */
  -webkit-app-region: no-drag;
}

.mac-sidebar.collapsed .sidebar-header {
  padding: 52px 0 16px;
  grid-template-columns: 1fr;
  justify-items: center;
}

.sidebar-title {
  font-size: 1.1rem;
  font-weight: 700;
  color: var(--mac-text);
  letter-spacing: -0.02em;
  white-space: nowrap;
  overflow: hidden;
  grid-column: 2;
  justify-self: center;
}

.collapse-btn {
  width: 28px;
  height: 28px;
  border: none;
  background: transparent;
  border-radius: 6px;
  color: var(--mac-text-secondary);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: all 0.15s ease;
  flex-shrink: 0;
  grid-column: 3;
  justify-self: end;
}

.mac-sidebar.collapsed .collapse-btn {
  grid-column: 1;
  justify-self: center;
}

.collapse-btn:hover {
  background: rgba(15, 23, 42, 0.06);
  color: var(--mac-text);
}

html.dark .collapse-btn:hover {
  background: rgba(255, 255, 255, 0.08);
}

.collapse-btn svg {
  width: 16px;
  height: 16px;
}

.nav-list {
  flex: 1;
  padding: 12px 8px;
  display: flex;
  flex-direction: column;
  gap: 2px;
  overflow-y: auto;
  scrollbar-width: none; /* Firefox 隐藏滚动条但保留滚动 */
  -ms-overflow-style: none; /* IE/Edge Legacy 隐藏滚动条 */
}

.nav-list::-webkit-scrollbar {
  display: none; /* WebKit 隐藏滚动条 */
}

.mac-sidebar.collapsed .nav-list {
  padding: 12px 0;
  align-items: center;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: 8px;
  border: none;
  background: transparent;
  color: var(--mac-text-secondary);
  font-size: 0.9rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.15s ease;
  /* 横向留出缓冲，避免被父级 overflow 裁切圆角 */
  box-sizing: border-box;
  width: calc(100% - 8px);
  margin: 0 4px;
  text-align: left;
}

.mac-sidebar.collapsed .nav-item {
  /* 收起态固定宽度，确保图标居中 */
  width: 36px;
  margin: 0 auto;
  padding: 10px 0;
  justify-content: center;
}

.nav-item:hover {
  background: rgba(15, 23, 42, 0.06);
  color: var(--mac-text);
}

html.dark .nav-item:hover {
  background: rgba(255, 255, 255, 0.08);
}

.nav-item.active {
  background: var(--mac-accent);
  color: #fff;
}

.nav-item.active:hover {
  background: var(--mac-accent);
  color: #fff;
}

.nav-icon {
  width: 18px;
  height: 18px;
  flex-shrink: 0;
}

.nav-label {
  flex: 1;
}

.sidebar-footer {
  padding: 12px 16px;
  border-top: 1px solid var(--mac-border);
}

.version {
  font-size: 0.75rem;
  color: var(--mac-text-secondary);
  opacity: 0.6;
}

@media (max-width: 760px) {
  .mac-sidebar,
  .mac-sidebar.collapsed {
    position: fixed;
    left: 0;
    right: 0;
    bottom: 0;
    z-index: 1200;
    width: 100%;
    min-width: 0;
    height: calc(64px + env(safe-area-inset-bottom));
    border-right: none;
    border-top: 1px solid var(--mac-border);
    background: color-mix(in srgb, var(--mac-surface) 92%, transparent);
    backdrop-filter: blur(18px);
    flex-direction: row;
    align-items: stretch;
    box-sizing: border-box;
    overflow: hidden;
  }

  .sidebar-header {
    display: none;
  }

  .nav-list,
  .mac-sidebar.collapsed .nav-list {
    flex: 1;
    height: 100%;
    min-width: 0;
    padding: 6px 6px calc(6px + env(safe-area-inset-bottom));
    flex-direction: row;
    align-items: stretch;
    justify-content: space-around;
    gap: 4px;
    overflow: hidden;
  }

  .nav-item,
  .mac-sidebar.collapsed .nav-item {
    width: auto;
    min-width: 0;
    flex: 1 1 0;
    margin: 0;
    padding: 6px 2px;
    flex-direction: column;
    justify-content: center;
    gap: 3px;
    border-radius: 10px;
  }

  .nav-icon {
    width: 18px;
    height: 18px;
  }

  .nav-label {
    flex: 0 1 auto;
    width: 100%;
    font-size: 11px;
    line-height: 1.1;
    text-align: center;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
}
</style>
