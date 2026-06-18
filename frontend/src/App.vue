<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from 'vue'
import { RouterView, useRoute } from 'vue-router'
import AdminAccessGate from './components/Auth/AdminAccessGate.vue'
import Sidebar from './components/Sidebar.vue'
import { refreshAdminAuthStatus, useAdminAuthState } from './services/adminAuth'

const applyTheme = () => {
  const userTheme = localStorage.getItem('theme')
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches

  const isDark = userTheme === 'dark' || (!userTheme && systemPrefersDark)

  document.documentElement.classList.toggle('dark', isDark)
}

const authState = useAdminAuthState()
const route = useRoute()
const isTray = computed(() => route.path === '/tray')
const isCheckingAuth = computed(() => !authState.ready)
const canRenderApp = computed(() => authState.ready && authState.authenticated)

let mediaQuery: MediaQueryList | null = null
let handleThemeChange: (() => void) | null = null
let handleWindowFocus: (() => void) | null = null

onMounted(() => {
  applyTheme()
  refreshAdminAuthStatus().catch((error) => {
    console.error('failed to refresh admin auth status', error)
  })

  mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')
  handleThemeChange = () => {
    applyTheme()
  }
  mediaQuery.addEventListener('change', handleThemeChange)

  handleWindowFocus = () => {
    refreshAdminAuthStatus(true).catch((error) => {
      console.error('failed to refresh admin auth status', error)
    })
  }
  window.addEventListener('focus', handleWindowFocus)
})

onBeforeUnmount(() => {
  if (mediaQuery && handleThemeChange) {
    mediaQuery.removeEventListener('change', handleThemeChange)
  }
  if (handleWindowFocus) {
    window.removeEventListener('focus', handleWindowFocus)
  }
})
</script>

<template>
  <div v-if="isCheckingAuth" class="app-auth-loading" aria-live="polite">
    <span class="app-auth-spinner" aria-hidden="true"></span>
  </div>
  <AdminAccessGate v-else-if="!canRenderApp" />
  <div v-else-if="isTray" class="tray-layout">
    <RouterView v-slot="{ Component }">
      <component :is="Component" />
    </RouterView>
  </div>
  <div v-else class="app-layout">
    <Sidebar />
    <main class="main-content">
      <RouterView v-slot="{ Component }">
        <keep-alive>
          <component :is="Component" />
        </keep-alive>
      </RouterView>
    </main>
  </div>
</template>

<style scoped>
.tray-layout {
  width: 100vw;
  height: 100vh;
  overflow: hidden;
}

.app-layout {
  display: flex;
  height: 100vh;
  width: 100vw;
  overflow: hidden;
  background: var(--app-background);
}

.main-content {
  flex: 1;
  overflow-y: auto;
  background: var(--mac-bg);
  min-width: 0;
}

.app-auth-loading {
  width: 100vw;
  height: 100vh;
  display: grid;
  place-items: center;
  background: var(--app-background);
}

.app-auth-spinner {
  width: 28px;
  height: 28px;
  border-radius: 999px;
  border: 3px solid color-mix(in srgb, var(--mac-accent) 16%, transparent);
  border-top-color: var(--mac-accent);
  animation: app-auth-spin 0.9s linear infinite;
}

@keyframes app-auth-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 760px) {
  .app-layout {
    display: block;
    height: 100dvh;
    overflow: hidden;
  }

  .main-content {
    height: 100dvh;
    padding-bottom: 72px;
    box-sizing: border-box;
    -webkit-overflow-scrolling: touch;
  }
}
</style>
