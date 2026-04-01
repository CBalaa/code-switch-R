<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted } from 'vue'
import { RouterView, useRoute } from 'vue-router'
import AdminAccessGate from './components/Auth/AdminAccessGate.vue'
import Sidebar from './components/Sidebar.vue'
import UpdateNotification from './components/common/UpdateNotification.vue'
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
  <AdminAccessGate v-if="!canRenderApp" />
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
    <UpdateNotification />
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
}
</style>
