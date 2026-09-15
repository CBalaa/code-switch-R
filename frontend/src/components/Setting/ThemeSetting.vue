<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { setTheme, getCurrentTheme, ThemeMode } from '../../utils/ThemeManager'

const themevalue = ref<ThemeMode>('light')

const themeChange = () => {
  setTheme(themevalue.value)
}

onMounted(() => {
  themevalue.value = getCurrentTheme()
})
</script>

<template>
  <select
    class="mac-select"
    v-model="themevalue"
    :aria-label="$t('components.themesetting.select.theme')"
    data-testid="theme-switcher"
    @change="themeChange"
  >
    <option value="light">{{ $t('components.themesetting.select.opt_light') }}</option>
    <option value="dark">{{ $t('components.themesetting.select.opt_dark') }}</option>
  </select>
</template>
