<template>
  <select
    class="mac-select"
    v-model="locale"
    aria-label="Language / 语言"
    data-testid="language-switcher"
    @change="switchLang"
  >
    <option value="zh">简体中文</option>
    <option value="en">English</option>
  </select>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { i18n, setupI18n } from '../../utils/i18n'
import { Locale } from '../../locales'

const locale = ref(i18n.global.locale.value)

const switchLang = async () => {
  await setupI18n(locale.value as Locale)
}
</script>
