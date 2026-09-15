<template>
  <TransitionRoot as="template" :show="open">
    <Dialog as="div" class="modal-backdrop" :open="open" :data-testid="testId" @close="$emit('close')">
      <div class="modal-overlay" aria-hidden="true" data-testid="modal-overlay"></div>
      <div class="modal-wrapper">
        <TransitionChild
          as="template"
          enter="ease-out duration-200"
          enter-from="opacity-0 translate-y-4"
          enter-to="opacity-100 translate-y-0"
          leave="ease-in duration-150"
          leave-from="opacity-100 translate-y-0"
          leave-to="opacity-0 translate-y-4"
        >
          <DialogPanel :class="['modal', variantClass, sizeClass]" data-testid="modal-panel">
            <header class="modal-header">
              <DialogTitle class="modal-title">{{ title }}</DialogTitle>
              <button
                type="button"
                class="ghost-icon"
                :aria-label="t('common.close')"
                data-testid="modal-close"
                @click="$emit('close')"
              >✕</button>
            </header>
            <div class="modal-body modal-scrollable">
              <slot />
            </div>
          </DialogPanel>
        </TransitionChild>
      </div>
    </Dialog>
  </TransitionRoot>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { Dialog, DialogPanel, DialogTitle, TransitionChild, TransitionRoot } from '@headlessui/vue'

type Variant = 'default' | 'confirm'
type Size = 'default' | 'wide'

const props = withDefaults(
  defineProps<{
    open: boolean
    title: string
    variant?: Variant
    size?: Size
    /** Stable automation hook for the dialog root. */
    testId?: string
  }>(),
  { variant: 'default', size: 'default', testId: 'app-modal' },
)

defineEmits<{ (e: 'close'): void }>()

const { t } = useI18n()

const variantClass = computed(() => (props.variant === 'confirm' ? 'confirm-modal' : ''))
const sizeClass = computed(() => (props.size === 'wide' ? 'modal-wide' : ''))
</script>
