type ToastType = 'success' | 'error' | 'warning'

const TOAST_DURATION = 2400
/** Fallback removal if the CSS transition never fires (hidden tab, reduced motion). */
const TOAST_REMOVE_FALLBACK = TOAST_DURATION + 600

let toastContainer: HTMLElement | null = null

function getContainer() {
  if (toastContainer) return toastContainer

  toastContainer = document.createElement('div')
  toastContainer.className = 'mac-toast-container'
  // Screen readers and automation must be able to observe the only completion
  // signal the app has. Success/warning are polite; errors are assertive.
  toastContainer.setAttribute('aria-live', 'polite')
  toastContainer.setAttribute('aria-atomic', 'false')
  toastContainer.setAttribute('data-testid', 'toast-container')
  document.body.appendChild(toastContainer)
  return toastContainer
}

export function showToast(message: string, type: ToastType = 'success') {
  if (!message) return

  const container = getContainer()
  const toast = document.createElement('div')
  toast.className = `mac-toast mac-toast-${type}`
  toast.textContent = message
  // Stable hooks for automation: role, type, lifecycle state and test id.
  toast.setAttribute('role', type === 'error' ? 'alert' : 'status')
  toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite')
  toast.setAttribute('data-testid', 'toast-item')
  toast.setAttribute('data-toast-type', type)
  toast.setAttribute('data-state', 'visible')

  container.appendChild(toast)

  requestAnimationFrame(() => {
    toast.classList.add('mac-toast-visible')
  })

  let removed = false
  const remove = () => {
    if (removed) return
    removed = true
    toast.setAttribute('data-state', 'leaving')
    toast.classList.remove('mac-toast-visible')
    toast.classList.add('mac-toast-hide')
    const handler = () => {
      toast.removeEventListener('transitionend', handler)
      toast.remove()
      if (toastContainer && toastContainer.childElementCount === 0) {
        toastContainer.remove()
        toastContainer = null
      }
    }
    toast.addEventListener('transitionend', handler)
    // transitionend never fires when the tab is hidden or transitions are
    // disabled; keep the DOM deterministic for tests either way.
    setTimeout(handler, TOAST_REMOVE_FALLBACK)
  }

  setTimeout(remove, TOAST_DURATION)
}
