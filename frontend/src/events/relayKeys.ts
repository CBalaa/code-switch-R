export const RELAY_KEYS_UPDATED_EVENT = 'relay-keys-updated'

export const notifyRelayKeysUpdated = () => {
  window.dispatchEvent(new CustomEvent(RELAY_KEYS_UPDATED_EVENT))
}
