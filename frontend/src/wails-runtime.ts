export type CancellablePromise<T> = Promise<T>

export type WailsEvent<T = any> = {
  name: string
  data: T
  sender?: string
}

type RPCSuccess<T = any> = {
  data: T
}

type RPCError = {
  error?: {
    code?: string
    message?: string
  }
}

let sharedEventSource: EventSource | null = null

function notifyAdminAuthInvalid() {
  window.dispatchEvent(new Event('codeswitch-admin-auth-invalid'))
}

async function rpcCall<T>(name: string, args: any[]): Promise<T> {
  const response = await fetch('/api/wails/call', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name, args }),
  })

  const payload = await response.json().catch(() => ({})) as RPCSuccess<T> & RPCError
  if (!response.ok) {
    if (response.status === 401) {
      notifyAdminAuthInvalid()
    }
    const message = payload?.error?.message || `RPC failed with status ${response.status}`
    throw new Error(message)
  }

  return payload.data as T
}

function ensureEventSource(): EventSource {
  if (!sharedEventSource) {
    sharedEventSource = new EventSource('/api/wails/events')
    sharedEventSource.onerror = () => {
      if (sharedEventSource?.readyState === EventSource.CLOSED) {
        sharedEventSource = null
      }
    }
  }
  return sharedEventSource
}

export function resetEventSource() {
  if (!sharedEventSource) {
    return
  }
  sharedEventSource.close()
  sharedEventSource = null
}

export namespace Call {
  export function ByName<T = any>(name: string, ...args: any[]): CancellablePromise<T> {
    return rpcCall<T>(name, args)
  }

  export function ByID<T = any>(id: number, ..._args: any[]): CancellablePromise<T> {
    return Promise.reject(new Error(`Call.ByID(${id}) is not available in the web runtime`))
  }
}

export namespace Browser {
  export function OpenURL(url: string): CancellablePromise<void> {
    try {
      const opened = window.open(url, '_blank', 'noopener,noreferrer')
      if (!opened) {
        window.location.href = url
      }
      return Promise.resolve()
    } catch (error) {
      return Promise.reject(error)
    }
  }
}

export namespace Events {
  export type Callback<T = any> = (event: WailsEvent<T>) => void

  export function On<T = any>(name: string, callback: Callback<T>): () => void {
    const source = ensureEventSource()
    const handler = (event: MessageEvent<string>) => {
      let data: T
      try {
        data = JSON.parse(event.data) as T
      } catch {
        data = event.data as T
      }
      callback({ name, data })
    }
    source.addEventListener(name, handler as EventListener)
    return () => {
      source.removeEventListener(name, handler as EventListener)
    }
  }
}

type Creator<T = any> = (source: any) => T

export const Create = {
  Any(source: any) {
    return source
  },
  Array<T>(creator: Creator<T>) {
    return (source: any): T[] => {
      if (!Array.isArray(source)) {
        return []
      }
      return source.map((item) => creator(item))
    }
  },
  Map<K = any, V = any>(_keyCreator: Creator<K>, valueCreator: Creator<V>) {
    return (source: any): Record<string, V> => {
      if (!source || typeof source !== 'object') {
        return {}
      }
      return Object.fromEntries(
        Object.entries(source).map(([key, value]) => [key, valueCreator(value)])
      )
    }
  },
  Nullable<T>(creator: Creator<T>) {
    return (source: any): T | null => {
      if (source === null || source === undefined) {
        return null
      }
      return creator(source)
    }
  },
  Events: {},
}
