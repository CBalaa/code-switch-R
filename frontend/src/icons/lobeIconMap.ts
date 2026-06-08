import fallbackIcons from './fallbackLobeIcons'

const globIcons = import.meta.glob('../../node_modules/@lobehub/icons-static-svg/icons/*.svg', {
  import: 'default',
  query: '?raw',
}) as Record<string, () => Promise<string>>

const normalizeFallback = (source: Record<string, string>) => {
  return Object.entries(source).reduce<Record<string, string>>((acc, [key, value]) => {
    acc[key.toLowerCase()] = value
    return acc
  }, {})
}

const normalizeLoaders = (source: Record<string, () => Promise<string>>) => {
  return Object.entries(source).reduce<Record<string, () => Promise<string>>>((acc, [key, loader]) => {
    const name = key
      .split('/')
      .pop()
      ?.replace('.svg', '')
      ?.toLowerCase()
    if (name) {
      acc[name] = loader
    }
    return acc
  }, {})
}

export const fallbackIconMap = normalizeFallback(fallbackIcons)

const lobeIconLoaders = normalizeLoaders(globIcons)

export const iconNames = Array.from(
  new Set([...Object.keys(fallbackIconMap), ...Object.keys(lobeIconLoaders)]),
).sort((a, b) => a.localeCompare(b))

export const loadLobeIcon = async (name: string) => {
  const normalized = name.trim().toLowerCase()
  if (!normalized) return ''
  if (fallbackIconMap[normalized]) {
    return fallbackIconMap[normalized]
  }
  const loader = lobeIconLoaders[normalized]
  if (!loader) return ''
  return loader()
}
