import { Call } from '@wailsio/runtime'

export type AppSettings = {
  show_home_title: boolean
  auto_start: boolean
  auto_connectivity_test: boolean
  enable_switch_notify: boolean // 供应商切换通知开关
  enable_codex_stream_guard: boolean // Codex 流式空响应保护
}

const DEFAULT_SETTINGS: AppSettings = {
  show_home_title: true,
  auto_start: false,
  auto_connectivity_test: false,
  enable_switch_notify: true,  // 默认开启
  enable_codex_stream_guard: true,
}

export const fetchAppSettings = async (): Promise<AppSettings> => {
  const data = await Call.ByName('codeswitch/services.AppSettingsService.GetAppSettings')
  return data ?? DEFAULT_SETTINGS
}

export const saveAppSettings = async (settings: AppSettings): Promise<AppSettings> => {
  return Call.ByName('codeswitch/services.AppSettingsService.SaveAppSettings', settings)
}
