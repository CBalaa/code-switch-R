package services

import (
	"fmt"
	"strconv"

	"github.com/daodao97/xgo/xdb"
)

// SettingsService 管理全局配置
type SettingsService struct{}

func NewSettingsService() *SettingsService {
	if err := ensureAppSettingsTable(); err != nil {
		fmt.Printf("[SettingsService] 初始化数据库表失败: %v\n", err)
	}
	return &SettingsService{}
}

// GetIntSetting 获取整数类型的配置值（通用方法）
// 如果找不到或解析失败，返回 0
func (ss *SettingsService) GetIntSetting(key string) int {
	db, err := xdb.DB("default")
	if err != nil {
		return 0
	}

	var valueStr string
	err = db.QueryRow(`SELECT value FROM app_settings WHERE key = ?`, key).Scan(&valueStr)
	if err != nil {
		return 0
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0
	}

	return value
}

// SetIntSetting 设置整数类型的配置值（通用方法）
func (ss *SettingsService) SetIntSetting(key string, value int) error {
	err := GlobalDBQueue.Exec(`
		INSERT INTO app_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, strconv.Itoa(value))

	if err != nil {
		return fmt.Errorf("设置 %s 失败: %w", key, err)
	}

	return nil
}
