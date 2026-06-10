package services

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// EnvConflict 环境变量冲突
type EnvConflict struct {
	VarName    string `json:"varName"`    // 变量名
	VarValue   string `json:"varValue"`   // 变量值
	SourceType string `json:"sourceType"` // 来源类型: "system" | "file"
	SourcePath string `json:"sourcePath"` // 来源路径
}

// EnvCheckService 环境变量检测服务
type EnvCheckService struct{}

// NewEnvCheckService 创建环境变量检测服务
func NewEnvCheckService() *EnvCheckService {
	return &EnvCheckService{}
}

// Start Wails生命周期方法
func (s *EnvCheckService) Start() error {
	return nil
}

// Stop Wails生命周期方法
func (s *EnvCheckService) Stop() error {
	return nil
}

// CheckEnvConflicts 检查指定平台的环境变量冲突
func (s *EnvCheckService) CheckEnvConflicts(app string) ([]EnvConflict, error) {
	keywords := s.getKeywordsForApp(app)
	if len(keywords) == 0 {
		return []EnvConflict{}, nil
	}

	var conflicts []EnvConflict

	// 检查系统环境变量
	systemConflicts := s.checkSystemEnv(keywords)
	conflicts = append(conflicts, systemConflicts...)

	// 检查 Shell 配置文件（仅 Unix/Mac）
	if runtime.GOOS != "windows" {
		shellConflicts, err := s.checkShellConfigs(keywords)
		if err == nil {
			conflicts = append(conflicts, shellConflicts...)
		}
	}

	return conflicts, nil
}

// getKeywordsForApp 获取平台相关的关键词
func (s *EnvCheckService) getKeywordsForApp(app string) []string {
	switch strings.ToLower(app) {
	case "claude":
		return []string{"ANTHROPIC"}
	case "openai-responses", "openai-chat":
		return []string{"OPENAI"}
	case "gemini":
		return []string{"GEMINI", "GOOGLE_GEMINI"}
	default:
		return []string{}
	}
}

// checkSystemEnv 检查系统环境变量
func (s *EnvCheckService) checkSystemEnv(keywords []string) []EnvConflict {
	var conflicts []EnvConflict

	// 遍历所有环境变量
	for _, env := range os.Environ() {
		// 分割为 key=value
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		// 检查是否包含关键词
		upperKey := strings.ToUpper(key)
		for _, keyword := range keywords {
			if strings.Contains(upperKey, keyword) {
				conflicts = append(conflicts, EnvConflict{
					VarName:    key,
					VarValue:   value,
					SourceType: "system",
					SourcePath: "Process Environment",
				})
				break
			}
		}
	}

	return conflicts
}

// checkShellConfigs 检查 Shell 配置文件（Unix/Mac）
func (s *EnvCheckService) checkShellConfigs(keywords []string) ([]EnvConflict, error) {
	var conflicts []EnvConflict

	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp"
	}

	// 常见的 Shell 配置文件
	configFiles := []string{
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".profile"),
		"/etc/profile",
		"/etc/bashrc",
	}

	for _, filePath := range configFiles {
		fileConflicts, err := s.checkFile(filePath, keywords)
		if err == nil {
			conflicts = append(conflicts, fileConflicts...)
		}
	}

	return conflicts, nil
}

// checkFile 检查单个配置文件
func (s *EnvCheckService) checkFile(filePath string, keywords []string) ([]EnvConflict, error) {
	var conflicts []EnvConflict

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// 跳过注释行
		if strings.HasPrefix(line, "#") {
			continue
		}

		// 匹配 export VAR=value 或 VAR=value
		var varLine string
		if strings.HasPrefix(line, "export ") {
			varLine = strings.TrimPrefix(line, "export ")
		} else if strings.Contains(line, "=") {
			varLine = line
		} else {
			continue
		}

		// 解析变量名和值
		eqPos := strings.Index(varLine, "=")
		if eqPos <= 0 {
			continue
		}

		varName := strings.TrimSpace(varLine[:eqPos])
		varValue := strings.TrimSpace(varLine[eqPos+1:])

		// 移除引号
		varValue = strings.Trim(varValue, `"'`)

		// 检查是否包含关键词
		upperName := strings.ToUpper(varName)
		for _, keyword := range keywords {
			if strings.Contains(upperName, keyword) {
				conflicts = append(conflicts, EnvConflict{
					VarName:    varName,
					VarValue:   varValue,
					SourceType: "file",
					SourcePath: fmt.Sprintf("%s:%d", filePath, lineNum),
				})
				break
			}
		}
	}

	return conflicts, scanner.Err()
}
