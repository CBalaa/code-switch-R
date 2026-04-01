package main

import (
	"codeswitch/services"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const adminSessionCookieName = "code_switch_admin_session"

type adminLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type adminInitializeRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type adminUpdateCredentialsRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewUsername     string `json:"newUsername"`
	NewPassword     string `json:"newPassword"`
}

type codexRelayKeyCreateRequest struct {
	Name string `json:"name"`
}

func registerAdminAuthRoutes(router *gin.Engine, rt *appRuntime) {
	authRequired := requireAdminSession(rt.adminAuth)

	router.GET("/api/admin/status", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		status, err := rt.adminAuth.GetStatus(adminSessionTokenFromRequest(c.Request))
		if err != nil {
			c.JSON(http.StatusInternalServerError, apiErrorResponse{
				Error: apiError{Code: "status_failed", Message: err.Error()},
			})
			return
		}
		c.JSON(http.StatusOK, status)
	})

	router.POST("/api/admin/initialize", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var request adminInitializeRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "invalid_request", Message: err.Error()},
			})
			return
		}

		token, status, err := rt.adminAuth.InitializeAdmin(request.Username, request.Password)
		if err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "initialize_failed", Message: err.Error()},
			})
			return
		}

		setAdminSessionCookie(c, token)
		c.JSON(http.StatusOK, status)
	})

	router.POST("/api/admin/login", func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var request adminLoginRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "invalid_request", Message: err.Error()},
			})
			return
		}

		token, status, err := rt.adminAuth.Login(request.Username, request.Password)
		if err != nil {
			c.JSON(http.StatusUnauthorized, apiErrorResponse{
				Error: apiError{Code: "login_failed", Message: err.Error()},
			})
			return
		}

		setAdminSessionCookie(c, token)
		c.JSON(http.StatusOK, status)
	})

	router.POST("/api/admin/logout", authRequired, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		clearAdminSessionCookie(c)
		c.Status(http.StatusNoContent)
	})

	router.POST("/api/admin/credentials", authRequired, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var request adminUpdateCredentialsRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "invalid_request", Message: err.Error()},
			})
			return
		}

		token, status, err := rt.adminAuth.UpdateCredentials(
			request.CurrentPassword,
			request.NewUsername,
			request.NewPassword,
		)
		if err != nil {
			statusCode := http.StatusBadRequest
			if strings.Contains(err.Error(), "当前密码错误") {
				statusCode = http.StatusUnauthorized
			}
			c.JSON(statusCode, apiErrorResponse{
				Error: apiError{Code: "update_credentials_failed", Message: err.Error()},
			})
			return
		}

		setAdminSessionCookie(c, token)
		c.JSON(http.StatusOK, status)
	})

	router.GET("/api/admin/codex-keys", authRequired, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		keys, err := rt.codexRelayKeys.ListKeys()
		if err != nil {
			c.JSON(http.StatusInternalServerError, apiErrorResponse{
				Error: apiError{Code: "list_keys_failed", Message: err.Error()},
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"keys": keys})
	})

	router.POST("/api/admin/codex-keys", authRequired, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		var request codexRelayKeyCreateRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "invalid_request", Message: err.Error()},
			})
			return
		}

		result, err := rt.codexRelayKeys.CreateKey(request.Name)
		if err != nil {
			c.JSON(http.StatusBadRequest, apiErrorResponse{
				Error: apiError{Code: "create_key_failed", Message: err.Error()},
			})
			return
		}
		c.JSON(http.StatusOK, result)
	})

	router.GET("/api/admin/codex-keys/:id/secret", authRequired, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		secret, err := rt.codexRelayKeys.GetKeySecret(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusNotFound, apiErrorResponse{
				Error: apiError{Code: "key_not_found", Message: err.Error()},
			})
			return
		}
		c.JSON(http.StatusOK, gin.H{"key": secret})
	})

	router.DELETE("/api/admin/codex-keys/:id", authRequired, func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		if err := rt.codexRelayKeys.DeleteKey(c.Param("id")); err != nil {
			statusCode := http.StatusBadRequest
			if strings.Contains(err.Error(), "未找到") {
				statusCode = http.StatusNotFound
			}
			c.JSON(statusCode, apiErrorResponse{
				Error: apiError{Code: "delete_key_failed", Message: err.Error()},
			})
			return
		}
		if err := refreshCodexProxyKey(rt); err != nil {
			c.JSON(http.StatusInternalServerError, apiErrorResponse{
				Error: apiError{Code: "refresh_codex_key_failed", Message: err.Error()},
			})
			return
		}
		c.Status(http.StatusNoContent)
	})
}

func requireAdminSession(authService *services.AdminAuthService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if authService == nil {
			c.JSON(http.StatusInternalServerError, apiErrorResponse{
				Error: apiError{Code: "auth_unavailable", Message: "admin auth service is unavailable"},
			})
			c.Abort()
			return
		}

		username, ok, err := authService.ValidateSession(adminSessionTokenFromRequest(c.Request))
		if err != nil {
			c.JSON(http.StatusInternalServerError, apiErrorResponse{
				Error: apiError{Code: "auth_failed", Message: err.Error()},
			})
			c.Abort()
			return
		}
		if !ok {
			c.JSON(http.StatusUnauthorized, apiErrorResponse{
				Error: apiError{Code: "unauthorized", Message: "admin login required"},
			})
			c.Abort()
			return
		}

		c.Set("admin_username", username)
		c.Next()
	}
}

func adminSessionTokenFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie.Value)
}

func setAdminSessionCookie(c *gin.Context, token string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(services.AdminSessionTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearAdminSessionCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
}

func refreshCodexProxyKey(rt *appRuntime) error {
	if rt == nil || rt.codexSettings == nil {
		return nil
	}

	status, err := rt.codexSettings.ProxyStatus()
	if err != nil {
		return err
	}
	if !status.Enabled {
		return nil
	}

	if err := rt.codexSettings.EnableProxy(); err != nil {
		return err
	}
	return nil
}
