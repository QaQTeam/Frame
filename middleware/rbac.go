package middleware

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

var enforcer *casbin.Enforcer

func InitCasbin(db *gorm.DB) error {
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return err
	}

	enforcer, err = casbin.NewEnforcer("config/rbac_model.conf", adapter)
	if err != nil {
		return err
	}

	// 加载策略
	if err := enforcer.LoadPolicy(); err != nil {
		return err
	}

	// 添加默认策略
	_, err = enforcer.AddPolicy("admin", "/admin/*", "(GET)|(POST)|(PUT)|(DELETE)")
	if err != nil {
		return err
	}

	_, err = enforcer.AddPolicy("admin", "/products*", "(GET)|(POST)|(PUT)|(DELETE)")
	if err != nil {
		return err
	}

	_, err = enforcer.AddPolicy("user", "/products*", "GET")
	if err != nil {
		return err
	}

	_, err = enforcer.AddPolicy("admin", "/users*", "(GET)|(POST)|(PUT)|(DELETE)")
	if err != nil {
		return err
	}

	return nil
}

func RBACMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未找到用户角色信息"})
			c.Abort()
			return
		}

		roleName := role.(string)
		path := c.Request.URL.Path
		method := c.Request.Method

		// 检查权限
		ok, err := enforcer.Enforce(roleName, path, method)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "权限检查失败"})
			c.Abort()
			return
		}

		if !ok {
			c.JSON(http.StatusForbidden, gin.H{"error": "没有权限访问该资源"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func UpdateUserRole(userID uint64, newRole string) error {
	// 删除旧的角色
	_, err := enforcer.DeleteRolesForUser(string(userID))
	if err != nil {
		return err
	}

	// 添加新的角色
	_, err = enforcer.AddRoleForUser(string(userID), newRole)
	if err != nil {
		return err
	}

	return nil
}
