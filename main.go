package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
	"time"

	"qaqmall/handlers"
	"qaqmall/jobs"
	"qaqmall/middleware"
)

func main() {
	// 连接数据库
	dsn := "root:123456@tcp(127.0.0.1:3306)/qaqmall?charset=utf8mb4&parseTime=True&loc=Local"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect database:", err)
	}

	// 初始化 Casbin
	if err := middleware.InitCasbin(db); err != nil {
		log.Fatal("Failed to initialize Casbin:", err)
	}

	// 创建Gin引擎
	r := gin.New()

	// 添加中间件
	r.Use(middleware.Logger())
	r.Use(gin.Recovery())
	r.Use(middleware.CORS())

	// 健康检查
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
		})
	})

	// 初始化处理器
	userHandler := handlers.NewUserHandler(db)
	productHandler := handlers.NewProductHandler(db)
	cartHandler := handlers.NewCartHandler(db)
	addressHandler := handlers.NewAddressHandler(db)
	orderHandler := handlers.NewOrderHandler(db)

	// 定义 context.Context 变量
	ctx := context.Background()
	paymentHandler := handlers.NewPayHandler(db, ctx)
	aiQueryHandler := handlers.NewAIQueryHandler(db)

	// 初始化定时任务
	orderJobs := jobs.NewOrderJobs(db)

	// 启动定时任务
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		for range ticker.C {
			orderJobs.CancelExpiredOrders()
		}
	}()

	// 用户相关路由
	r.POST("/register", userHandler.Register)
	r.POST("/login", userHandler.Login)

	// 需要认证的路由组
	auth := r.Group("/")
	auth.Use(middleware.Auth(db))
	{
		// 用户管理
		auth.POST("/logout", userHandler.Logout)
		auth.GET("/user/info", userHandler.GetUserInfo)
		auth.PUT("/user/info", userHandler.UpdateUserInfo)
		auth.DELETE("/user", userHandler.DeleteUser)

		// 购物车管理
		auth.GET("/cart/items", cartHandler.ListCart)
		auth.POST("/cart/items", cartHandler.AddToCart)
		auth.PUT("/cart/items/:id", cartHandler.UpdateCartItem)
		auth.DELETE("/cart/items/:id", cartHandler.RemoveFromCart)
		auth.DELETE("/cart/items", cartHandler.EmptyCart)

		// 地址管理
		auth.GET("/addresses", addressHandler.ListAddresses)
		auth.POST("/addresses", addressHandler.CreateAddress)
		auth.PUT("/addresses/:id", addressHandler.UpdateAddress)
		auth.DELETE("/addresses/:id", addressHandler.DeleteAddress)

		// 订单管理
		auth.POST("/orders", orderHandler.CreateOrder)
		auth.GET("/orders", orderHandler.GetOrders)
		auth.GET("/orders/:id", orderHandler.GetOrder)
		auth.PUT("/orders/:id", orderHandler.UpdateOrder)
		auth.POST("/orders/:id/cancel", orderHandler.CancelOrder)

		// 支付管理
		auth.POST("/payments", paymentHandler.Charge)        // 支付接口
		auth.GET("/payments/:id", paymentHandler.GetPayment) // 更具用户id和支付状态查询记录

		// AI 查询
		auth.POST("/ai/query", aiQueryHandler.Query)
	}

	// 需要管理员权限的路由组
	admin := auth.Group("/admin")
	admin.Use(middleware.RBACMiddleware())
	{
		// 商品管理
		admin.POST("/products", productHandler.CreateProduct)
		admin.PUT("/products/:id", productHandler.UpdateProduct)
		admin.DELETE("/products/:id", productHandler.DeleteProduct)
	}

	// 不需要认证的路由
	r.GET("/products", productHandler.ListProducts)

	// 支付回调接口（不需要认证）
	r.POST("/payments/callback", func(c *gin.Context) {
		paymentHandler.AlipayNotify(c.Writer, c.Request)
	}) // 支付宝回调接口
	r.POST("/payments/wechat/callback", func(c *gin.Context) {
		handlers.WxPayNotify(c.Writer, c.Request)
	}) // 微信支付回调接口

	// 启动服务器
	if err := r.Run(":8888"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
