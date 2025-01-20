package jobs

import (
	"log"
	"time"

	"gorm.io/gorm"

	"qaqmall/models"
)

// OrderJobs 订单相关的定时任务
type OrderJobs struct {
	db *gorm.DB
}

func NewOrderJobs(db *gorm.DB) *OrderJobs {
	return &OrderJobs{db: db}
}

// CancelExpiredOrders 取消过期订单
func (j *OrderJobs) CancelExpiredOrders() {
	// 查找过期的待支付订单
	var orders []models.Order
	if err := j.db.Where("status = ? AND expired_at < ?", models.OrderStatusPending, time.Now()).
		Preload("Items").Find(&orders).Error; err != nil {
		log.Printf("查询过期订单失败: %v", err)
		return
	}

	for _, order := range orders {
		// 开始事务
		tx := j.db.Begin()

		// 更新订单状态为已取消
		if err := tx.Model(&order).Update("status", models.OrderStatusCancelled).Error; err != nil {
			tx.Rollback()
			log.Printf("取消订单 %s 失败: %v", order.OrderNumber, err)
			continue
		}

		// 恢复商品库存
		for _, item := range order.Items {
			if err := tx.Model(&models.Product{}).Where("id = ?", item.ProductID).
				UpdateColumn("stock", gorm.Expr("stock + ?", item.Quantity)).Error; err != nil {
				tx.Rollback()
				log.Printf("恢复订单 %s 商品库存失败: %v", order.OrderNumber, err)
				continue
			}
		}

		// 提交事务
		if err := tx.Commit().Error; err != nil {
			log.Printf("提交订单 %s 取消事务失败: %v", order.OrderNumber, err)
			continue
		}

		log.Printf("成功取消过期订单: %s", order.OrderNumber)
	}
}
