package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "qaqmall/api/cart/v1"
)

func main() {
	// 连接 gRPC 服务器
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewCartServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 测试用户ID
	userID := uint64(1)

	// 1. 添加商品到购物车
	log.Println("=== 测试添加商品到购物车 ===")
	addResp, err := client.AddToCart(ctx, &pb.AddToCartRequest{
		UserId:    userID,
		ProductId: 3, // 使用 iPad Pro 的ID
		Quantity:  2,
	})
	if err != nil {
		log.Printf("添加商品失败: %v", err)
	} else {
		log.Printf("添加商品成功: ID=%d, 商品=%s, 数量=%d",
			addResp.Item.Id,
			addResp.Item.ProductName,
			addResp.Item.Quantity)
	}

	// 2. 获取购物车内容
	log.Println("\n=== 测试获取购物车内容 ===")
	cartResp, err := client.GetCart(ctx, &pb.GetCartRequest{
		UserId: userID,
	})
	if err != nil {
		log.Printf("获取购物车失败: %v", err)
	} else {
		log.Printf("购物车商品数量: %d", len(cartResp.Items))
		log.Printf("总价: %.2f", cartResp.TotalPrice)
		log.Printf("总数量: %d", cartResp.TotalQuantity)
		log.Printf("已选商品数量: %d", cartResp.SelectedQuantity)
		log.Printf("已选商品总价: %.2f", cartResp.SelectedPrice)
		for _, item := range cartResp.Items {
			log.Printf("- 商品: %s, 数量: %d, 价格: %.2f",
				item.ProductName,
				item.Quantity,
				item.Price)
		}
	}

	// 如果购物车有商品，继续测试其他功能
	if cartResp != nil && len(cartResp.Items) > 0 {
		// 3. 更新购物车商品
		log.Println("\n=== 测试更新购物车商品 ===")
		updateResp, err := client.UpdateCartItem(ctx, &pb.UpdateCartItemRequest{
			UserId:     userID,
			CartItemId: cartResp.Items[0].Id,
			Quantity:   3,
			Selected:   true,
		})
		if err != nil {
			log.Printf("更新商品失败: %v", err)
		} else {
			log.Printf("更新商品成功: ID=%d, 新数量=%d",
				updateResp.Item.Id,
				updateResp.Item.Quantity)
		}

		// 4. 获取购物车商品数量
		log.Println("\n=== 测试获取购物车商品数量 ===")
		countResp, err := client.GetCartItemCount(ctx, &pb.GetCartItemCountRequest{
			UserId: userID,
		})
		if err != nil {
			log.Printf("获取商品数量失败: %v", err)
		} else {
			log.Printf("购物车商品数量: %d", countResp.Count)
		}

		// 5. 删除购物车商品
		log.Println("\n=== 测试删除购物车商品 ===")
		removeResp, err := client.RemoveFromCart(ctx, &pb.RemoveFromCartRequest{
			UserId:     userID,
			CartItemId: cartResp.Items[0].Id,
		})
		if err != nil {
			log.Printf("删除商品失败: %v", err)
		} else {
			log.Printf("删除商品成功: %v, %s",
				removeResp.Success,
				removeResp.Message)
		}
	}

	// 6. 清空购物车
	log.Println("\n=== 测试清空购物车 ===")
	clearResp, err := client.ClearCart(ctx, &pb.ClearCartRequest{
		UserId: userID,
	})
	if err != nil {
		log.Printf("清空购物车失败: %v", err)
	} else {
		log.Printf("清空购物车成功: %v, %s",
			clearResp.Success,
			clearResp.Message)
	}
}
