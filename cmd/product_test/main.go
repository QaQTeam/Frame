package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "qaqmall/api/product/v1"
)

func main() {
	// 连接 gRPC 服务器
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewProductServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. 创建商品分类
	log.Println("=== 测试商品分类列表 ===")
	categories, err := client.ListCategories(ctx, &pb.ListCategoriesRequest{
		OnlyActive: true,
	})
	if err != nil {
		log.Printf("获取分类列表失败: %v", err)
	} else {
		log.Printf("获取到 %d 个分类", len(categories.Categories))
		for _, cat := range categories.Categories {
			log.Printf("分类: ID=%d, 名称=%s", cat.Id, cat.Name)
		}
	}

	// 2. 创建商品
	log.Println("\n=== 测试创建商品 ===")
	categoryID := uint64(1) // 假设已经有ID为1的分类
	product, err := client.CreateProduct(ctx, &pb.CreateProductRequest{
		Name:        "测试商品",
		Description: "这是一个测试商品",
		Price:       99.99,
		Stock:       100,
		CategoryId:  categoryID,
		ImageUrl:    "https://example.com/test.jpg",
		IsOnSale:    true,
	})
	if err != nil {
		log.Printf("创建商品失败: %v", err)
	} else {
		log.Printf("创建商品成功: ID=%d, 名称=%s", product.Product.Id, product.Product.Name)
	}

	// 3. 获取商品详情
	log.Println("\n=== 测试获取商品详情 ===")
	if product != nil {
		detail, err := client.GetProduct(ctx, &pb.GetProductRequest{
			Id: product.Product.Id,
		})
		if err != nil {
			log.Printf("获取商品详情失败: %v", err)
		} else {
			log.Printf("商品详情: ID=%d, 名称=%s, 价格=%.2f",
				detail.Product.Id,
				detail.Product.Name,
				detail.Product.Price)
		}
	}

	// 4. 更新商品
	log.Println("\n=== 测试更新商品 ===")
	if product != nil {
		updated, err := client.UpdateProduct(ctx, &pb.UpdateProductRequest{
			Id:          product.Product.Id,
			Name:        "更新后的商品名称",
			Description: "更新后的商品描述",
			Price:       199.99,
			Stock:       50,
			CategoryId:  categoryID,
			ImageUrl:    "https://example.com/updated.jpg",
			IsOnSale:    true,
		})
		if err != nil {
			log.Printf("更新商品失败: %v", err)
		} else {
			log.Printf("更新商品成功: ID=%d, 新名称=%s, 新价格=%.2f",
				updated.Product.Id,
				updated.Product.Name,
				updated.Product.Price)
		}
	}

	// 5. 测试商品列表
	log.Println("\n=== 测试商品列表 ===")
	products, err := client.ListProducts(ctx, &pb.ListProductsRequest{
		Page:       1,
		PageSize:   10,
		OnlyOnSale: true,
		SortBy:     "created_at",
		Desc:       true,
	})
	if err != nil {
		log.Printf("获取商品列表失败: %v", err)
	} else {
		log.Printf("获取到 %d 个商品，总数: %d",
			len(products.Products),
			products.Total)
		for _, p := range products.Products {
			log.Printf("商品: ID=%d, 名称=%s, 价格=%.2f",
				p.Id, p.Name, p.Price)
		}
	}

	// 6. 测试商品搜索
	log.Println("\n=== 测试商品搜索 ===")
	searchResults, err := client.SearchProducts(ctx, &pb.SearchProductsRequest{
		Keyword:    "测试",
		Page:       1,
		PageSize:   10,
		MinPrice:   50,
		MaxPrice:   200,
		OnlyOnSale: true,
		SortBy:     "price",
		Desc:       false,
	})
	if err != nil {
		log.Printf("搜索商品失败: %v", err)
	} else {
		log.Printf("搜索到 %d 个商品，总数: %d",
			len(searchResults.Products),
			searchResults.Total)
		for _, p := range searchResults.Products {
			log.Printf("商品: ID=%d, 名称=%s, 价格=%.2f",
				p.Id, p.Name, p.Price)
		}
	}

	// 7. 删除商品
	log.Println("\n=== 测试删除商品 ===")
	if product != nil {
		result, err := client.DeleteProduct(ctx, &pb.DeleteProductRequest{
			Id: product.Product.Id,
		})
		if err != nil {
			log.Printf("删除商品失败: %v", err)
		} else {
			log.Printf("删除商品成功: %v, %s", result.Success, result.Message)
		}
	}
}
