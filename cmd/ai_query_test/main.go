package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "qaqmall/api/ai_query/v1"
)

func main() {
	// 连接 gRPC 服务器
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewAIQueryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. 测试智能查询商品
	log.Println("=== 测试智能查询商品 ===")
	queryResp, err := client.QueryProducts(ctx, &pb.QueryProductsRequest{
		Query:     "手机",
		Page:      1,
		PageSize:  10,
		SortBy:    "price",
		Ascending: true,
		Filters:   []string{"category:手机数码", "in_stock:true"},
	})
	if err != nil {
		log.Printf("查询商品失败: %v", err)
	} else {
		log.Printf("查询到 %d 个商品:", queryResp.Total)
		for _, product := range queryResp.Products {
			log.Printf("- %s (价格: %.2f, 相关度: %.2f)", product.Name, product.Price, product.SimilarityScore)
		}
		if len(queryResp.Suggestions) > 0 {
			log.Printf("搜索建议: %v", queryResp.Suggestions)
		}
	}

	// 2. 测试获取商品推荐
	log.Println("\n=== 测试获取商品推荐 ===")
	recResp, err := client.GetRecommendations(ctx, &pb.GetRecommendationsRequest{
		UserId:  1,
		Limit:   5,
		Context: "homepage",
	})
	if err != nil {
		log.Printf("获取推荐失败: %v", err)
	} else {
		log.Printf("推荐ID: %s", recResp.RecommendationId)
		log.Printf("推荐商品:")
		for _, product := range recResp.Products {
			log.Printf("- %s (价格: %.2f)", product.Name, product.Price)
		}
	}

	// 3. 测试获取相似商品
	log.Println("\n=== 测试获取相似商品 ===")
	similarResp, err := client.GetSimilarProducts(ctx, &pb.GetSimilarProductsRequest{
		ProductId: 1,
		Limit:     5,
		Aspects:   []string{"price", "category"},
	})
	if err != nil {
		log.Printf("获取相似商品失败: %v", err)
	} else {
		log.Printf("相似商品:")
		for _, product := range similarResp.Products {
			log.Printf("- %s (价格: %.2f, 相似度: %.2f)", product.Name, product.Price, product.SimilarityScore)
		}
	}

	// 4. 测试智能分类商品
	log.Println("\n=== 测试智能分类商品 ===")
	classifyResp, err := client.ClassifyProducts(ctx, &pb.ClassifyProductsRequest{
		ProductIds:         []uint64{1, 2, 3, 4, 5},
		ClassificationType: "price_range",
	})
	if err != nil {
		log.Printf("分类商品失败: %v", err)
	} else {
		log.Printf("分类结果:")
		for _, classification := range classifyResp.Classifications {
			log.Printf("\n%s (%s):", classification.Category, classification.Description)
			for _, product := range classification.Products {
				log.Printf("- %s (价格: %.2f)", product.Name, product.Price)
			}
		}
	}
}
