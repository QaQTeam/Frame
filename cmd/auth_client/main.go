package main

import (
	"context"
	"log"
	"time"

	pb "qaqmall/api/auth/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	// 连接到 gRPC 服务器
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// 创建客户端
	client := pb.NewAuthServiceClient(conn)

	// 设置超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// 测试生成 token
	tokenResp, err := client.GenerateToken(ctx, &pb.GenerateTokenRequest{
		UserId: 1,
		Role:   0,
	})
	if err != nil {
		log.Fatalf("could not generate token: %v", err)
	}
	log.Printf("Token: %s", tokenResp.Token)
	log.Printf("Expires at: %v", time.Unix(tokenResp.ExpiresAt, 0))

	// 测试验证 token
	verifyResp, err := client.VerifyToken(ctx, &pb.VerifyTokenRequest{
		Token: tokenResp.Token,
	})
	if err != nil {
		log.Fatalf("could not verify token: %v", err)
	}
	log.Printf("Token valid: %v", verifyResp.IsValid)
	log.Printf("User ID: %d", verifyResp.UserId)
	log.Printf("Role: %d", verifyResp.Role)
	log.Printf("Needs renewal: %v", verifyResp.NeedsRenewal)

	// 测试续期 token
	if verifyResp.NeedsRenewal {
		renewResp, err := client.RenewToken(ctx, &pb.RenewTokenRequest{
			OldToken: tokenResp.Token,
		})
		if err != nil {
			log.Fatalf("could not renew token: %v", err)
		}
		log.Printf("New token: %s", renewResp.NewToken)
		log.Printf("New expiry: %v", time.Unix(renewResp.ExpiresAt, 0))
	}
}
