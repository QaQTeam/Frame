package main

import (
	"context"
	"log"
	"time"

	pb "qaqmall/api/user/v1"

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
	client := pb.NewUserServiceClient(conn)

	// 设置超时上下文
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// 1. 测试注册
	log.Println("测试注册功能...")
	registerResp, err := client.Register(ctx, &pb.RegisterRequest{
		Username: "testuser",
		Password: "testpass123",
		Email:    "test@example.com",
		Phone:    "13800138000",
	})
	if err != nil {
		log.Printf("注册失败: %v", err)
	} else {
		log.Printf("注册成功: %+v", registerResp)
	}

	// 2. 测试登录
	log.Println("\n测试登录功能...")
	loginResp, err := client.Login(ctx, &pb.LoginRequest{
		Username: "testuser",
		Password: "testpass123",
	})
	if err != nil {
		log.Printf("登录失败: %v", err)
	} else {
		log.Printf("登录成功: %+v", loginResp)
	}

	// 3. 测试获取用户信息
	if loginResp != nil {
		log.Println("\n测试获取用户信息...")
		userInfo, err := client.GetUserInfo(ctx, &pb.GetUserInfoRequest{
			UserId: loginResp.UserId,
		})
		if err != nil {
			log.Printf("获取用户信息失败: %v", err)
		} else {
			log.Printf("用户信息: %+v", userInfo)
		}

		// 4. 测试更新用户信息
		log.Println("\n测试更新用户信息...")
		updateResp, err := client.UpdateUser(ctx, &pb.UpdateUserRequest{
			UserId: loginResp.UserId,
			Email:  "newemail@example.com",
			Phone:  "13900139000",
		})
		if err != nil {
			log.Printf("更新用户信息失败: %v", err)
		} else {
			log.Printf("更新结果: %+v", updateResp)
		}

		// 5. 测试获取用户列表
		log.Println("\n测试获取用户列表...")
		listResp, err := client.ListUsers(ctx, &pb.ListUsersRequest{
			Page:     1,
			PageSize: 10,
			Search:   "test",
		})
		if err != nil {
			log.Printf("获取用户列表失败: %v", err)
		} else {
			log.Printf("用户列表: 总数=%d, 总页数=%d", listResp.Total, listResp.TotalPages)
			for _, user := range listResp.Users {
				log.Printf("- 用户: %s (ID=%d, Email=%s)", user.Username, user.UserId, user.Email)
			}
		}

		// 6. 测试删除用户
		log.Println("\n测试删除用户...")
		deleteResp, err := client.DeleteUser(ctx, &pb.DeleteUserRequest{
			UserId:       loginResp.UserId,
			OperatorId:   loginResp.UserId,
			OperatorRole: loginResp.Role,
		})
		if err != nil {
			log.Printf("删除用户失败: %v", err)
		} else {
			log.Printf("删除结果: %+v", deleteResp)
		}
	}
}
