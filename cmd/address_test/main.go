package main

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "qaqmall/api/address/v1"
)

func main() {
	// 连接 gRPC 服务器
	conn, err := grpc.Dial("localhost:50051", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	defer conn.Close()

	client := pb.NewAddressServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 测试用户ID
	userID := uint64(1)

	// 1. 创建地址
	log.Println("=== 测试创建地址 ===")
	createResp, err := client.CreateAddress(ctx, &pb.CreateAddressRequest{
		UserId:     userID,
		Name:       "张三",
		Phone:      "13800138000",
		Province:   "北京市",
		City:       "北京市",
		District:   "朝阳区",
		Street:     "三里屯街道",
		Detail:     "SOHO现代城 1号楼 1单元 1001室",
		IsDefault:  true,
		PostalCode: "100000",
		Tag:        "家",
	})
	if err != nil {
		log.Printf("创建地址失败: %v", err)
	} else {
		log.Printf("创建地址成功: ID=%d", createResp.Address.Id)
		log.Printf("地址详情: %s %s %s %s %s",
			createResp.Address.Province,
			createResp.Address.City,
			createResp.Address.District,
			createResp.Address.Street,
			createResp.Address.Detail)
	}

	// 2. 创建第二个地址
	log.Println("\n=== 测试创建第二个地址 ===")
	createResp2, err := client.CreateAddress(ctx, &pb.CreateAddressRequest{
		UserId:     userID,
		Name:       "李四",
		Phone:      "13900139000",
		Province:   "北京市",
		City:       "北京市",
		District:   "海淀区",
		Street:     "中关村街道",
		Detail:     "科技大厦 2号楼 2单元 2002室",
		IsDefault:  false,
		PostalCode: "100080",
		Tag:        "公司",
	})
	if err != nil {
		log.Printf("创建第二个地址失败: %v", err)
	} else {
		log.Printf("创建第二个地址成功: ID=%d", createResp2.Address.Id)
	}

	// 3. 获取地址列表
	log.Println("\n=== 测试获取地址列表 ===")
	listResp, err := client.ListAddresses(ctx, &pb.ListAddressesRequest{
		UserId: userID,
	})
	if err != nil {
		log.Printf("获取地址列表失败: %v", err)
	} else {
		log.Printf("地址列表:")
		log.Printf("总数: %d", listResp.Total)
		for _, addr := range listResp.Addresses {
			log.Printf("- ID=%d, 姓名=%s, 电话=%s, 地址=%s %s %s %s %s, 默认=%v",
				addr.Id,
				addr.Name,
				addr.Phone,
				addr.Province,
				addr.City,
				addr.District,
				addr.Street,
				addr.Detail,
				addr.IsDefault)
		}
	}

	if createResp != nil && createResp.Address != nil {
		addressID := createResp.Address.Id

		// 4. 更新地址
		log.Println("\n=== 测试更新地址 ===")
		updateResp, err := client.UpdateAddress(ctx, &pb.UpdateAddressRequest{
			UserId:     userID,
			AddressId:  addressID,
			Name:       "张三",
			Phone:      "13800138000",
			Province:   "北京市",
			City:       "北京市",
			District:   "朝阳区",
			Street:     "三里屯街道",
			Detail:     "SOHO现代城 1号楼 1单元 1002室", // 修改房间号
			IsDefault:  true,
			PostalCode: "100000",
			Tag:        "家",
		})
		if err != nil {
			log.Printf("更新地址失败: %v", err)
		} else {
			log.Printf("更新地址成功: ID=%d", updateResp.Address.Id)
			log.Printf("新地址: %s %s %s %s %s",
				updateResp.Address.Province,
				updateResp.Address.City,
				updateResp.Address.District,
				updateResp.Address.Street,
				updateResp.Address.Detail)
		}

		// 5. 获取地址详情
		log.Println("\n=== 测试获取地址详情 ===")
		getResp, err := client.GetAddress(ctx, &pb.GetAddressRequest{
			UserId:    userID,
			AddressId: addressID,
		})
		if err != nil {
			log.Printf("获取地址详情失败: %v", err)
		} else {
			log.Printf("地址详情:")
			log.Printf("- ID: %d", getResp.Address.Id)
			log.Printf("- 姓名: %s", getResp.Address.Name)
			log.Printf("- 电话: %s", getResp.Address.Phone)
			log.Printf("- 地址: %s %s %s %s %s",
				getResp.Address.Province,
				getResp.Address.City,
				getResp.Address.District,
				getResp.Address.Street,
				getResp.Address.Detail)
			log.Printf("- 邮编: %s", getResp.Address.PostalCode)
			log.Printf("- 标签: %s", getResp.Address.Tag)
			log.Printf("- 是否默认: %v", getResp.Address.IsDefault)
		}

		// 6. 设置默认地址
		if createResp2 != nil && createResp2.Address != nil {
			log.Println("\n=== 测试设置默认地址 ===")
			setDefaultResp, err := client.SetDefaultAddress(ctx, &pb.SetDefaultAddressRequest{
				UserId:    userID,
				AddressId: createResp2.Address.Id, // 将第二个地址设为默认
			})
			if err != nil {
				log.Printf("设置默认地址失败: %v", err)
			} else {
				log.Printf("设置默认地址成功: ID=%d", setDefaultResp.Address.Id)
			}

			// 再次获取地址列表，验证默认地址是否已更改
			log.Println("\n=== 验证默认地址更改 ===")
			listResp, err = client.ListAddresses(ctx, &pb.ListAddressesRequest{
				UserId: userID,
			})
			if err != nil {
				log.Printf("获取地址列表失败: %v", err)
			} else {
				for _, addr := range listResp.Addresses {
					log.Printf("- ID=%d, 默认=%v", addr.Id, addr.IsDefault)
				}
			}

			// 7. 删除地址
			log.Println("\n=== 测试删除地址 ===")
			deleteResp, err := client.DeleteAddress(ctx, &pb.DeleteAddressRequest{
				UserId:    userID,
				AddressId: createResp2.Address.Id, // 删除第二个地址
			})
			if err != nil {
				log.Printf("删除地址失败: %v", err)
			} else {
				log.Printf("删除地址成功: %v, %s", deleteResp.Success, deleteResp.Message)
			}
		}
	}
}
