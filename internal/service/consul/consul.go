package consul

import (
	"fmt"
	"log"

	consulapi "github.com/hashicorp/consul/api"
)

type ConsulService struct {
	client *consulapi.Client
}

func NewConsulService(address string) (*ConsulService, error) {
	config := consulapi.DefaultConfig()
	config.Address = address
	client, err := consulapi.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("创建 Consul 客户端失败: %v", err)
	}
	return &ConsulService{client: client}, nil
}

// RegisterService 注册服务到 Consul
func (c *ConsulService) RegisterService(name string, id string, address string, port int, tags []string) error {
	registration := &consulapi.AgentServiceRegistration{
		ID:      id,
		Name:    name,
		Port:    port,
		Address: address,
		Tags:    tags,
		Check: &consulapi.AgentServiceCheck{
			HTTP:     fmt.Sprintf("http://%s:%d/health", address, port),
			Interval: "10s",
			Timeout:  "5s",
		},
	}

	if err := c.client.Agent().ServiceRegister(registration); err != nil {
		return fmt.Errorf("注册服务失败: %v", err)
	}

	log.Printf("服务 %s 已注册到 Consul", name)
	return nil
}

// DeregisterService 从 Consul 注销服务
func (c *ConsulService) DeregisterService(id string) error {
	if err := c.client.Agent().ServiceDeregister(id); err != nil {
		return fmt.Errorf("注销服务失败: %v", err)
	}
	log.Printf("服务 %s 已从 Consul 注销", id)
	return nil
}

// GetService 从 Consul 获取服务信息
func (c *ConsulService) GetService(name string) ([]*consulapi.ServiceEntry, error) {
	services, _, err := c.client.Health().Service(name, "", true, nil)
	if err != nil {
		return nil, fmt.Errorf("获取服务信息失败: %v", err)
	}
	return services, nil
}
