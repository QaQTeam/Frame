package handlers

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-pay/gopay"
	"github.com/go-pay/gopay/wechat/v3"
	"github.com/google/uuid" // 引入 uuid 库
	"github.com/skip2/go-qrcode"
	"github.com/smartwalle/alipay/v3"
	"gorm.io/gorm"
	"io/ioutil"
	"log"
	"net/http"
	"qaqmall/models"
	"time"
)

// WechatPayService 结构体用于表示微信支付服务的客户端
type WechatPayService struct {
	ctx       context.Context  // 上下文，控制请求生命周期
	config    WechatPayConfig  // 微信支付的配置
	wechatPay *wechat.ClientV3 // 微信支付的客户端
}

// Config 配置结构体，用于加载微信支付的公钥等
type Config struct {
	WxPublicKey  string         `mapstructure:"wx_public_key"` // 微信支付公钥
	RsaPublicKey *rsa.PublicKey // RSA 公钥，用于验证微信支付签名
}

// GlobalConf 全局配置变量
var GlobalConf = &Config{}

// WechatPayConfig 微信支付的配置信息
type WechatPayConfig struct {
	Appid       string // 应用ID
	Appid1      string // 备用应用ID (然并用)
	MchId       string // 商户号
	ApiV3Key    string // API v3 密钥
	MchSerialNo string // 商户证书序列号
	PrivateKey  string // 商户私钥
	NotifyUrl   string // 支付回调通知地址
	RefundUrl   string // 退款回调地址
}

// PayAo 支付请求的输入参数结构体
type PayAo struct {
	OrderId       uint64  `json:"order_id"`       // 订单ID
	UserId        uint64  `json:"user_id"`        // 用户ID
	Amount        float64 `json:"amount"`         // 支付金额
	PaymentMethod string  `json:"payment_method"` // 支付方式 (微信支付/支付宝等)
}

// PayHandler 支付处理结构体，包含了支付宝和微信支付的客户端
type PayHandler struct {
	db            *gorm.DB          // 数据库连接
	alipayClient  *alipay.Client    // 支付宝客户端
	wechatService *WechatPayService // 微信支付服务客户端
	payConfig     WechatPayConfig   // 微信支付配置
}

func NewWechatPayService(ctx context.Context, config WechatPayConfig) *WechatPayService {
	client, err := wechat.NewClientV3(config.MchId, config.MchSerialNo, config.ApiV3Key, config.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	err = client.AutoVerifySign()
	if err != nil {
		fmt.Println(err)
		return nil
	}
	client.DebugSwitch = gopay.DebugOn

	LoadConfig()

	return &WechatPayService{
		ctx:       ctx,
		wechatPay: client,
		config:    config,
	}
}

func LoadConfig() error {
	GlobalConf = &Config{
		WxPublicKey: "your_public_key_here", // TODO: 替换为实际的公钥内容
	}

	// 解析公钥
	block, _ := pem.Decode([]byte(GlobalConf.WxPublicKey))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}

	// 将公钥保存到 Config 中
	if rsaPub, ok := pub.(*rsa.PublicKey); ok {
		GlobalConf.RsaPublicKey = rsaPub
	} else {
		return fmt.Errorf("public key is not of type *rsa.PublicKey")
	}

	return nil
}

func NewPayHandler(db *gorm.DB, ctx context.Context) *PayHandler {
	// 支付宝 支付客户端 TODO
	appID := "9021000144618446" //你的appID
	privateKey := "MIIEowIBAAKCAQEAwq9xfKTvrTJYkJorBxowaY7PEpi5sxl4/7lzr/1k0VJ3rhb6zttW062s5M2n7BT1pQ3CLbMa+p9hg++QSCStKKo/5YWJoFTn1K/rTG2zEk" +
		"WauNljebceGAywTlYORKjQkFUGHq+X2g8I3aRcGrIRdelffZQFblc31/GWzh+Vh/Wbax6Kos5GIZiwGcUk1y9WWmc1JiNmi+x1oPa2uFxdE8Y4dAvlvc7PSawqb4znAeSX" +
		"53CrXY/JA9ExnaIV40tZzXGBvpLoCDhcKl3WJtckFndtRDXhk8gpwxzViCkBa50nczlSx/MVpHiJjbqRpv3eHhYPQRWmHfinQtqIXAkLdwIDAQABAoIBAGdzpQGP/5Bw" +
		"RWGpmp2ui/U7nsuJ/nuuWH7DBDeLlewpP1FyApqzMSNQkaQPqGCqDpJDimCQYRC2arIaNfgwDRejyEpluGlLVNnPFWDKljJqbDo3wkVmSgaLj5BA6FoRvqpDk/nwYufLv3" +
		"FPqmXBI8gdV9G6O1yT2ifUx8cGP4Y7zQVdZCdqOgQyPTHMPwDt0cD/wAhNiq9hXeWD38EdkMwlXi8G+Z4L5Kp16QOFiD9tmjoVPO8RtW55GFJzydj7wKP7B0M4NghGvn" +
		"Q7MAyBMfSJNRmCu7Op4KTjpNZMsvttvo9HuXzwyVuWcU+v9twbwa2ykl3N1e3THWrd3ayxJkkCgYEA+3sTW7uPHGK+Tw2ycGCOb1yq2pLbMZHUXBLYa38ViZvmamnEN0" +
		"/J+H+CHvi9WUfwTq8/+Zv4QZBq069vpbr2WWSEtFlW6O8nAXHABtW7dpqAKjqOBloUj0xKG+QEHgLsG1GBwXZFpypszd8CjpYw3otOZkLitZY502MXza/0eNsCgYEAxi8V" +
		"S2AUkWZBpMWjtoj8QYropqS8jy6f0e9Qw5yfpjmHYlRtxQx7RhT087tVSRNHIJ870t7SgLkmaDIicKbYrRwdzXW0Xi/5q9rSzwwO2MMFE8Ajn8+1wydkna2hXmfXQ/o14d3" +
		"rKdR48sNMuDHal4uiA9WZAr+mVuvUOH7wXJUCgYEA0gzW+oQK4RbJBpbWOG8uCW5Jdw+67gh0bAOBqSgZATuqla+KKPkIJfu638u7vFsOKWrP8NmJ3pmV4QJkKvWi1r/S6C" +
		"DHKwC2f8pXLl5Pmp0p+Bu4jS2ohpiePfWSSs7+D0NhMgpr21jgUIS5SgfBAeExttCfNDUqT5oxQ6h4dokCgYAxCYVjWSq9r2eetaiEifCg5xYZ5bkiVI8HCwgY3rBCGQn+" +
		"spVWpHf8J0NU6412v2ZiFARhcPD1GNr//Se4aBBFBSf6pp0ykPxeIY733CvwRpEDCg/Gg0aeOykSOtwq19bT4x1h/d8qQoCK0Pgyu2MzDEHSYQ+zNmiaKVAhioc+4QKBgAY" +
		"LgBsUkZyOPNI5RHtnFBWKlc6L6YGNf6nQ8gHEmclTrGLg97EixeW4Dl7kyC/l7KiOFUST9uLGoA0k7WssS8ylRmkaCZyNl/5hSlNCOhtPaVUHMeNcRBBnboOVZrFhLeS918D" +
		"gguDqDxiNHos4rZ0sOUlLI56AfIXf7Ih9zTlq" //私钥

	aliPhublicKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAg1guOKjqO4uxMCi6Zefp2RzWQ6lJF5j/0/iAm3deiaS+eE/lN/6zPBsNA+ZvcN+G8YHJ25LhRK7" +
		"pH2btT0k0eXMZB4o2GuzvgUHbrNjlVNhKtuCXYLbMXNJO67cK2+xOk2FQSJ/SgFjNS1GzgM2s/aLI6X8MVNOmFhXZksovJd2fa4XwYtI6J3Fkkvs607MaKN93P3IS8MOG" +
		"jeemzVexYX2FqAtq/ixF9Avbz5SwXCyX6Mm4RORieVWsJ37jWzW6szlc92jDctuFzkt2YLa/b4rYCN+pzUGZnAY0gUgmHZ25Lyz0zz64aOHmTqznT3T09Z7yow+IFEPlKAMf" +
		"fNHywwIDAQAB" //支付宝的公钥
	client, err := alipay.New(appID, privateKey, false)
	if err != nil {
		panic(err)
	}
	err = client.LoadAliPayPublicKey(aliPhublicKey)
	if err != nil {
		panic(err)
	}

	// 初始化微信支付服务
	service := NewWechatPayService(ctx, WechatPayConfig{
		Appid:       "", // 微信支付应用的AppID
		Appid1:      "", // 可能是另一个AppID，具体用途需确认
		MchId:       "", // 商户号
		ApiV3Key:    "", // API v3密钥
		MchSerialNo: "", // 商户证书序列号
		PrivateKey:  "", // 商户私钥
		NotifyUrl:   "", // 支付结果通知地址
		RefundUrl:   "", // 退款结果通知地址
	})

	return &PayHandler{
		db:            db,
		alipayClient:  client,
		wechatService: service, // 将 WechatPayService 注入 PayHandler
		payConfig:     service.config,
	}
}

// 支付的接口
func (h *PayHandler) Charge(c *gin.Context) {
	var req PayAo
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "无效的请求参数"})
		return
	}

	// 检查订单是否存在
	var order models.Order
	if err := h.db.First(&order, req.OrderId).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "订单不存在"})
		return
	}

	// 检查支付记录是否存在
	var payment models.Payment
	tx := h.db.Where("order_id = ?", req.OrderId).First(&payment)

	if tx.Error != nil {
		if tx.Error == gorm.ErrRecordNotFound {
			// 如果不存在 就创建新的支付记录
			newPayment := models.Payment{
				PaymentNumber: generateUniqueID(),
				OrderID:       req.OrderId,
				UserID:        req.UserId,
				Amount:        req.Amount,
				PaymentMethod: models.PaymentMethod(req.PaymentMethod),
				Status:        models.PaymentStatusPending,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			}

			// 存储新的支付记录
			if err := h.db.Create(&newPayment).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "网络存在波动,请稍后重试"})
				return
			}
			// 启动定时器，15分钟后检查支付状态
			go h.checkAndCancelPayment(newPayment.ID, 15*time.Minute)
			payment = newPayment
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "网络存在波动,请稍后重试"})
			return
		}
	}

	// 检查支付状态
	if payment.Status != models.PaymentStatusPending {
		c.JSON(http.StatusBadRequest, gin.H{"message": "当前订单状态不支持支付,请稍后重试"})
		return
	}

	// 调用支付服务
	h.PayService(payment, c)
}

// 支付服务
func (h *PayHandler) PayService(payment models.Payment, c *gin.Context) {
	body := "订单支付"
	outTradeNo := payment.PaymentNumber
	totalFee := int(payment.Amount * 100)              // 金额单位为分
	notifyURL := "http://yourdomain.com/notify/wechat" // 确保这是正确的通知URL

	switch payment.PaymentMethod {
	case models.PaymentMethodWechat:
		h.wechatService.WechatPay(payment, c, body, outTradeNo, totalFee, notifyURL) // 使用 wechatService 调用 WechatPay 方法
	case models.PaymentMethodAlipay:
		h.Alipay(payment, c, body, outTradeNo, payment.Amount, notifyURL)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"message": "不支持的支付方式"})
	}
}

// 支付宝支付（网页支付）
func (h *PayHandler) Alipay(payment models.Payment, c *gin.Context, body string, outTradeNo string, totalAmount float64, notifyURL string) {
	// 构建支付请求参数

	var p = alipay.TradePagePay{}
	p.NotifyURL = notifyURL                          // 支付宝通知回调地址
	p.ReturnURL = notifyURL                          // 支付后跳转页面
	p.Subject = body                                 // 标题
	p.OutTradeNo = outTradeNo                        // 订单号
	p.TotalAmount = fmt.Sprintf("%.2f", totalAmount) // 支付金额
	p.ProductCode = "FAST_INSTANT_TRADE_PAY"         // 支付类型 (网页支付)

	// 生成支付链接
	url, err := h.alipayClient.TradePagePay(p)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "支付宝支付请求失败", "error": err.Error()})
		return
	}

	// 返回支付链接给前端，前端通过浏览器跳转到支付宝进行支付
	c.JSON(http.StatusOK, gin.H{"message": "支付宝支付链接生成成功", "url": url})
}

// 微信支付 PC端扫码
func (w *WechatPayService) WechatPay(payment models.Payment, c *gin.Context, body string, outTradeNo string, totalFee int, notifyURL string) (result string, err error) {
	//TODO 微信支付没有商业认证 这里考虑不处理 反正是测试功能
	amount := totalFee
	expire := time.Now().Add(10 * time.Minute).Format(time.RFC3339)
	bm := make(gopay.BodyMap)
	bm.Set("appid", w.config.Appid).
		Set("mchid", w.config.MchId).
		Set("description", body).
		Set("out_trade_no", outTradeNo).
		Set("time_expire", expire).
		Set("notify_url", notifyURL).
		SetBodyMap("amount", func(bm gopay.BodyMap) {
			bm.Set("total", amount).
				Set("currency", "CNY")
		})
	//TODO 这里是正常的逻辑但是微信支付需要商家申请
	//rsp, err := w.wechatPay.V3TransactionNative(w.ctx, bm)
	//if err != nil {
	//	return
	//}
	// result = rsp.Response.CodeUrl
	//TODO 这里可以考虑给result重新设置一个二维码
	result = GenerateQRCode()
	if result == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "网络存在波动,请稍后重试"})
		return
	}
	return
}

// 检查并取消支付状态
func (h *PayHandler) checkAndCancelPayment(paymentId uint64, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-timer.C:
		var payment models.Payment
		tx := h.db.First(&payment, paymentId)
		if tx.Error != nil {
			return
		}

		if payment.Status == models.PaymentStatusPending { // 0表示待支付状态
			payment.Status = models.PaymentStatusCancelled // 3表示已取消状态
			payment.UpdatedAt = time.Now()
			h.db.Save(&payment)
		}
	}
}

// 生成一个唯一的ID 使用 uuid 库
func generateUniqueID() string {
	return uuid.New().String()
}

// 处理微信支付回调的函数
func WxPayNotify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// 读取请求体
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read request body:", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 解析 XML 数据
	var callbackData WeChatCallbackResponse
	err = xml.Unmarshal(body, &callbackData)
	if err != nil {
		log.Println("Failed to unmarshal XML:", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 打印回调信息
	log.Printf("Received WeChat Callback: %+v\n", callbackData)

	// 检查返回的结果
	if callbackData.ReturnCode != "SUCCESS" {
		// 如果返回状态不是成功，响应微信
		sendFailureResponse(w)
		return
	}

	// 这里你可以进行一些业务处理，比如检查订单状态、更新数据库等
	// 比如：
	if callbackData.ResultCode == "SUCCESS" {
		// 处理支付成功的逻辑
		log.Printf("Payment Success for Order: %s, TransactionID: %s\n", callbackData.OutTradeNo, callbackData.TransactionID)
		// 更新订单状态等
	} else {
		// 处理支付失败的逻辑
		log.Printf("Payment Failed for Order: %s\n", callbackData.OutTradeNo)
	}

	// 返回微信成功的响应
	sendSuccessResponse(w)
}

// WeChatCallbackResponse 微信支付回调返回的结构体
type WeChatCallbackResponse struct {
	XMLName       xml.Name `xml:"xml"`            // XML根元素
	ReturnCode    string   `xml:"return_code"`    // 返回状态码，SUCCESS 表示成功，FAIL 表示失败
	ReturnMsg     string   `xml:"return_msg"`     // 返回消息，如有错误时返回错误信息
	AppID         string   `xml:"appid"`          // 小程序或公众号的应用ID
	MchID         string   `xml:"mch_id"`         // 微信支付商户号
	NonceStr      string   `xml:"nonce_str"`      // 随机字符串，不长于32位
	Sign          string   `xml:"sign"`           // 签名，验证数据的完整性
	ResultCode    string   `xml:"result_code"`    // 业务结果，SUCCESS 表示成功，FAIL 表示失败
	OpenID        string   `xml:"openid"`         // 用户的唯一标识
	IsSubscribe   string   `xml:"is_subscribe"`   // 用户是否订阅该公众号，Y表示订阅，N表示未订阅
	TradeType     string   `xml:"trade_type"`     // 交易类型，JSAPI，NATIVE，APP等
	BankType      string   `xml:"bank_type"`      // 付款银行
	TotalFee      int      `xml:"total_fee"`      // 订单总金额，单位为分
	FeeType       string   `xml:"fee_type"`       // 货币类型，默认CNY
	CashFee       int      `xml:"cash_fee"`       // 现金支付金额，单位为分
	CashFeeType   string   `xml:"cash_fee_type"`  // 现金支付币种
	TransactionID string   `xml:"transaction_id"` // 微信支付订单号
	OutTradeNo    string   `xml:"out_trade_no"`   // 商户订单号
	TimeEnd       string   `xml:"time_end"`       // 支付完成时间，格式为yyyyMMddHHmmss
}

// 发送成功响应给微信
func sendSuccessResponse(w http.ResponseWriter) {
	// 返回成功响应的XML格式
	response := "<xml><return_code><![CDATA[SUCCESS]]></return_code><return_msg><![CDATA[OK]]></return_msg></xml>"
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(response)) // 将响应写入HTTP响应体
}

// 发送失败响应给微信
func sendFailureResponse(w http.ResponseWriter) {
	// 返回失败响应的XML格式
	response := "<xml><return_code><![CDATA[FAIL]]></return_code><return_msg><![CDATA[Error]]></return_msg></xml>"
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(response)) // 将响应写入HTTP响应体
}

// 支付宝回调
func (h *PayHandler) AlipayNotify(w http.ResponseWriter, r *http.Request) {
	// 解析 POST 表单数据
	if err := r.ParseForm(); err != nil {
		http.Error(w, "解析表单失败", http.StatusBadRequest) // 如果解析失败，返回 400 错误
		return
	}

	// 获取表单数据
	formData := r.PostForm

	// 验证支付宝通知签名
	isValid := h.alipayClient.VerifySign(formData)
	if isValid != nil {
		http.Error(w, "无效的通知", http.StatusBadRequest) // 如果签名无效，返回 400 错误
		return
	}

	// 获取 out_trade_no 参数
	outTradeNo := formData.Get("out_trade_no")
	if outTradeNo == "" {
		http.Error(w, "无效的通知", http.StatusBadRequest) // 如果订单号为空，返回 400 错误
		return
	}

	// 获取 trade_status 参数
	tradeStatus := formData.Get("trade_status")
	if tradeStatus != "TRADE_SUCCESS" && tradeStatus != "TRADE_FINISHED" {
		http.Error(w, "交易未完成", http.StatusBadRequest) // 如果交易状态不是成功或已完成，返回 400 错误
		return
	}

	// 查找支付记录
	var payment models.Payment
	if err := h.db.Where("payment_number = ?", outTradeNo).First(&payment).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			http.Error(w, "支付记录不存在", http.StatusNotFound) // 如果未找到支付记录，返回 404 错误
		} else {
			http.Error(w, "内部服务器错误", http.StatusInternalServerError) // 如果数据库查询出错，返回 500 错误
		}
		return
	}

	// 更新支付状态
	payment.Status = models.PaymentStatusPaid // 标记支付成功
	currentTime := time.Now()
	payment.PaidAt = &currentTime
	payment.UpdatedAt = currentTime
	if err := h.db.Save(&payment).Error; err != nil {
		http.Error(w, "更新支付状态失败", http.StatusInternalServerError) // 如果更新失败，返回 500 错误
		return
	}

	// 返回成功响应
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("success")) // 返回支付宝要求的 "success" 字符串
}

// GetPayment 根据用户ID和支付状态查询支付记录
func (h *PayHandler) GetPayment(c *gin.Context) {
	// 获取上下文中的用户ID
	userID, b := c.Get("user_id")
	// 获取查询参数中的支付状态
	paymentStatus := c.DefaultQuery("status", "") // 获取请求中的支付状态，默认为空
	if !b {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "参数有误!"})
		return
	}

	userIDUint64, ok := userID.(uint64)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户ID!"})
		return
	}

	// 创建查询条件
	var payments []models.Payment

	// 如果有支付状态，查询时加上状态条件
	query := h.db.Where("user_id = ?", userIDUint64)
	if paymentStatus != "" {
		query = query.Where("status = ?", paymentStatus)
	}

	// 执行查询，获取支付记录集合
	if err := query.Find(&payments).Error; err != nil {
		// 查询失败时返回错误
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查询支付记录失败!"})
		return
	}

	// 如果没有找到记录，返回提示信息
	if len(payments) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"message": "没有找到支付记录!"})
		return
	}

	// 返回支付记录集合
	c.JSON(http.StatusOK, gin.H{
		"payments": payments,
	})
}
func GenerateQRCode() string {
	// 要编码到二维码中的内容
	content := "跳转微信支付失败..."

	// 生成二维码图像
	png, err := qrcode.Encode(content, qrcode.Medium, 256)
	if err != nil {
		return ""
	}

	// 将二维码图像编码为Base64字符串
	base64Encoded := base64.StdEncoding.EncodeToString(png)

	return base64Encoded
}
