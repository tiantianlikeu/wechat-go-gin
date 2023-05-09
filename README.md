# wechat-go-gin


暂时解决 每次 http 请求过来都会去调用 officialAccount.GetServer，然而该方法每次都会新建一个 server 对象的问题


```go
    wc := wechat.NewWechat()
	//配置微信参数
	config := &offConfig.Config{
		AppID:         AppID,
		AppSecret:      AppSecret,
		Token:          Token,
		EncodingAESKey: EncodingAESKey,
		Cache:          redis,
	}
	officialAccount := wc.GetOfficialAccount(config)

    // 获取公众号实例的上下文
    wxCtx := officialAccount.GetContext()


    // 获取微信消息 c为 *gin.Context
	ginWxMsg, error := wechatgogin.GetWxMsg(c, wxCtx, false)
	if error == nil {
        // 微信消息处理
		reply := messageReply(ginWxMsg.MixMessage)
        // 设置返回结果
		ginWxMsg.MessageReply = reply
        // 编译返回结果
		wechatgogin.BuildResponse(ginWxMsg)
        // 返回消息给微信
		wechatgogin.Result(ginWxMsg)
	}

```