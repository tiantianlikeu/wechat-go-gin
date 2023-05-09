package wechatgogin

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/silenceper/wechat/v2/officialaccount/context"
	"github.com/silenceper/wechat/v2/officialaccount/message"
	"github.com/silenceper/wechat/v2/util"
	"github.com/tidwall/gjson"
)

// gin 微信消息
type GinWxMsg struct {
	Gin           *gin.Context
	WxCtx         *context.Context
	MixMessage    *message.MixMessage
	IsSafeMode    bool
	IsJSONContent bool
	Random        []byte
	Nonce         string
	Timestamp     int64

	SkipValidate bool

	OpenID string

	MessageReply *message.Reply

	RequestRawXMLMsg  []byte
	RequestMsg        *message.MixMessage
	ResponseRawXMLMsg []byte
	ResponseMsg       interface{}
}

// gin 获取微信消息
func GetWxMsg(c *gin.Context, wxCtx *context.Context, skip bool) (ginWxMsg *GinWxMsg, err error) {
	var msg interface{}
	ginWxMsg = new(GinWxMsg)
	ginWxMsg.WxCtx = wxCtx
	ginWxMsg.Gin = c
	ginWxMsg.SkipValidate = skip

	// 验证签名
	if !Validate(ginWxMsg) {
		fmt.Println("签名校验失败。")
		return nil, errors.New("签名校验失败")
	}

	// echostr, exists := c.GetQuery("echostr")
	// if exists {
	// 	ReulstString(c, echostr)
	// 	return nil, nil
	// }

	msg, err = getMessage(ginWxMsg)
	if err != nil {
		return
	}
	mixMessage, success := msg.(*message.MixMessage)
	ginWxMsg.MixMessage = mixMessage
	if !success {
		err = errors.New("消息类型转换失败")
		return nil, err
	}

	ginWxMsg.RequestMsg = mixMessage
	return ginWxMsg, nil
}

// getMessage 解析微信返回的消息
func getMessage(ginWxMsg *GinWxMsg) (interface{}, error) {
	c := ginWxMsg.Gin
	// set isSafeMode
	ginWxMsg.IsSafeMode = false
	encryptType := c.Query("encrypt_type")
	if encryptType == "aes" {
		ginWxMsg.IsSafeMode = true
	}

	// set openID
	ginWxMsg.OpenID = c.Query("openid")

	var rawXMLMsgBytes []byte
	var err error
	if ginWxMsg.IsSafeMode {
		encryptedXMLMsg, dataErr := getEncryptBody(ginWxMsg)
		if dataErr != nil {
			return nil, dataErr
		}

		// 验证消息签名
		timestamp := c.Query("timestamp")
		ginWxMsg.Timestamp, err = strconv.ParseInt(timestamp, 10, 32)
		if err != nil {
			return nil, err
		}
		nonce := c.Query("nonce")
		ginWxMsg.Nonce = nonce
		msgSignature := c.Query("msg_signature")
		msgSignatureGen := util.Signature(ginWxMsg.WxCtx.Token, timestamp, nonce, encryptedXMLMsg.EncryptedMsg)
		if msgSignature != msgSignatureGen {
			return nil, fmt.Errorf("消息不合法，验证签名失败")
		}

		// 解密
		ginWxMsg.Random, rawXMLMsgBytes, err = util.DecryptMsg(ginWxMsg.WxCtx.AppID, encryptedXMLMsg.EncryptedMsg, ginWxMsg.WxCtx.EncodingAESKey)
		if err != nil {
			return nil, fmt.Errorf("消息解密失败, err=%v", err)
		}
	} else {
		rawXMLMsgBytes, err = io.ReadAll(c.Request.Body)
		if err != nil {
			return nil, fmt.Errorf("从body中解析xml失败, err=%v", err)
		}
	}
	ginWxMsg.RequestRawXMLMsg = rawXMLMsgBytes
	return parseRequestMessage(c, rawXMLMsgBytes)
}

// 获取加密消息体
func getEncryptBody(ginWxMsg *GinWxMsg) (*message.EncryptedXMLMsg, error) {
	c := ginWxMsg.Gin
	var encryptedXMLMsg = &message.EncryptedXMLMsg{}
	contentType := c.Request.Header.Get("Content-Type")
	ginWxMsg.IsJSONContent = strings.Contains(contentType, "application/json")
	if ginWxMsg.IsJSONContent {
		body, _ := io.ReadAll(c.Request.Body)
		if err := json.Unmarshal(body, encryptedXMLMsg); err != nil {
			return nil, fmt.Errorf("从body中解析json失败,err=%v", err)
		}
	} else {
		body, _ := io.ReadAll(c.Request.Body)
		if err := xml.Unmarshal(body, encryptedXMLMsg); err != nil {
			return nil, fmt.Errorf("从body中解析xml失败,err=%v", err)
		}
	}
	return encryptedXMLMsg, nil
}

// 判断参数是否是json
func isJSONContent(c *gin.Context) bool {
	contentType := c.Request.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

// Validate 校验请求是否合法
func Validate(ginWxMsg *GinWxMsg) bool {
	if ginWxMsg.SkipValidate {
		return true
	}

	c := ginWxMsg.Gin
	timestamp := c.Query("timestamp")
	nonce := c.Query("nonce")
	signature := c.Query("signature")
	fmt.Println("validate signature, timestamp= ", timestamp, " , nonce=", nonce)
	return signature == util.Signature(ginWxMsg.WxCtx.Token, timestamp, nonce)
}

// 编译响应参数
func BuildResponse(ginWxMsg *GinWxMsg) (err error) {
	reply := ginWxMsg.MessageReply
	defer func() {
		if e := recover(); e != nil {
			err = fmt.Errorf("panic error: %v\n%s", e, debug.Stack())
		}
	}()
	if reply == nil {
		// do nothing
		return nil
	}
	msgType := reply.MsgType
	switch msgType {
	case message.MsgTypeText:
	case message.MsgTypeImage:
	case message.MsgTypeVoice:
	case message.MsgTypeVideo:
	case message.MsgTypeMusic:
	case message.MsgTypeNews:
	case message.MsgTypeTransfer:
	default:
		err = message.ErrUnsupportReply
		return
	}

	msgData := reply.MsgData
	value := reflect.ValueOf(msgData)
	// msgData must be a ptr
	kind := value.Kind().String()
	if kind != "ptr" {
		return message.ErrUnsupportReply
	}

	params := make([]reflect.Value, 1)
	params[0] = reflect.ValueOf(ginWxMsg.RequestMsg.FromUserName)
	value.MethodByName("SetToUserName").Call(params)

	params[0] = reflect.ValueOf(ginWxMsg.RequestMsg.ToUserName)
	value.MethodByName("SetFromUserName").Call(params)

	params[0] = reflect.ValueOf(msgType)
	value.MethodByName("SetMsgType").Call(params)

	params[0] = reflect.ValueOf(util.GetCurrTS())
	value.MethodByName("SetCreateTime").Call(params)

	ginWxMsg.ResponseMsg = msgData
	ginWxMsg.ResponseRawXMLMsg, err = xml.Marshal(msgData)
	return
}

// 格式化请求消息
func parseRequestMessage(c *gin.Context, rawXMLMsgBytes []byte) (msg *message.MixMessage, err error) {
	msg = &message.MixMessage{}
	if isJSONContent(c) {
		err = xml.Unmarshal(rawXMLMsgBytes, msg)
		return
	}
	// parse json
	err = json.Unmarshal(rawXMLMsgBytes, msg)
	if err != nil {
		return
	}
	// nonstandard json, 目前小程序订阅消息返回数据格式不标准，订阅消息模板单个List返回是对象，多个List返回是数组。
	if msg.MsgType == message.MsgTypeEvent {
		listData := gjson.Get(string(rawXMLMsgBytes), "List")
		if listData.IsObject() {
			listItem := message.SubscribeMsgPopupEvent{}
			if parseErr := json.Unmarshal([]byte(listData.Raw), &listItem); parseErr != nil {
				return msg, parseErr
			}
			msg.SetSubscribeMsgPopupEvents([]message.SubscribeMsgPopupEvent{listItem})
		} else if listData.IsArray() {
			listItems := make([]message.SubscribeMsgPopupEvent, 0)
			if parseErr := json.Unmarshal([]byte(listData.Raw), &listItems); parseErr != nil {
				return msg, parseErr
			}
			msg.SetSubscribeMsgPopupEvents(listItems)
		}
	}
	return
}

var xmlContentType = []string{"application/xml; charset=utf-8"}
var plainContentType = []string{"text/plain; charset=utf-8"}

func writeContextType(w http.ResponseWriter, value []string) {
	header := w.Header()
	if val := header["Content-Type"]; len(val) == 0 {
		header["Content-Type"] = value
	}
}

func ResultXml(c *gin.Context, obj interface{}) {
	writeContextType(c.Writer, xmlContentType)
	bytes, err := xml.Marshal(obj)
	if err != nil {
		panic(err)
	}
	Render(c, bytes)
}

func ReulstString(c *gin.Context, str string) {
	writeContextType(c.Writer, plainContentType)
	Render(c, []byte(str))
}

func Render(c *gin.Context, bytes []byte) {
	c.Writer.WriteHeader(200)
	_, err := c.Writer.Write(bytes)
	if err != nil {
		panic(err)
	}
}

func Result(ginWxMsg *GinWxMsg) (err error) {
	replyMsg := ginWxMsg.ResponseMsg
	c := ginWxMsg.Gin
	if ginWxMsg.IsSafeMode {

		// 安全模式下对消息进行加密
		var encryptedMsg []byte
		encryptedMsg, err = util.EncryptMsg(ginWxMsg.Random, ginWxMsg.ResponseRawXMLMsg, ginWxMsg.WxCtx.AppID, ginWxMsg.WxCtx.EncodingAESKey)
		if err != nil {
			return
		}
		// TODO 如果获取不到timestamp nonce 则自己生成
		timestamp := ginWxMsg.Timestamp
		timestampStr := strconv.FormatInt(timestamp, 10)
		msgSignature := util.Signature(ginWxMsg.WxCtx.Token, timestampStr, ginWxMsg.Nonce, string(encryptedMsg))
		replyMsg = message.ResponseEncryptedXMLMsg{
			EncryptedMsg: string(encryptedMsg),
			MsgSignature: msgSignature,
			Timestamp:    timestamp,
			Nonce:        ginWxMsg.Nonce,
		}
	}
	if replyMsg != nil {
		ResultXml(c, replyMsg)
	}
	return
}
