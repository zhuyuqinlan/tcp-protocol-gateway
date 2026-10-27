package minecraft

import (
	"encoding/json"
	"fmt"
)

// StatusVersion 是状态响应 JSON 的 version 字段。
type StatusVersion struct {
	Name     string `json:"name"`
	Protocol int32  `json:"protocol"`
}

// StatusPlayers 是状态响应 JSON 的 players 字段。
type StatusPlayers struct {
	Max    int `json:"max"`
	Online int `json:"online"`
}

// StatusDescription 是状态响应 JSON 的 description 字段。
type StatusDescription struct {
	Text string `json:"text"`
}

// Status 是 Server List Ping 的状态响应结构。
// 字段顺序由 json.Marshal 的结构体字段顺序决定，
// 与协议文档中推荐的 JSON 顺序一致。
type Status struct {
	Version     StatusVersion     `json:"version"`
	Players     StatusPlayers     `json:"players"`
	Description StatusDescription `json:"description"`
}

// NewStatus 根据网关配置构造状态响应。
func NewStatus(versionName string, protocol int32, motd string, maxPlayers, onlinePlayers int) *Status {
	return &Status{
		Version:     StatusVersion{Name: versionName, Protocol: protocol},
		Players:     StatusPlayers{Max: maxPlayers, Online: onlinePlayers},
		Description: StatusDescription{Text: motd},
	}
}

// JSON 序列化为状态响应 JSON 文本。
func (s *Status) JSON() (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal status json: %w", err)
	}
	return string(b), nil
}

// DisconnectReason 构造 Login Disconnect 消息的 chat 组件 JSON。
// 客户端会在"无法连接"界面展示 text 字段。
func DisconnectReason(text string) string {
	b, err := json.Marshal(struct {
		Text string `json:"text"`
	}{Text: text})
	if err != nil {
		// json.Marshal 对纯字符串不会失败；此处兜底返回纯文本。
		return `{"text":"` + text + `"}`
	}
	return string(b)
}
