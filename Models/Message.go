package Models

import "math/big"

type Message struct {
	msg []byte
}

// NewMessage 创建消息
func NewMessage(msg []byte) *Message {
	return &Message{msg: msg}
}

// msg2bigInt
func Msg2BigInt(msg Message) *big.Int {
	return big.NewInt(0).SetBytes(msg.msg)
}
