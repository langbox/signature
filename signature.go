package signature

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func Sign(content string, privateKeyStr string) (string, error) {
	return SignECDSA(content, privateKeyStr)
}

func GetSHA256HASH(data string) []byte {
	bmsg := []byte(data)

	h := sha256.New()
	h.Write([]byte(bmsg))
	hash := h.Sum(nil)
	return hash

}

// Hash算法，这里是sha256，可以根据需要自定义
func Hash(data string) []byte {
	sum := sha256.Sum256([]byte(data))

	return sum[:]
}

func TransPem2Base64(privateKey string) {
	bl, _ := pem.Decode([]byte(privateKey))
	if bl == nil {
		fmt.Println("failed to decode PEM block from PrivateKey")
		return
	}
	fmt.Println("原始Key 的 byte")
	fmt.Println(bl.Bytes)
	baseStr := base64.RawURLEncoding.EncodeToString(bl.Bytes)
	fmt.Println(baseStr)
}

func TransBase642Pem(privateKeyStr string, keyType string) {
	bytes, err := base64.RawURLEncoding.DecodeString(privateKeyStr)
	if err != nil {
		fmt.Println("failed to decode string from PrivateKey")
		return
	}
	block := &pem.Block{
		Type:  keyType, //"PRIVATE KEY", PUBLIC KEY
		Bytes: bytes,
	}
	err = pem.Encode(os.Stdout, block)
	if err != nil {
		fmt.Println("failed to encode string from PrivateKey", err)
		return
	}

}
