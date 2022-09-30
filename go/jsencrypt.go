package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
)

// RSA加密
func RSAEncrypt(data, publicBytes []byte) ([]byte, error) {
	var res []byte
	// 解析公钥
	block, _ := pem.Decode(publicBytes)

	if block == nil {
		return res, fmt.Errorf("无法加密, 公钥可能不正确")
	}

	// 使用X509将解码之后的数据 解析出来
	// x509.MarshalPKCS1PublicKey(block):解析之后无法用，所以采用以下方法：ParsePKIXPublicKey
	keyInit, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return res, fmt.Errorf("无法加密, 公钥可能不正确, %v", err)
	}
	// 使用公钥加密数据
	pubKey := keyInit.(*rsa.PublicKey)
	res, err = rsa.EncryptPKCS1v15(rand.Reader, pubKey, data)
	if err != nil {
		return res, fmt.Errorf("无法加密, 公钥可能不正确, %v", err)
	}
	// 将数据加密为base64格式
	return []byte(EncodeStr2Base64(string(res))), nil
}

// 加密base64字符串
func EncodeStr2Base64(str string) string {
	return base64.StdEncoding.EncodeToString([]byte(str))
}

func DecodeRSA(privatekey string, cipherText string) string {

	block, _ := pem.Decode([]byte(privatekey))

	b, err := base64.StdEncoding.DecodeString(cipherText)
	//X509解码
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	//对密文进行解密
	plainText, dd := rsa.DecryptPKCS1v15(rand.Reader, privateKey, b)
	if dd != nil {
		fmt.Println(dd)
	}
	return string(plainText)
}

//数组解压RSA 和单个
func SetDecryptArray(privatekey string, inter interface{}) string {
	var ps string
	md := privatekey

	switch reflect.TypeOf(inter).Kind() {
	case reflect.Slice, reflect.Array:
		s := reflect.ValueOf(inter)
		for i := 0; i < s.Len(); i++ {
			str := fmt.Sprint(s.Index(i))

			ps += DecodeRSA(md, str)

		}
	case reflect.String:
		s := reflect.ValueOf(inter)
		ps += DecodeRSA(md, s.String())

	}

	return ps
}

func SetDecrypt(privatekey string, data string) string {
	var ps string
	ps = DecodeRSA(privatekey, data)
	return ps
}

//加密
//加密
func SetEncrypt(publickey string, data string) string {

	psdata, err := RSAEncrypt([]byte(data), []byte(publickey))

	if err != nil {
		panic(err)
	}

	return string(psdata)
}

func SetLongEncrypt(publickey string, data string) []string {
	list := make([]string, 0)
	ionum := 0
	ioStr := ""
	for _, page := range []rune(data) {

		if ionum == 116 {
			list = append(list, ioStr)

			ionum = len(string(page))
			ioStr = string(page)
		} else {
			ionum += len(string(page))
			if ionum > 116 {
				list = append(list, ioStr)
				ionum = len(string(page))
				ioStr = string(page)
			} else {
				ionum += len(string(page))
				ioStr += string(page)
			}
		}

	}
	EnList := make([]string, 0)

	for _, str := range list {
		endate := SetEncrypt(publickey, str)
		EnList = append(EnList, endate)
	}
	return EnList
}

func setLongEncryptObject(privatekey string, data interface{}) map[string]string {
	var list map[string]string

	return list
}

//字符串转map
func RecResultJsonToPlain(json_str string) interface{} {

	var dat map[string]interface{}
	json.Unmarshal([]byte(json_str), &dat)
	return dat
}
