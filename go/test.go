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

func main() {
	data := "分割结果是不包含空字符串的，比如ab前面有一个空格"
	ddlong := "分割结果是不包含空字符串的，比如ab前面有一个空格5x56D6as4d6as6das6d6asdf61as6f16ab前面有一个空"
	fmt.Println(data)
	//请加记得加 \n
	publiukey := "-----BEGIN PUBLIC KEY-----\n" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlOJu6TyygqxfWT7eLtGDwajtNFOb9I5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4gwQco1KRMDSmXSMkDwIDAQAB\n" + "-----END PUBLIC KEY-----\n"
	//请加记得加 \n
	privatekey := "-----BEGIN RSA PRIVATE KEY-----\n" + "MIICXQIBAAKBgQDlOJu6TyygqxfWT7eLtGDwajtNFOb9I5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4gwQco1KRMDSmXSMkDwIDAQABAoGAfY9LpnuWK5Bs50UVep5c93SJdUi82u7yMx4iHFMc/Z2hfenfYEzu+57fI4fvxTQ//5DbzRR/XKb8ulNv6+CHyPF31xk7YOBfkGI8qjLoq06V+FyBfDSwL8KbLyeHm7KUZnLNQbk8yGLzB3iYKkRHlmUanQGaNMIJziWOkN+N9dECQQD0ONYRNZeuM8zd8XJTSdcIX4a3gy3GGCJxOzv16XHxD03GW6UNLmfPwenKu+cdrQeaqEixrCejXdAFz/7+BSMpAkEA8EaSOeP5Xr3ZrbiKzi6TGMwHMvC7HdJxaBJbVRfApFrE0/mPwmP5rN7QwjrMY+0+AbXcm8mRQyQ1+IGEembsdwJBAN6az8Rv7QnD/YBvi52POIlRSSIMV7SwWvSK4WSMnGb1ZBbhgdg57DXaspcwHsFV7hByQ5BvMtIduHcT14ECfcECQATeaTgjFnqE/lQ22Rk0eGaYO80cc643BXVGafNfd9fcvwBMnk0iGX0XRsOozVt5AzilpsLBYuApa66NcVHJpCECQQDTjI2AQhFc1yRnCU/YgDnSpJVm1nASoRUnU8Jfm3Ozuku7JUXcVpt08DFSceCEX9unCuMcT72rAQlLpdZir876\n" + "-----END RSA PRIVATE KEY-----\n"

	//公钥加密
	endata := SetEncrypt(publiukey, data)
	fmt.Println(endata)
	//私钥解密
	dedata := SetDecrypt(privatekey, endata)
	fmt.Println(dedata)
	//超长文本公钥加密
	datalist := SetLongEncrypt(publiukey, ddlong)

	fmt.Println(datalist)
	//超长文本私钥解密
	datade := SetDecryptArray(privatekey, datalist)
	fmt.Println(datade)

}

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

func setLongEncryptObject(privatekey string, data interface{}) []string {
	var list []string

	return list
}

//字符串转map
func RecResultJsonToPlain(json_str string) interface{} {

	var dat map[string]interface{}
	json.Unmarshal([]byte(json_str), &dat)
	return dat
}
