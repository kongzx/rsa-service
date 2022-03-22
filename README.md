# rsa-service

setLongEncrypt  数组=（秘钥，字符串）
 长文字加密 分成116个字节加密，是根据1024位长度RSA秘钥去做的
 返回一个数组类字符串，每串加密数据都是116字节 最后一个待定
setDecryptArray   字符串=（秘钥，数组）
数组解密 setLongEncrypt 生成数组，拼接成一串文字不限大小

setEncrypt 普通加密

setDecrypt 普通解密

#2020-03-28
nodejs 版本新增


#2020-04-03
C# 版本新增


#2020-04-04
PHP 版本新增 php_openssl php必须支持


#2020-04-08
JAVA 版本新增 

#2020-06-10
H5 版本新增 
