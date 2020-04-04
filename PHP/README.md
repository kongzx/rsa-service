# php 解密

php 版本必须支持 php_openssl


//单个加密
$EnStr=setEncrypt($publiukey,"666222");


//解密
$DeStr=setDecrypt($privatekey,$EnStr);


//超长字符串加密
$strArr=setLongEncrypt($publiukey,$datas);


//列表解密
$strTest=setDecryptArray($privatekey,$strArr);
