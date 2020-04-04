<?php

//只支持117位加密
function setEncrypt($public_key,$data){
	$encrypted = "";
	$pu_key = openssl_pkey_get_public($public_key);
	openssl_public_encrypt($data,$encrypted,$pu_key);
	$encrypted = base64_encode($encrypted);
	return $encrypted;
	
}

//超长字符加密 返回数值
function setLongEncrypt($public_key,$data){
	$listdata=Array();
	
	$subject=$data;
	$spr=str_split($subject,116);
	
	
	for($i=0;$i<count($spr);$i++){
		
		$srt=setEncrypt($public_key,$spr[$i]);
		array_push($listdata,$srt);
		
	}
	return $listdata;
}

//解密
function setDecrypt($private_key,$data){
	$decrypted = "";
	$pi_key =  openssl_pkey_get_private($private_key);

	//这个函数可用来判断私钥是否是可用的，可用返回资源id Resource id
	openssl_private_decrypt(base64_decode($data),$decrypted,$pi_key);
	
	return $decrypted;
}


//数组解密
function setDecryptArray($private_key,$arraydata){
	
	$DecryptStr="";
	for($i=0;$i<count($arraydata);$i++){
		$DecryptStr=$DecryptStr.setDecrypt($private_key,$arraydata[$i]);
	}
	
	return $DecryptStr;
}
 
 