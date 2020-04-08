/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.kongzhixiong.Rsa;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;


public class jsencrypt {
    private static Map<Integer, String> keyMap = new HashMap<Integer, String>();  //用于封装随机产生的公钥与私钥
	

    
    public static String pemToKey(String pem){
        if(pem==null) return "";
        if(pem.indexOf("KEY-----")>0){
            pem = pem.substring(pem.indexOf("KEY-----")+"KEY-----".length());
        }
        if(pem.indexOf("-----END")>0){
            pem = pem.substring(0,pem.indexOf("-----END"));
        }
        return pem.replace("\n","");
    }
    public static String encrypt(String publicKey,String str) throws Exception{
		//base64编码的公钥
	byte[] decoded = Base64.decodeBase64(publicKey);
	RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
	//RSA加密
	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.ENCRYPT_MODE, pubKey);
	String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
	return outStr;
    }
    public String setEncrypt(String publicKey,String str) {
		//base64编码的公钥
         String StrData="";
	 try{
             StrData=encrypt(pemToKey(publicKey),str);
          }catch(Exception e){
            return "";
          }
        return StrData;
    }
   
    public static List<String> getStrList(String inputString, int length) {
        int size = inputString.length() / length;
        if (inputString.length() % length != 0) {
            size += 1;
        }
        return getStrList(inputString, length, size);
    }
    public static List<String> getStrList(String inputString, int length,int size) {
        List<String> list = new ArrayList<String>();
        for (int index = 0; index < size; index++) {
            String childStr = substring(inputString, index * length,
                    (index + 1) * length);
            list.add(childStr);
        }
        return list;
    }
    public static String substring(String str, int f, int t) {
        if (f > str.length())
            return null;
        if (t > str.length()) {
            return str.substring(f, str.length());
        } else {
            return str.substring(f, t);
        }
    }
   public List<String> setLongEncrypt(String publicKey,String str) {
		//base64编码的公钥
        List<String> list = new ArrayList<String>();
	List<String> enstrlist = getStrList(str,116);
        
        for(int i=0;i<enstrlist.size();i++){
            String stru = (String)enstrlist.get(i);
           String stren = setEncrypt(publicKey,stru);
           list.add(stren);
        }
        return list;
    }
    
	/** 
	 * RSA私钥解密
	 *  
	 * @param str 
	 *            加密字符串
	 * @param privateKey 
	 *            私钥 
	 * @return kongzx
	 * @throws Exception 
	 *             解密过程中的异常信息 
	 */  
    public static String decrypt( String privateKey,String str) throws Exception{
		//64位解码加密后的字符串
	byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
		//base64编码的私钥

        byte[] privateKeyBytes = Base64.decodeBase64(privateKey.getBytes("UTF-8"));   
         // 取得私钥  for PKCS#1
        RSAPrivateKeyStructure asn1PrivKey = new RSAPrivateKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(privateKeyBytes));
        RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(asn1PrivKey.getModulus(), asn1PrivKey.getPrivateExponent());  
        KeyFactory keyFactory= KeyFactory.getInstance("RSA");
         RSAPrivateKey priKey = (RSAPrivateKey)keyFactory.generatePrivate(rsaPrivKeySpec);   

        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
       cipher.init(Cipher.DECRYPT_MODE, priKey);  
        //RSA解密
	String outStr = new String(cipher.doFinal(inputByte));
	return outStr;
    }

        /**
         * 
         * 解码接口
         * 
         * 
         */
    public String setDecrypt(String publicKey,String str) {
		//base64编码的公钥
        String StrData="";
	try{
            StrData=decrypt(pemToKey(publicKey),str);
         }catch(Exception e){
               return "";
         }
       return StrData;
    }
    
    public String setDecryptArray(String publicKey,List<String> str) {
        
        String StrData="";
	 for(int i=0;i<str.size();i++){
            StrData=StrData+setDecrypt(publicKey,str.get(i));
            
        }
        return StrData;
        
    }
    
}
