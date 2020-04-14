


var jsencrypt1=require("./jsencrypt.js")
var jsencrypt=new jsencrypt1();
//公钥
var publiukey='-----BEGIN PUBLIC KEY-----'+
'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlOJu6TyygqxfWT7eLtGDwajtNFOb9I5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4gwQco1KRMDSmXSMkDwIDAQAB'
+'-----END PUBLIC KEY-----';

//私钥
var privatekey='-----BEGIN RSA PRIVATE KEY-----\n'+
'MIICXQIBAAKBgQDlOJu6TyygqxfWT7eLtGDwajtNFOb9I5XRb6khyfD1Yt3YiCgQWMNW649887VGJiGr/L5i2osbl8C9+WJTeucF+S76xFxdU6jE0NQ+Z+zEdhUTooNRaY5nZiu5PgDB0ED/ZKBUSLKL7eibMxZtMlUDHjm4gwQco1KRMDSmXSMkDwIDAQABAoGAfY9LpnuWK5Bs50UVep5c93SJdUi82u7yMx4iHFMc/Z2hfenfYEzu+57fI4fvxTQ//5DbzRR/XKb8ulNv6+CHyPF31xk7YOBfkGI8qjLoq06V+FyBfDSwL8KbLyeHm7KUZnLNQbk8yGLzB3iYKkRHlmUanQGaNMIJziWOkN+N9dECQQD0ONYRNZeuM8zd8XJTSdcIX4a3gy3GGCJxOzv16XHxD03GW6UNLmfPwenKu+cdrQeaqEixrCejXdAFz/7+BSMpAkEA8EaSOeP5Xr3ZrbiKzi6TGMwHMvC7HdJxaBJbVRfApFrE0/mPwmP5rN7QwjrMY+0+AbXcm8mRQyQ1+IGEembsdwJBAN6az8Rv7QnD/YBvi52POIlRSSIMV7SwWvSK4WSMnGb1ZBbhgdg57DXaspcwHsFV7hByQ5BvMtIduHcT14ECfcECQATeaTgjFnqE/lQ22Rk0eGaYO80cc643BXVGafNfd9fcvwBMnk0iGX0XRsOozVt5AzilpsLBYuApa66NcVHJpCECQQDTjI2AQhFc1yRnCU/YgDnSpJVm1nASoRUnU8Jfm3Ozuku7JUXcVpt08DFSceCEX9unCuMcT72rAQlLpdZir876'+
'\n-----END RSA PRIVATE KEY-----'
 var strs="a65dfasf1s6f6as4f64a6f4s64gdh";
 for(var pp=0;pp<99;pp++){
	 strs=strs+"啊啊"+pp.toString()
 }
  console.log(strs.length)
 console.log(strs)
 // 加密
var pubblicData1=jsencrypt.setEncrypt(publiukey,"sss")
console.log(pubblicData1);
  // 加密
var pubblicData=jsencrypt.setLongEncrypt(publiukey,strs)
console.log(pubblicData);
//解密

var strc="p5JIeeaq7lTR9g3QtPJVrn/LJ4jQ9blernPcvBlSrvsgBHTqfsN6JcTb0dWTB+z3jaxe/tAv6OVoz4q2O+e70xE7yAdr51YauVV7TH7hyFpsDf+pXaU2BBPD/kQ8a3BJDpsKbv3MSwg8ENZncO1DALm2JT/YGPhSsvwUQz017fk=";
var opencs=jsencrypt.setDecrypt(privatekey,strc);
//console.log(opencs)
var openData=jsencrypt.setDecryptArray(privatekey,pubblicData);
console.log(openData);