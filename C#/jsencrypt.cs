using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using System.IO;

namespace ConsoleApp6
{


    public class jsencrypt
    {


        
        public static RSACryptoServiceProvider FromPEM(string pem)
        {
            var rsaParams = new CspParameters();
            rsaParams.Flags = CspProviderFlags.UseMachineKeyStore;
            var rsa = new RSACryptoServiceProvider(rsaParams);

            var param = new RSAParameters();

            var base64 = _PEMCode.Replace(pem, "");
            var data = RSA_Unit.Base64DecodeBytes(base64);
            if (data == null)
            {
                throw new Exception("PEM内容无效");
            }
            var idx = 0;

            //读取长度
            Func<byte, int> readLen = (first) => {
                if (data[idx] == first)
                {
                    idx++;
                    if (data[idx] == 0x81)
                    {
                        idx++;
                        return data[idx++];
                    }
                    else if (data[idx] == 0x82)
                    {
                        idx++;
                        return (((int)data[idx++]) << 8) + data[idx++];
                    }
                    else if (data[idx] < 0x80)
                    {
                        return data[idx++];
                    }
                }
                throw new Exception("PEM未能提取到数据");
            };
            //读取块数据
            Func<byte[]> readBlock = () => {
                var len = readLen(0x02);
                if (data[idx] == 0x00)
                {
                    idx++;
                    len--;
                }
                var val = data.sub(idx, len);
                idx += len;
                return val;
            };
            //比较data从idx位置开始是否是byts内容
            Func<byte[], bool> eq = (byts) => {
                for (var i = 0; i < byts.Length; i++, idx++)
                {
                    if (idx >= data.Length)
                    {
                        return false;
                    }
                    if (byts[i] != data[idx])
                    {
                        return false;
                    }
                }
                return true;
            };




            if (pem.Contains("PUBLIC KEY"))
            {
                /****使用公钥****/
                //读取数据总长度
                readLen(0x30);
                if (!eq(_SeqOID))
                {
                    throw new Exception("PEM未知格式");
                }
                //读取1长度
                readLen(0x03);
                idx++;//跳过0x00
                      //读取2长度
                readLen(0x30);

                //Modulus
                param.Modulus = readBlock();

                //Exponent
                param.Exponent = readBlock();
            }
            else if (pem.Contains("PRIVATE KEY"))
            {
                /****使用私钥****/
                //读取数据总长度
                readLen(0x30);

                //读取版本号
                if (!eq(_Ver))
                {
                    throw new Exception("PEM未知版本");
                }

                //检测PKCS8
                var idx2 = idx;
                if (eq(_SeqOID))
                {
                    //读取1长度
                    readLen(0x04);
                    //读取2长度
                    readLen(0x30);

                    //读取版本号
                    if (!eq(_Ver))
                    {
                        throw new Exception("PEM版本无效");
                    }
                }
                else
                {
                    idx = idx2;
                }

                //读取数据
                param.Modulus = readBlock();
                param.Exponent = readBlock();
                param.D = readBlock();
                param.P = readBlock();
                param.Q = readBlock();
                param.DP = readBlock();
                param.DQ = readBlock();
                param.InverseQ = readBlock();
            }
            else
            {
                throw new Exception("pem需要BEGIN END标头");
            }

            rsa.ImportParameters(param);
            return rsa;
        }
        static private Regex _PEMCode = new Regex(@"--+.+?--+|\s+");
        static private byte[] _SeqOID = new byte[] { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
        static private byte[] _Ver = new byte[] { 0x02, 0x01, 0x00 };


        //单个加密
        public string setEncrypt( string sPublicKey, string DataStr) {
            //方法1
            RSACryptoServiceProvider rsa = FromPEM(sPublicKey);
           // rsa.ImportCspBlob(Convert.FromBase64String(sPublicKey));
            //方法2
            byte[] cipherbytes;
            //rsa.FromXmlString(sPublicKey);
            byte[] DataByte = Encoding.UTF8.GetBytes(DataStr);
            cipherbytes = rsa.Encrypt(DataByte, true);

            return Convert.ToBase64String(cipherbytes);

         
        
        }

        public string[] setLongEncrypt(string sPublicKey, string DataStr)
        {
            
            ArrayList list = new ArrayList();
            String input ="/.{ 116}/ g";

            string[] substrings = Regex.Split(input, DataStr);
            foreach (string match in substrings)
            {
                list.Add(this.setEncrypt(sPublicKey, match));
            }
            string[] str = (string[])list.ToArray(typeof(string));
            return str;

        }

        public string setDecryptArray(string sPrivateKey, string[] DataStr)
        {
            StringBuilder strbuf = new StringBuilder();
            foreach (string match in DataStr)
            {
                strbuf.Append(this.setDecrypt(sPrivateKey, match));
            }
            
            return strbuf.ToString();

        }

        public string setDecrypt(string sPrivateKey, string DataStr)
        {
            
            byte[] cipherbytes;
            RSACryptoServiceProvider rsa =FromPEM(sPrivateKey);
       //     rsa.FromXmlString(sPrivateKey);

            cipherbytes=rsa.Decrypt(Convert.FromBase64String(DataStr), true);
            return Encoding.UTF8.GetString(cipherbytes).ToString();

        }
    }

    public class RSA_Unit
    {
        static public string Base64EncodeBytes(byte[] byts)
        {
            return Convert.ToBase64String(byts);
        }
        static public byte[] Base64DecodeBytes(string str)
        {
            try
            {
                return Convert.FromBase64String(str);
            }
            catch
            {
                return null;
            }
        }
        /// <summary>
        /// 把字符串按每行多少个字断行
        /// </summary>
        static public string TextBreak(string text, int line)
        {
            var idx = 0;
            var len = text.Length;
            var str = new StringBuilder();
            while (idx < len)
            {
                if (idx > 0)
                {
                    str.Append('\n');
                }
                if (idx + line >= len)
                {
                    str.Append(text.Substring(idx));
                }
                else
                {
                    str.Append(text.Substring(idx, line));
                }
                idx += line;
            }
            return str.ToString();
        }
    }

    static public class Extensions
    {
        /// <summary>
        /// 从数组start开始到指定长度复制一份
        /// </summary>
        static public T[] sub<T>(this T[] arr, int start, int count)
        {
            T[] val = new T[count];
            for (var i = 0; i < count; i++)
            {
                val[i] = arr[start + i];
            }
            return val;
        }
        static public void writeAll(this Stream stream, byte[] byts)
        {
            stream.Write(byts, 0, byts.Length);
        }
    }

}
