using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SqlServerExpressBackup
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Clear();
            if (args == null || args.Length < 2)
            {
                Console.WriteLine("參數:");
                Console.WriteLine("-e Encryption 將連線設定加密(必須為第一個參數)");
                Console.WriteLine("-c {加密字串} Config 使用加密字串做設定檔(必須為第一個參數)");
                Console.WriteLine("-s {資料庫主機名稱與位址} Server 伺服器位置");
                Console.WriteLine("-d {資料庫名稱} DataBase");
                Console.WriteLine("-u {帳號} UserName 使用者名稱");
                Console.WriteLine("-p {密碼} Password 使用者密碼");
                Console.WriteLine("-f {檔案路徑} 伺服器備份資料夾路徑(資料庫名稱_備份時間.bak)");
                return;
            }

            if (args[0] == "-c")
            {
                args = Decrypt(args[1]).Split(new[] {"\r\n"}, StringSplitOptions.None);
            }

            var argList = new Dictionary<string, string>();
            for (var i = 0; i < args.Length; i++)
            {
                if (args[i] == "-e" || !args[i].StartsWith("-") || args[i].Length < 2)
                {
                    continue;
                }

                argList.Add(args[i], i + 1 >= args.Length ? string.Empty : args[i + 1].Replace("\"", string.Empty));
            }


            if (!argList["-f"].EndsWith("\\"))
            {
                argList["-f"] += "\\";
            }

            var notReady = false;
            if (!argList.ContainsKey("-s"))
            {
                Console.WriteLine("-s {資料庫主機名稱與位址}");
                notReady = true;
            }
            if (!argList.ContainsKey("-d"))
            {
                Console.WriteLine("-d {資料庫名稱}");
                notReady = true;
            }
            if (!argList.ContainsKey("-u"))
            {
                Console.WriteLine("-u {帳號}");
                notReady = true;
            }
            if (!argList.ContainsKey("-p"))
            {
                Console.WriteLine("-p {密碼}");
                notReady = true;
            }
            if (!argList.ContainsKey("-f"))
            {
                Console.WriteLine("-f {檔案路徑}");
                notReady = true;
            }

            if (notReady)
            {
                return;
            }

            if (args[0] == "-e")
            {
                var encryptString = string.Empty;

                foreach (var key in argList.Keys)
                {
                    encryptString += $"{key}\r\n{argList[key]}\r\n";
                }

                Console.WriteLine("字串已加密:");
                Console.WriteLine("{0}", Encrypt(encryptString));
                return;
            }



            SqlConnection connection = null;
            try
            {
                connection = new SqlConnection($"Data Source={argList["-s"]};Initial Catalog={argList["-d"]};Persist Security Info=True;User ID={argList["-a"]};Password={argList["-p"]}");
                connection.Open();

                #region SqlCommandString
                var sqlCommandString = @"
DECLARE 
@backupTime VARCHAR(20)
DECLARE 
@filePath VARCHAR(1000) 
SELECT @backupTime = (CONVERT(VARCHAR(8), GETDATE(), 112) + REPLACE(CONVERT(VARCHAR(5), GETDATE(), 114), ':', '')) 
SELECT @filePath = @FileFolder + @DbName + '_' + @backupTime + '.bak'
backup database @DbName to disk=@filePath
";

                #endregion
                var command = connection.CreateCommand();
                command.CommandTimeout = int.MaxValue;
                command.CommandType = System.Data.CommandType.Text;
                command.CommandText = sqlCommandString;

                command.Parameters.Add("@FileFolder", SqlDbType.NVarChar).Value = argList["-f"];
                command.Parameters.Add("@DbName", SqlDbType.NVarChar).Value = argList["-d"];
                
                command.ExecuteNonQuery();

                Console.WriteLine("備份完成");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
                System.Threading.Thread.Sleep(5000);
            }
            finally
            {
                if (connection != null)
                {
                    connection.Close();
                    connection.Dispose();
                }
            }

        }


        #region Encryption / Decryption 加解密

        #region salt 加密種子
        private static string _salt = "Msg";
        /// <summary>
        /// 加密種子
        /// </summary>
        public static string salt
        {
            get
            {
                return _salt;
            }
            set
            {
                _salt = value;
            }
        }
        #endregion

        #region rgbKey
        private static byte[] rgbKey(string salt)
        {
            return ASCIIEncoding.ASCII.GetBytes((salt + System.Math.PI.ToString()).Substring(0, 8));
        }
        #endregion

        #region rgbIV
        private static byte[] rgbIV(string salt)
        {
            return ASCIIEncoding.ASCII.GetBytes((salt + System.Math.Sqrt(2.0).ToString()).Substring(0, 8));
        }
        #endregion

        /// <summary>
        /// 加密文字。
        /// </summary>
        /// <param name="plainText">要加密的文字。</param>
        /// <param name="EncryptText">已加密文字。</param>
        /// <returns>成功或失敗。</returns>
        public static string Encrypt(string plainText)
        {
            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoProvider.CreateEncryptor(rgbKey(_salt), rgbIV(_salt)), CryptoStreamMode.Write);
            StreamWriter writer = new StreamWriter(cryptoStream);
            writer.Write(plainText);
            writer.Flush();
            cryptoStream.FlushFinalBlock();
            writer.Flush();

            return Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length);
        }
        #endregion

        #region Decrypt 解密文字
        /// <summary>
        /// 解密文字。
        /// </summary>
        /// <param name="cryptedText">加密的文字。</param>
        /// <param name="PlainText">已解密的文字。</param>
        /// <returns>成功或失敗。</returns>
        public static string Decrypt(string cryptedText)
        {
            if (string.IsNullOrEmpty(cryptedText))
            {
                return string.Empty;
            }

            DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
            MemoryStream memoryStream = new MemoryStream(Convert.FromBase64String(cryptedText));
            CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoProvider.CreateDecryptor(rgbKey(_salt), rgbIV(_salt)), CryptoStreamMode.Read);
            StreamReader reader = new StreamReader(cryptoStream);

            return reader.ReadToEnd();

        }
        #endregion
    }
}
