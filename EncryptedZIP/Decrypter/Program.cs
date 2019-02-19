using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Decrypter
{
    class Program
    {
        public static byte[] GenerateSalt()
        {
            byte[] data = new byte[32];
            RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
            for (int i = 0; i < 10; i++)
            {
                rng.GetBytes(data);
            }
            return data;
        }

        public static void Decrypter(string inputFile, string outputFile, string password)
        {
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] salt = new byte[32];

            FileStream fsCrypt = new FileStream(inputFile, FileMode.Open);
            fsCrypt.Read(salt, 0, salt.Length);
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000);
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Padding = PaddingMode.PKCS7;
            AES.Mode = CipherMode.CFB;

            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateDecryptor(), CryptoStreamMode.Read);
            FileStream fs = new FileStream(outputFile, FileMode.Create);
            
            byte[] buffer = new byte[1048576];
            int read;

            try
            {
                while ((read = cs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    fs.Write(buffer, 0, read);
                }
            }
            catch (CryptographicException ex_CryptographicException)
            {
                Console.WriteLine("[-] Error decrypting the archive: " + ex_CryptographicException.Message);
                Environment.Exit(1); //Usually due to invalid key
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error: " + e.Message);
                Environment.Exit(1);
            }

            try
            {
                cs.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Error closing the crypto stream: " + e.Message);
                Environment.Exit(1);
            }
            finally
            {
                fs.Close();
                fsCrypt.Close();
            }
        }
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("[-] Usage: Decrypter.exe <path to encrypted ZIP> <encryption key>");
                Environment.Exit(1);
            }
            Console.WriteLine("[+] Decrypting " + args[0]);
            string[] fileName = (Path.GetFileNameWithoutExtension(args[0])).Split('.');
            string outFile = fileName[0] + ".zip";
            try
            {
                Decrypter(args[0], outFile, args[1]);
                Console.WriteLine("[+] Decrypted {0} successfully!", outFile);
            }
            catch
            {
                Console.WriteLine("[-] Something went wrong decrypting the file.");
                Environment.Exit(1);
            }
        }
    }
}
