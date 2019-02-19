using System;
using System.IO;
using System.IO.Packaging;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace EncryptedZIP
{
    class Program
    {
        [DllImport("kernel32.dll", EntryPoint = "RtlZeroMemory")]
        public static extern bool RtlZeroMemory(IntPtr Destination, int Length);

        public static void AddToArchive(string archiveName, string file)
        {
            //System.IO.Compression is not supported until .NET 4.0, so we get this clunky method derived from https://goo.gl/bF8wL1
            using (Package zip = Package.Open(archiveName, FileMode.OpenOrCreate))
            {
                string archivePath = @".\" + Path.GetFileName(file);
                Uri uri = PackUriHelper.CreatePartUri(new Uri(archivePath, UriKind.Relative));
                if (zip.PartExists(uri))
                {
                    zip.DeletePart(uri);
                }
                PackagePart pkgPart = zip.CreatePart(uri, "", CompressionOption.Normal);
                using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read))
                {
                    using (Stream archiveDest = pkgPart.GetStream())
                    {
                        CopyStream(fs, archiveDest);
                    }
                }
            }
        }

        private const long BUFFER_SIZE = 4096;

        private static void CopyStream(FileStream inStream, Stream outStream)
        {
            long bufSize = inStream.Length < BUFFER_SIZE ? inStream.Length : BUFFER_SIZE;
            byte[] buf = new byte[bufSize];
            int bytesRead = 0;
            long bytesWritten = 0;
            while ((bytesRead = inStream.Read(buf, 0, buf.Length)) != 0)
            {
                outStream.Write(buf, 0, bytesRead);
                bytesWritten += bufSize;
            }
        }

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

        public static void Encrypter(string inputFile, string password)
        {

            FileStream fsCrypt = new FileStream(Path.GetFileNameWithoutExtension(inputFile) + ".aes.zip", FileMode.Create); //Output.aes.zip
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            
            //Setup AES256 CFB
            RijndaelManaged AES = new RijndaelManaged();
            AES.KeySize = 256;
            AES.BlockSize = 128;
            AES.Padding = PaddingMode.PKCS7;
            byte[] salt = GenerateSalt();
            var key = new Rfc2898DeriveBytes(passwordBytes, salt, 50000); //PBKDF2
            AES.Key = key.GetBytes(AES.KeySize / 8);
            AES.IV = key.GetBytes(AES.BlockSize / 8);
            AES.Mode = CipherMode.CFB;

            fsCrypt.Write(salt, 0, salt.Length);
            CryptoStream cs = new CryptoStream(fsCrypt, AES.CreateEncryptor(), CryptoStreamMode.Write);
            FileStream fs = new FileStream(inputFile, FileMode.Open);

            byte[] buffer = new byte[1048576]; //Allocate 1MB instead of the whole target file
            int read;
     
            try
            {
                while ((read = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cs.Write(buffer, 0, read);
                }
                fs.Close();
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: " + e.Message);
            }
            finally
            {
                cs.Close();
                fsCrypt.Close();
            }
        }

        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("[-] Usage: EncryptedZIP.exe <path to compress> <encryption key>");
                Environment.Exit(1);
            }

            //Generate a random filename for the archive
            Random random = new Random();
            string characters = "0123456789";
            characters += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            characters += "abcdefghijklmnopqrstuvwxyz";
            StringBuilder randomName = new StringBuilder(8);
            for (int i = 0; i < 8; i++)
            {
                randomName.Append(characters[random.Next(characters.Length)]);
            }
            string archiveName = randomName.ToString() + ".zip";

            if (!Directory.Exists(args[0]) && !File.Exists(args[0]))
            {
                Console.WriteLine("[-] Can't find the path you supplied. Does it exist?");
                Environment.Exit(1);
            }

            FileAttributes pathAttr = File.GetAttributes(args[0]);
            if ((pathAttr & FileAttributes.Directory) == FileAttributes.Directory)
            {
                Console.WriteLine("[+] Path provided is a directory");
                string[] files = Directory.GetFiles(args[0]);
                foreach (string fileName in files)
                {
                    AddToArchive(archiveName, fileName);
                    Console.WriteLine("[+] Added {0} to the archive", fileName);
                }

            }

            else
            {
                Console.WriteLine("[+] Path provided is a single file");
                AddToArchive(archiveName, args[0]);
            }
            Console.WriteLine("[+] Created ZIP archive " + archiveName);
            Console.WriteLine("[+] Encrypting the archive...");
            string passwd = args[1];
            GCHandle handle = GCHandle.Alloc(passwd, GCHandleType.Pinned); //Pin the password
            try
            {
                Encrypter(archiveName, passwd);
                Console.WriteLine("[+] Wrote encrypted archive " + Path.GetFileNameWithoutExtension(archiveName) + ".aes.zip to disk!");
            }
            catch
            {
                Console.WriteLine("[-] Something went wrong encrypting the archive. {0} left on disk.", archiveName);
            }
                
            //Cleanup
            RtlZeroMemory(handle.AddrOfPinnedObject(), passwd.Length * 2); //Zero out the pinned password on the heap
            handle.Free();
            Console.WriteLine("[+] Removed encryption key from memory");
            File.Delete(archiveName);
            Console.WriteLine("[+] Deleted unecrypted archive");

            Console.WriteLine("[+] Ready for exfil");
        }
    }
}
