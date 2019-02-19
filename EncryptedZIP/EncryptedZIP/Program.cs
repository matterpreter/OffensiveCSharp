using System;
using System.IO;
using System.IO.Packaging;

namespace EncryptedZIP
{
    class Program
    {
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

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[-] Usage: EncryptedZIP.exe <path to compress> <encryption key> ");
            }

            FileAttributes pathAttr = File.GetAttributes(args[0]);
            if ((pathAttr & FileAttributes.Directory) == FileAttributes.Directory)
            {
                Console.WriteLine("[+] Path provided is a directory");
                string[] files = Directory.GetFiles(args[0]);
                foreach (string fileName in files)
                    AddToArchive("Output.zip", fileName);
            }

            else
            {
                Console.WriteLine("[+] Path provided is a single file");
                AddToArchive("Output.zip", args[0]);
            }
        }
    }
}
