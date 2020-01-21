using System;
using System.ServiceProcess;
using System.Text;
using System.Configuration.Install;
using System.ComponentModel;

namespace PhantomService
{
    class Program
    {
        public static void Main(string[] args)
        {
            string usage = "PhantomService.exe (audit|remove)";
            if (args.Length == 1 && args[0].ToLower() == "audit")
            {
                RemovePhantomServices(false);
            }
            else if (args.Length == 1 && args[0].ToLower() == "remove")
            {
                RemovePhantomServices(true);
            }
            else
            {
                Console.WriteLine(usage);
            }

        }

        static void RemovePhantomServices(bool remove)
        {
            Console.OutputEncoding = Encoding.Unicode;
            ServiceController[] services = ServiceController.GetServices();

            foreach (ServiceController service in services)
            {
                string serviceName = service.ServiceName;

                if (Encoding.UTF8.GetByteCount(serviceName) != serviceName.Length)
                {
                    Console.WriteLine("[*] Found non-ASCII service: " + service.ServiceName);
                    if (remove)
                    {
                        try
                        {
                            ServiceInstaller ServiceInstallerObj = new ServiceInstaller();
                            InstallContext Context = new InstallContext(null, null);
                            ServiceInstallerObj.Context = Context;
                            ServiceInstallerObj.ServiceName = service.ServiceName;
                            ServiceInstallerObj.Uninstall(null);
                            Console.WriteLine();
                        }
                        catch (Win32Exception w)
                        {
                            Console.WriteLine("[-] Failed to remove {0} -> {1}", service.ServiceName, w.Message);
                        }
                    }
                }
            }
        }
    }
}
