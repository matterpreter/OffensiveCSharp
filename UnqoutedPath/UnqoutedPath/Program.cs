using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.ServiceProcess;

namespace UnqoutedPath
{
    class Program
    {
        private static string GetServiceInstallPath(string serviceName)
        {
            RegistryKey regkey;
            regkey = Registry.LocalMachine.OpenSubKey(string.Format(@"SYSTEM\CurrentControlSet\services\{0}", serviceName));

            if (regkey.GetValue("ImagePath") == null)
                return "Not Found";
            else
                return regkey.GetValue("ImagePath").ToString();
        }

        static void Main(string[] args)
        {
            List<string> vulnSvcs = new List<string>();
            RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\");
            foreach (var service in services.GetSubKeyNames())
            {
                RegistryKey imagePath = services.OpenSubKey(service);
                foreach (var value in imagePath.GetValueNames())
                {
                    string path = Convert.ToString(imagePath.GetValue("ImagePath"));
                    if (!string.IsNullOrEmpty(path))
                    {
                        if (!path.Contains("\"") && path.Contains(" ")) //If path is unquoted and has a space...
                        {
                            if (!path.Contains("System32") && !path.Contains("system32") && !path.Contains("SysWow64")) //...and is not System32/SysWow64
                            {
                                vulnSvcs.Add(path);
                            }
                        }
                    }
                    
                }
                
            }
            List<string> distinctPaths = vulnSvcs.Distinct().ToList();
            if (!distinctPaths.Any())
            {
                Console.WriteLine("[-] Couldn't find any unquoted services paths");
            }
            else
            {
                Console.WriteLine("[+] Unquoted service paths found");
                foreach (string path in distinctPaths)
                {
                    Console.WriteLine(path);
                }
            }
        }
    }
}
