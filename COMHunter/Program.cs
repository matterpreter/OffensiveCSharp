using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Reflection;

namespace COMHunter
{
    class Program
    {
        public static string usage = "Usage: COMHunter.exe <-inproc|-localserver>";

        public struct COMServer
        {
            public string CLSID;
            public string ServerPath;
            public string Type;
        }
        
        static void Main(string[] args)
        {
            List<COMServer> servers = new List<COMServer>();

            if (args.Length == 0)
            {
                servers = WMICollection("InprocServer32");
                servers.AddRange(WMICollection("LocalServer32"));
            }
            else if(args[0].ToLower() == "-inproc")
            {
                servers = WMICollection("InprocServer32");
            }
            else if (args[0].ToLower() == "-localserver")
            {
                servers = WMICollection("LocalServer32");
            }
            else
            {
                Console.WriteLine(usage);
                return;
            }

            string[] defaultMethods = new string[] { "Equals", "GetHashCode", "GetType", "ToString" };

            foreach (COMServer server in servers)
            {
                Console.WriteLine("{0} {1} ({2})", server.CLSID, server.ServerPath, server.Type);

                // If the COM server is a .NET assembly, get the path of the actual DLL
                if (server.ServerPath.ToLower().Contains("mscoree.dll"))
                {
                    object assembly = Registry.GetValue(string.Format("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\CLSID\\{0}\\InprocServer32\\1.0.0.0", server.CLSID), "CodeBase", null);

                    if (assembly != null)
                    {
                        Console.WriteLine(string.Format(".NET Assembly: {0}", assembly));

                        Type assembly_type = Type.GetTypeFromCLSID(Guid.Parse(server.CLSID));

                        foreach (MethodInfo mInfo in assembly_type.GetMethods())
                        {
                            // Print any non-default methods defined in the DLL
                            if (defaultMethods.Any(s => mInfo.Name.Contains(s)))
                            {
                                Console.WriteLine(string.Format("  Method: {0}", mInfo.Name));
                            }
                        }
                    }
                }
            }
            return;
        }

        static List<COMServer> WMICollection(string type)
        {
            List<COMServer> comServers = new List<COMServer>();
            try
            {
                ManagementObjectSearcher searcher =new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_ClassicCOMClassSetting");
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    // Collect InProcServer32 values
                    string svrObj = Convert.ToString(queryObj[type]);
                    string svr = Environment.ExpandEnvironmentVariables(svrObj).Trim('"');

                    if (!string.IsNullOrEmpty(svr)
                        // Commented out so COMHunter can find "mscoree.dll" which is used by .NET assemblies
                        //&& svr.ToLower().StartsWith(@"c:\") // Filter out things like combase.dll and ole32.dll
                        && !svr.ToLower().Contains(@"c:\windows\") // Ignore OS components
                        && File.Exists(svr)) // Make sure the file exists
                    {
                        comServers.Add(new COMServer
                        {
                            CLSID = queryObj["ComponentId"].ToString(),
                            ServerPath = svr,
                            Type = type
                        });
                    }
                }
            }
            catch (ManagementException ex)
            {
                Console.WriteLine("[-] An error occurred while querying for WMI data: " + ex.Message);
                return null;
            }

            // Sort by path
            comServers = comServers.OfType<COMServer>().OrderBy(x => x.ServerPath).ToList();
            return comServers;
        }
    }
}
