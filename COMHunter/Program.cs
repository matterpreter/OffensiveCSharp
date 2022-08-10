using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Runtime;
using System.Reflection;
using System.Runtime.InteropServices;

namespace COMHunter
{
    class Program
    {
        public static string usage = "Usage: COMHunter.exe [-inproc | -localserver] [-includesystem]";

        public struct COMServer
        {
            public string CLSID;
            public string ServerPath;
            public string Type;
        }
        
        // Trim function is not present on .NET versions < 4.6
        public static string TrimEnd(string source, string value)
        {
            if (!source.EndsWith(value)) {
                return source;
            }
            return source.Remove(source.LastIndexOf(value));
        }
        
        static void Main(string[] args)
        {
            List<COMServer> servers = new List<COMServer>();

            HashSet<string> exclusionSet = new HashSet<string>();
            exclusionSet.Add("ToString");
            exclusionSet.Add("GetLifetimeService");
            exclusionSet.Add("InitializeLifetimeService");
            exclusionSet.Add("CreateObjRef");
            exclusionSet.Add("Equals");
            exclusionSet.Add("GetHashCode");
            exclusionSet.Add("GetType");

            bool includeSystem = false;
            bool inproc = true;
            bool localserver = true;
            foreach(string arg in args) {
                if (arg.Equals("-includesystem")) {
                    includeSystem = true;
                } else if (arg.Equals("-inproc")) {
                    localserver = false;
                } else if (arg.Equals("-localserver")) {
                    inproc = false;
                } else {
                    Console.WriteLine(usage);
                    return;
                }
            }
            
            if (!inproc && !localserver) {
                inproc = localserver = true;	    
            }

            if (inproc && localserver)
            {
                servers = WMICollection("InprocServer32", includeSystem);
                servers.AddRange(WMICollection("LocalServer32", includeSystem));
            }
            else if (inproc)
            {
                servers = WMICollection("InprocServer32", includeSystem);
            }
            else if (localserver)
            {
                servers = WMICollection("LocalServer32", includeSystem);
            }
            else
            {
                Console.WriteLine(usage);
                return;
            }

            foreach (COMServer server in servers)
            {
                Console.WriteLine("{0} {1} ({2})", server.CLSID, server.ServerPath, server.Type);
                Type t = Type.GetTypeFromCLSID(new Guid(server.CLSID));
                MethodInfo[] methods = t.GetMethods(BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public);
                foreach (MethodInfo m in methods) {
                        if(exclusionSet.Contains(m.Name)) {
                            continue;
                        }
                    Console.WriteLine("\t- " + m.Name);
                }
            }
            return;
        }

        static List<COMServer> WMICollection(string type, bool includeSystem)
        {
            List<COMServer> comServers = new List<COMServer>();
            try
            {
                ManagementObjectSearcher searcher =new ManagementObjectSearcher("root\\CIMV2", "SELECT * FROM Win32_ClassicCOMClassSetting");
                foreach (ManagementObject queryObj in searcher.Get())
                {
                    // Collect InProcServer32 values
                    string svrObj = Convert.ToString(queryObj[type]);
                    string svr = TrimEnd(Environment.ExpandEnvironmentVariables(svrObj), "\"");

                    if (!string.IsNullOrEmpty(svr)
                        && svr.ToLower().StartsWith(@"c:\")
                        && File.Exists(svr)) // Make sure the file exists
                    {
                        //Ignore OS components, if flag isn't set
                        if(!includeSystem && svr.ToLower().Contains(@"c:\windows\")) {
                            continue;
                        }
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
