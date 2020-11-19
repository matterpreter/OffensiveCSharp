using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using Mono.Cecil;

namespace InspectAssembly
{
    class Program
    {
        private const string BF_DESERIALIZE = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize";
        private const string DC_JSON_READ_OBJ = "System.Runtime.Serialization.Json.DataContractJsonSerializer::ReadObject";
        private const string DC_XML_READ_OBJ = "System.Runtime.Serialization.Xml.DataContractSerializer::ReadObject";
        private const string JS_SERIALIZER_DESERIALIZE = "System.Web.Script.Serialization.JavaScriptSerializer::Deserialize";
        private const string LOS_FORMATTER_DESERIALIZE = "System.Web.UI.LosFormatter::Deserialize";
        private const string NET_DATA_CONTRACT_READ_OBJ = "System.Runtime.Serialization.NetDataContractSerializer::ReadObject";
        private const string NET_DATA_CONTRACT_DESERIALIZE = "System.Runtime.Serialization.NetDataContractSerializer::Deserialize";
        private const string OBJ_STATE_FORMATTER_DESERIALIZE = "System.Web.UI.ObjectStateFormatter::Deserialize";
        private const string SOAP_FORMATTER_DESERIALIZE = "System.Runtime.Serialization.Formatters.Soap.SoapFormatter::Deserialize";
        private const string XML_SERIALIZER_DESERIALIZE = "System.Xml.Serialization.XmlSerializer::Deserialize";
        private const string REGISTER_CHANNEL = "System.Runtime.Remoting.Channels.ChannelServices::RegisterChannel";
        private const string WCF_SERVER_STRING = "System.ServiceModel.ServiceHost::AddServiceEndpoint";
        private const string WCF_CLIENT_STRING = "System.ServiceModel.ChannelFactory::CreateChannel";

        private static string[] wcfServerGadgetNames = { WCF_SERVER_STRING };

        static Dictionary<string, object> ArgParser(string[] args)
        {
            Dictionary<string, object> result = new Dictionary<string, object>();
            
            foreach(string arg in args)
            {
                if (!arg.Contains("="))
                {
                    Console.WriteLine("Argument '{0}' is not of format 'key=val'. Skipping.", arg);
                    continue;
                }
                string[] parts = arg.Split(new char[] { '=' }, 2);
                if (parts.Length != 2)
                {
                    Console.WriteLine("Argument '{0}' contained an empty value. Skipping.", arg);
                    continue;
                }
                result[parts[0].ToLower()] = parts[1];
            }
            if (!result.ContainsKey("path") && !result.ContainsKey("pid"))
                throw new Exception("Not enough arguments given. Must be passed 'path' or 'pid' to parse.");
            if (result.ContainsKey("path") && result.ContainsKey("pid"))
            {
                throw new Exception("Must be passed path or pid as arguments, not both.");
            }
            if (result.ContainsKey("path"))
            {
                string path = result["path"].ToString();
                if ((path.StartsWith("'") && path.EndsWith("'")) ||
                    (path.StartsWith("\"") && path.EndsWith("\"")))
                {
                    path = path.Substring(1, path.Length - 2);
                    result["path"] = path;
                }
                if (!File.Exists((string)result["path"]) && !Directory.Exists((string)result["path"]))
                    throw new Exception(String.Format("File or directory {0} does not exist.", result["path"]));
            } else
            {
                string pids = (string)result["pid"];
                if (pids.Contains(","))
                {
                    var pidInts = pids.Split(',');
                    List<int> pidList = new List<int>();
                    foreach(var pid in pidInts)
                    {
                        if (int.TryParse(pid, out int iRes))
                        {
                            pidList.Add(iRes);
                        }
                    }
                    result["pid"] = pidList.ToArray();
                } else if (result["pid"].ToString().ToLower() != "all")
                {
                    if (int.TryParse(result["pid"].ToString(), out int iRes))
                    {
                        result["pid"] = iRes;
                    } else
                    {
                        throw new Exception(string.Format("Given invalid pid: {0}. Argument 'pid' must be one of integer, integer list, or value 'all'.", result["pid"].ToString()));
                    }
                }
            }
            return result;
        }

        static AssemblyGadgetAnalysis InspectAssembly(string path)
        {
            string targetAssembly = path;

            // Make sure that the target is actually an assembly before we get started
            AssemblyName assemblyName = AssemblyName.GetAssemblyName(targetAssembly);

            return AnalyzeAssembly(targetAssembly);
        }

        static string Usage()
        {
            return @"
Example Usage:
    InspectAssembly.exe path=""C:\Windows\System32\powershell.exe""
    InspectAssembly.exe path=""C:\Windows\System32\""    
    InspectAssembly.exe pid=12044
    InspectAssembly.exe pid=12044,12300 outfile=proc_analysis.txt
    InspectAssembly.exe pid=all

Arguments:
    path    - A path to a .NET binary to analyze, or a directory containing .NET assemblies.
    pid     - An integer or comma-separated list of integers to analyze.
              If the keyword 'all' is passed, then all processes are analyzed.
    outfile - File to write results to.
";
        }

        static void Main(string[] args)
        {

            Dictionary<string, object> arguments;
            try
            {
                arguments = ArgParser(args);
            } catch (Exception ex)
            {
                Console.WriteLine("[-] Error parsing arguments. {0}", ex.Message);
                Console.WriteLine(Usage());
                return;
            }
            List<AssemblyGadgetAnalysis> results = new List<AssemblyGadgetAnalysis>();
            if (arguments.ContainsKey("path"))
            {
                string path = arguments["path"].ToString();
                if (File.Exists(path))
                {
                    try
                    {
                        AssemblyName assemblyName = AssemblyName.GetAssemblyName(path);
                        results.Add(InspectAssembly(path));
                    } catch { }
                } else
                {
                    foreach(var f in Directory.GetFiles(path))
                    {
                        try
                        {
                            AssemblyName assemblyName = AssemblyName.GetAssemblyName(f);
                            results.Add(InspectAssembly(f));
                        } catch { continue; }
                    }
                }
            } else
            {
                int[] test;
                List<Process> procs = new List<Process>();
                object pidArg = arguments["pid"];
                if (pidArg is int)
                {
                    try
                    {
                        procs.Add(Process.GetProcessById((int)pidArg));
                    } catch (Exception ex)
                    {
                        Console.WriteLine("[-] Error: {0}", ex.Message);
                        return;
                    }
                } else if (pidArg is int[])
                {
                    foreach(int id in (int[])pidArg)
                    {
                        try
                        {
                            procs.Add(Process.GetProcessById((int)id));
                        } catch (Exception ex)
                        {
                            continue;
                        }
                    }
                } else
                {
                    // all case
                    foreach (var proc in Process.GetProcesses())
                    {
                        try
                        {
                            procs.Add(proc);
                        }
                        catch (Exception ex)
                        { continue; }
                    }
                }
                if (procs.Count == 0)
                {
                    Console.WriteLine("[-] Failed to acquire any processes given pid argument: {0}", pidArg);
                    return;
                }
                foreach(var proc in procs)
                {
                    try
                    {
                        string pathName = proc.MainModule.FileName;
                        AssemblyName assemblyName = AssemblyName.GetAssemblyName(pathName);
                        results.Add(InspectAssembly(pathName));
                    } catch (Exception ex)
                    { continue; }
                }
            }
            string resultStr = "";
            if (results.Count > 0)
            {
                foreach(var res in results)
                {
                    string temp = res.ToString();
                    if (!string.IsNullOrEmpty(temp))
                        resultStr += res.ToString() +"\n";
                }
                if (!string.IsNullOrEmpty(resultStr))
                {
                    Console.WriteLine(resultStr);
                    if (arguments.ContainsKey("outfile"))
                    {
                        if (File.Exists((string)arguments["outfile"]))
                        {
                            Console.WriteLine("[-] File {0} already exists - will not write data to outfile.", arguments["outfile"]);
                        }
                        else
                        {
                            try
                            {
                                File.WriteAllText(arguments["outfile"].ToString(), resultStr);
                                Console.WriteLine("[+] Wrote results to {0}", arguments["outfile"]);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("[-] Failed to write output file: {0}", arguments["outfile"]);
                            }
                        }
                    }
                } else
                {
                    Console.WriteLine("[-] No results to display.");
                }
            } else
            {
                Console.WriteLine("[-] No results to display.");
            }
        }

        internal struct AssemblyGadgetAnalysis
        {
            string AssemblyName;
            internal string[] RemotingChannels;
            internal bool IsWCFServer;
            internal bool IsWCFClient;
            Dictionary<string, MethodInfo[]> GadgetCalls;
            Dictionary<string, MethodInfo[]> ServerCalls;
            Dictionary<string, MethodInfo[]> ClientCalls;

            public AssemblyGadgetAnalysis(string assemblyName, GadgetItem[] items)
            {
                AssemblyName = assemblyName;
                IsWCFClient = false;
                IsWCFServer = false;
                Dictionary<string, List<MethodInfo>> temp = new Dictionary<string, List<MethodInfo>>();
                Dictionary<string, List<MethodInfo>> tempClient = new Dictionary<string, List<MethodInfo>>();
                Dictionary<string, List<MethodInfo>> tempServer = new Dictionary<string, List<MethodInfo>>();
                List<string> dnRemotingChannels = new List<string>();
                List<GadgetItem> serverGadgets = new List<GadgetItem>();
                List<GadgetItem> clientGadgets = new List<GadgetItem>();
                foreach(var gadget in items)
                {
                    if (gadget.IsWCFClient && !tempClient.ContainsKey(gadget.GadgetName))
                        tempClient[gadget.GadgetName] = new List<MethodInfo>();
                    else if (gadget.IsWCFServer && !tempServer.ContainsKey(gadget.GadgetName))
                        tempServer[gadget.GadgetName] = new List<MethodInfo>();
                    else if (!temp.ContainsKey(gadget.GadgetName))
                        temp[gadget.GadgetName] = new List<MethodInfo>();
                    if (gadget.IsWCFClient)
                    {
                        tempClient[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    } else if (gadget.IsWCFServer)
                    {
                        tempServer[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    } else
                    {
                        temp[gadget.GadgetName].Add(new MethodInfo()
                        {
                            MethodName = gadget.MethodAppearance,
                            FilterLevel = gadget.FilterLevel
                        });
                    }
                    if (gadget.IsDotNetRemoting)
                        dnRemotingChannels.Add(gadget.RemotingChannel);
                }
                RemotingChannels = dnRemotingChannels.ToArray();
                GadgetCalls = new Dictionary<string, MethodInfo[]>();
                ClientCalls = new Dictionary<string, MethodInfo[]>();
                ServerCalls = new Dictionary<string, MethodInfo[]>();
                foreach (var key in temp.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        GadgetCalls[key] = temp[key].ToArray();
                }
                foreach (var key in tempClient.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        ClientCalls[key] = tempClient[key].ToArray();
                }
                foreach (var key in tempServer.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        ServerCalls[key] = tempServer[key].ToArray();
                }
            }

            private static string FormatGadgets(Dictionary<string, MethodInfo[]> tmp)
            {
                string fmtStr = "";
                foreach (var key in tmp.Keys)
                {
                    string[] gadgetParts = key.Replace("::", "|").Split('|');
                    string gadget;
                    if (gadgetParts.Length != 2)
                        gadget = key;
                    else
                    {
                        string[] typeParts = gadgetParts[0].Split('.');
                        gadget = String.Format("{0}::{1}()", typeParts[typeParts.Length - 1], gadgetParts[1]);
                    }
                    fmtStr += String.Format("\t\t{0} is called in the following methods:\n", gadget);
                    foreach (var mi in tmp[key])
                    {
                        fmtStr += String.Format("\t\t\t{0}\n", mi.ToString());
                    }
                    fmtStr += "\n";
                }
                return fmtStr;
            }

            public override string ToString()
            {
                string fmtStr = "";
                var tmp = GadgetCalls;
                if (RemotingChannels.Length > 0)
                {
                    fmtStr += string.Format("\t.NET Remoting Channels:\n");
                    foreach (var chan in RemotingChannels)
                        fmtStr += string.Format("\t\t{0}\n", chan);
                }
                if (ClientCalls.Keys.Count > 0)
                {
                    fmtStr += "\tWCFClient Gadgets:\n";
                    fmtStr += FormatGadgets(ClientCalls);
                }
                if (ServerCalls.Keys.Count > 0)
                {
                    fmtStr += "\tWCFServer Gadgets:\n";
                    fmtStr += FormatGadgets(ServerCalls);

                }
                if (GadgetCalls.Keys.Count > 0)
                {
                    fmtStr += "\tSerialization Gadgets:\n";
                    fmtStr += FormatGadgets(GadgetCalls);
                }
                if (fmtStr != "")
                    fmtStr = String.Format("Assembly Name: {0}\n", AssemblyName) + fmtStr;
                return fmtStr;
            }
        }

        internal struct MethodInfo
        {
            internal string MethodName;
            internal string FilterLevel;

            public override string ToString()
            {
                return !string.IsNullOrEmpty(FilterLevel) ? string.Format("{0} (Filter Level: {1})", MethodName, FilterLevel) : MethodName;
            }
        }

        internal struct GadgetItem
        {
            internal bool IsDotNetRemoting;
            internal string RemotingChannel;
            internal bool IsWCFServer;
            internal bool IsWCFClient;
            internal string GadgetName;
            internal string FilterLevel;
            internal string MethodAppearance;

            public override string ToString()
            {
                //Console.WriteLine("[+] Assembly registers a .NET Remoting channel ({0}) in {1}.{2}", dnrChannel[5], method.t.Name, method.m.Name);
                string[] gadgetParts = GadgetName.Replace("::", "|").Split('|');
                string gadget;
                if (gadgetParts.Length != 2)
                    gadget = GadgetName;
                else
                {
                    string[] typeParts = gadgetParts[0].Split('.');
                    gadget = String.Format("{0}::{1}()", typeParts[typeParts.Length - 1], gadgetParts[1]);
                }
                string fmtMessage = String.Format(@"
IsDotNetRemoting     : {0}
    RemotingChannel  : {1}
IsWCFServer          : {2}
IsWCFClient          : {3}
GadgetName           : {4}
MethodAppearance     : {5}", IsDotNetRemoting, RemotingChannel, IsWCFServer, IsWCFClient, gadget, MethodAppearance);
                if (!string.IsNullOrEmpty(FilterLevel))
                    fmtMessage += string.Format("\n\tFilterLevel      : {0}", FilterLevel);
                return fmtMessage;
            }
        }

        static AssemblyGadgetAnalysis AnalyzeAssembly(string assemblyName)
        {
            // Just in case we run into .NET Remoting
            string[] dnrChannel = { };
            string typeFilterLevel = "ldc.i4.2"; // Default opcode if not set manually
            string filterLevel = "Low";
            bool hit = false;
            List<GadgetItem> listGadgets = new List<GadgetItem>();





            // Parse the target assembly and get its types
            AssemblyDefinition assembly = AssemblyDefinition.ReadAssembly(assemblyName);
            IEnumerable<TypeDefinition> allTypes = assembly.MainModule.GetTypes();

            // Pull out all the type with methods that we want to look at
            var validTypes = allTypes.SelectMany(t => t.Methods.Select(m => new { t, m }))
                .Where(x => x.m.HasBody);

            foreach (var method in validTypes)
            {
                // Disassemble the assembly and check for potentially vulnerable functions
                foreach (var instruction in method.m.Body.Instructions)
                {
                    //Console.WriteLine($"{instruction.OpCode} \"{instruction.Operand}\""); //DEBUG
                    string gadgetName = "";
                    bool isRemoting = false;
                    string remotingChannel = "";
                    bool isWCFServer = false;
                    bool isWCFClient = false;
                    // Deserialization checks
                    if (instruction.OpCode.ToString() == "callvirt")
                    {
                        switch (instruction.Operand.ToString())
                        {
                            case string x when x.Contains(BF_DESERIALIZE):
                                gadgetName = BF_DESERIALIZE;
                                break;
                            case string x when x.Contains(DC_JSON_READ_OBJ):
                                gadgetName = DC_JSON_READ_OBJ;
                                break;
                            case string x when x.Contains(DC_XML_READ_OBJ):
                                gadgetName = DC_XML_READ_OBJ;
                                break;
                            case string x when x.Contains(JS_SERIALIZER_DESERIALIZE):
                                gadgetName = JS_SERIALIZER_DESERIALIZE;
                                break;
                            case string x when x.Contains(LOS_FORMATTER_DESERIALIZE):
                                gadgetName = LOS_FORMATTER_DESERIALIZE;
                                break;
                            case string x when x.Contains(NET_DATA_CONTRACT_READ_OBJ):
                                gadgetName = NET_DATA_CONTRACT_READ_OBJ;
                                break;
                            case string x when x.Contains(NET_DATA_CONTRACT_DESERIALIZE):
                                gadgetName = NET_DATA_CONTRACT_DESERIALIZE;
                                break;
                            case string x when x.Contains(OBJ_STATE_FORMATTER_DESERIALIZE):
                                gadgetName = OBJ_STATE_FORMATTER_DESERIALIZE;
                                break;
                            case string x when x.Contains(SOAP_FORMATTER_DESERIALIZE):
                                gadgetName = SOAP_FORMATTER_DESERIALIZE;
                                break;
                            case string x when x.Contains(XML_SERIALIZER_DESERIALIZE):
                                gadgetName = XML_SERIALIZER_DESERIALIZE;
                                break;
                            case string x when x.Contains(WCF_SERVER_STRING):
                                gadgetName = WCF_SERVER_STRING;
                                isWCFServer = true;
                                break;
                            case string x when x.Contains("System.ServiceModel.ChannelFactory") && x.Contains("CreateChannel"): // System.ServiceModel.ChannelFactory`1<ClassName.ClassName>::CreateChannel()
                                gadgetName = WCF_CLIENT_STRING;
                                isWCFClient = true;
                                break;
                            // Collect the TypeFilterLevel if it is explicitly set
                            case string x when x.Contains("set_FilterLevel(System.Runtime.Serialization.Formatters.TypeFilterLevel)"):
                                if (typeFilterLevel.EndsWith("3"))
                                {
                                    filterLevel = "Full";
                                }
                                break;
                        }

                    } else if (instruction.OpCode.ToString().StartsWith("ldc.i4"))
                    {
                        typeFilterLevel = instruction.OpCode.ToString();
                    } else if (instruction.OpCode.ToString() == "newobj" && instruction.Operand.ToString().Contains("System.Runtime.Remoting.Channels."))
                    {
                        // .NET Remoting Checks
                        dnrChannel = instruction.Operand.ToString().Split('.');
                    } else if (instruction.OpCode.ToString() == "call")
                    {
                        switch (instruction.Operand.ToString())
                        {
                            case string x when x.Contains(REGISTER_CHANNEL):
                                isRemoting = true;
                                gadgetName = REGISTER_CHANNEL;
                                remotingChannel = dnrChannel[5];
                                break;
                        }
                    }
                    
                    if (!string.IsNullOrEmpty(gadgetName) || isWCFClient || isWCFServer || isRemoting)
                    {
                        listGadgets.Add(new GadgetItem()
                        {
                            GadgetName = gadgetName,
                            IsDotNetRemoting = isRemoting,
                            RemotingChannel = remotingChannel,
                            IsWCFClient = isWCFClient,
                            IsWCFServer = isWCFServer,
                            MethodAppearance = String.Format("{0}.{1}", method.t.Name, method.m.Name),
                            FilterLevel = gadgetName.Contains(BF_DESERIALIZE) ?  filterLevel : null
                        });
                    }
                }
            }

            return new AssemblyGadgetAnalysis(assemblyName, listGadgets.ToArray());
        }
    }
}
