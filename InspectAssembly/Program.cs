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

            public AssemblyGadgetAnalysis(string assemblyName, GadgetItem[] items)
            {
                AssemblyName = assemblyName;
                IsWCFClient = false;
                IsWCFServer = false;
                Dictionary<string, List<MethodInfo>> temp = new Dictionary<string, List<MethodInfo>>();
                List<string> dnRemotingChannels = new List<string>();
                foreach(var gadget in items)
                {
                    if (!temp.ContainsKey(gadget.GadgetName))
                        temp[gadget.GadgetName] = new List<MethodInfo>();
                    temp[gadget.GadgetName].Add(new MethodInfo()
                    {
                        MethodName = gadget.MethodAppearance,
                        FilterLevel = gadget.FilterLevel
                    });
                    if (gadget.IsDotNetRemoting)
                        dnRemotingChannels.Add(gadget.RemotingChannel);
                    if (gadget.IsWCFClient)
                        IsWCFClient = true;
                    if (gadget.IsWCFServer)
                        IsWCFServer = true;
                }
                RemotingChannels = dnRemotingChannels.ToArray();
                GadgetCalls = new Dictionary<string, MethodInfo[]>();
                foreach(var key in temp.Keys)
                {
                    if (!string.IsNullOrEmpty(key))
                        GadgetCalls[key] = temp[key].ToArray();
                }
            }

            public override string ToString()
            {
                string fmtStr = "";
                if (RemotingChannels.Length > 0)
                {
                    fmtStr += string.Format("\t.NET Remoting Channels:\n");
                    foreach (var chan in RemotingChannels)
                        fmtStr += string.Format("\t\t{0}\n", chan);
                }
                if (IsWCFClient)
                {
                    fmtStr += "\tWCFClient\n";
                }
                if (IsWCFServer)
                    fmtStr += "\tWCFServer\n";
                if (GadgetCalls.Keys.Count > 0)
                {
                    fmtStr += "\tSerialization Gadgets:\n";
                    foreach (var key in GadgetCalls.Keys)
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
                        foreach (var mi in GadgetCalls[key])
                        {
                            fmtStr += String.Format("\t\t\t{0}\n", mi.ToString());
                        }
                        fmtStr += "\n";
                    }
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
            //Dictionary<string, List<string>> methodTally = new Dictionary<string, List<string>>();
            //methodTally["System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize"] = new List<string>();
            //methodTally["System.Runtime.Serialization.Json.DataContractJsonSerializer::ReadObject"] = new List<string>();
            //methodTally["System.Runtime.Serialization.Xml.DataContractSerializer::ReadObject"] = new List<string>();
            //methodTally["System.Web.Script.Serialization.JavaScriptSerializer::Deserialize"] = new List<string>();
            //methodTally["System.Web.UI.LosFormatter::Deserialize"] = new List<string>();
            //methodTally["System.Runtime.Serialization.NetDataContractSerializer::ReadObject"] = new List<string>();
            //methodTally["System.Runtime.Serialization.NetDataContractSerializer::Deserialize"] = new List<string>();
            //methodTally["System.Web.UI.ObjectStateFormatter::Deserialize"] = new List<string>();
            //methodTally["System.Runtime.Serialization.Formatters.Soap.SoapFormatter::Deserialize"] = new List<string>();
            //methodTally["System.Xml.Serialization.XmlSerializer::Deserialize"] = new List<string>();

            string bfDeserialize = "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize";
            string dcJsonReadObj = "System.Runtime.Serialization.Json.DataContractJsonSerializer::ReadObject";
            string dcXmlReadObj = "System.Runtime.Serialization.Xml.DataContractSerializer::ReadObject";
            string jsSerializerDeserialize = "System.Web.Script.Serialization.JavaScriptSerializer::Deserialize";
            string losFormatterDeserialize = "System.Web.UI.LosFormatter::Deserialize";
            string netDataContractReadObject = "System.Runtime.Serialization.NetDataContractSerializer::ReadObject";
            string netDataContractDeserialize = "System.Runtime.Serialization.NetDataContractSerializer::Deserialize";
            string objStateFormatterDeserialize = "System.Web.UI.ObjectStateFormatter::Deserialize";
            string soapFormatterDeserialize = "System.Runtime.Serialization.Formatters.Soap.SoapFormatter::Deserialize";
            string xmlSerializerDeserialize = "System.Xml.Serialization.XmlSerializer::Deserialize";
            string registerChannel = "System.Runtime.Remoting.Channels.ChannelServices::RegisterChannel";
            string wcfServerString = "System.ServiceModel.ServiceHost::AddServiceEndpoint";




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
                            case string x when x.Contains(bfDeserialize):
                                gadgetName = bfDeserialize;
                                break;
                            case string x when x.Contains(dcJsonReadObj):
                                gadgetName = dcJsonReadObj;
                                break;
                            case string x when x.Contains(dcXmlReadObj):
                                gadgetName = dcXmlReadObj;
                                break;
                            case string x when x.Contains(jsSerializerDeserialize):
                                gadgetName = jsSerializerDeserialize;
                                break;
                            case string x when x.Contains(losFormatterDeserialize):
                                gadgetName = losFormatterDeserialize;
                                break;
                            case string x when x.Contains(netDataContractReadObject):
                                gadgetName = netDataContractReadObject;
                                break;
                            case string x when x.Contains(netDataContractDeserialize):
                                gadgetName = netDataContractDeserialize;
                                break;
                            case string x when x.Contains(objStateFormatterDeserialize):
                                gadgetName = objStateFormatterDeserialize;
                                break;
                            case string x when x.Contains(soapFormatterDeserialize):
                                gadgetName = soapFormatterDeserialize;
                                break;
                            case string x when x.Contains(xmlSerializerDeserialize):
                                gadgetName = xmlSerializerDeserialize;
                                break;
                            case string x when x.Contains(wcfServerString):
                                gadgetName = "System.ServiceModel.ServiceHost::AddServiceEndpoint";
                                isWCFServer = true;
                                break;
                            case string x when x.Contains("System.ServiceModel.ChannelFactory") && x.Contains("CreateChannel"): // System.ServiceModel.ChannelFactory`1<ClassName.ClassName>::CreateChannel()
                                //gadgetName = x.Replace("()","");
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
                            case string x when x.Contains(registerChannel):
                                isRemoting = true;
                                gadgetName = registerChannel;
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
                            FilterLevel = gadgetName.Contains(bfDeserialize) ?  filterLevel : null
                        });
                    }
                }
            }

            return new AssemblyGadgetAnalysis(assemblyName, listGadgets.ToArray());
        }
    }
}
