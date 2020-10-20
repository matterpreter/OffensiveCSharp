using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace HijackHunter
{
    class Program
    {
        // Usage: HijackHunter.exe <file_path> <-quiet>

        private static string g_basePath = string.Empty;
        // Global list for tracking all hijacks through recursion
        public static List<PEDetails> g_Hijackables = new List<PEDetails>();
        public static bool quietMode = false;
        

        static void Main(string[] args)
        {
            string fileName;
            // Make sure the target file exists
            try
            {
                fileName = args[0];
            }
            catch(Exception m)
            {
                Console.WriteLine(m.ToString());
                return;
            }
            g_basePath = Path.GetDirectoryName(fileName);
            if(g_basePath == "")
            {
                string tmp = fileName;
                fileName = String.Concat(".\\", tmp);
            }
            if (!File.Exists(fileName))
            {
                Console.WriteLine("[-] Can't access {0}", fileName);
                return;
            }
            if (fileName.ToLower().StartsWith(@"c:\windows\"))
            {
                Console.WriteLine("[!] You're targeting OS components. This is prone to false positives.");
            }

            if (args.Length > 1 && args[1] == "-quiet")
            {
                quietMode = true;
            }

            //Check the file signature
            byte[] fileBytes = File.ReadAllBytes(fileName);
            byte[] magic = new byte[2];
            Array.Copy(fileBytes, magic, 2);
            if (BitConverter.ToString(magic) != "4D-5A") // MZ
            {
                Console.WriteLine("[-] File does not appear to be a PE (Magic was {0})", BitConverter.ToString(magic));
                return;
            }

            // Start processing the file
            Console.WriteLine("[>] Processing {0}", fileName);

            // Get the static imports
            RecursiveHunter(fileName, fileBytes, true, "static", 0);
            // Get the dynamic imports/delay loads

            RecursiveHunter(fileName, fileBytes, false, "dynamic", 0);

            // Iterate over the list of potentially hijackable imports
            Console.WriteLine("\n[>] Hijack test results:");
            Console.WriteLine("---------------------------------");
            if (g_Hijackables.Count > 0)
            {
                foreach (PEDetails hijacks in g_Hijackables)
                {
                    string reason = "";
                    string technique = "";

                    // Static load hijacks
                    if (hijacks.HijackAttribute == "globallyMissingDll")
                    {
                        reason = "The DLL can't be found in the paths checked in the SafeDllSearchMode search order";
                        technique = "Drop your DLL anywhere along the search path";
                    }
                    else if (hijacks.HijackAttribute == "writableProgDirDllMissing")
                    {
                        reason = "The directory where the program is executed is writable and the target DLL is missing";
                        technique = "Drop your DLL in " + hijacks.Path;
                    }
                    else if (hijacks.HijackAttribute == "writableProgDirDllExists")
                    {
                        reason = "The directory where the program is executed is writable but the target DLL exists";
                        technique = "Drop your DLL in " + hijacks.Path + " and use export forwarding";
                    }
                    else if (hijacks.HijackAttribute == "writableEnvPathDllExists")
                    {
                        reason = "The DLL exists in a writeable directory in the %PATH% environment variable";
                        technique = "Drop your DLL in " + hijacks.Path + " and use export forwarding";
                    }
                    else if (hijacks.HijackAttribute == "writableProgDirDllMissing")
                    {
                        reason = "The DLL can't be found along the SafeDllSearchMode search path but a directory in the %PATH% environment variable is writable";
                        technique = "Drop your DLL in " + hijacks.Path;
                    }

                    Console.WriteLine("[+] " + hijacks.Name + " is hijackable");
                    Console.WriteLine("\tReason: {0}", reason);
                    Console.WriteLine("\tTechnique: {0}", technique);
                }
            }
            else
            {
                Console.WriteLine("[-] No hijacks found");
            }
            
        }

        public struct PEDetails
        {
            public string Name;                 // foo.dll
            public string Path;                 // C:\Windows\foo.dll
            public string Arch;                 // x86 or x64
            public List<string> staticImports;  // List of dll names
            public List<string> dynamicImports; // List of dll names
            public string HijackAttribute;      // hijackProgDirMissingDll, etc
        }

        static void RecursiveHunter(string fileName, byte[] fileBytes, bool isRoot, string target, int indent)
        {
            
           PEDetails targetFile = new PEDetails
            {
                Name = fileName,
                Path = Path.GetDirectoryName(fileName),
                Arch = UnsafeHelpers.GetPeArchitecture(fileBytes)
            };
            targetFile.staticImports = UnsafeHelpers.GetStaticImports(fileBytes, targetFile.Arch);
            targetFile.dynamicImports = UnsafeHelpers.GetDynamicImports(fileBytes, targetFile.Arch);

            string spacing = new string(' ', indent + 4); // Used for text formatting

            if (isRoot) // We only want to print this bit for the target EXE and not for imported DLLs during recursion
            {
                if (targetFile.staticImports.Count > 0)
                {
                    Console.WriteLine(spacing + "[+] Found {0} static imports!", targetFile.staticImports.Count);
                }
                if (targetFile.dynamicImports.Count > 0)
                {
                    Console.WriteLine(spacing + "[+] Found {0} dynamic imports!", targetFile.dynamicImports.Count);
                }

                if (!quietMode) { Console.WriteLine("[>] Beginning hijack checks"); }
            }

            if (target == "static")
            {
                if (targetFile.staticImports != null)
                {
                    foreach (string dll in targetFile.staticImports)
                    {
                        if (!dll.StartsWith("api-ms-win") && !dll.StartsWith("ext-ms-win")) // We won't process members of the API Set
                        {
                            try
                            {
                                // First see if we can find the DLL in any of the SafeDllSearchMode search order
                                targetFile.Name = dll;
                                string output = spacing + "└─ " + targetFile.Name;
                                targetFile.Path = FindFilePath(dll, Path.GetDirectoryName(targetFile.Path));

                                string hijackResult = HijackChecks(targetFile, false);
                                if (targetFile.Path != null && !targetFile.Path.Contains("system32")) // recursing into system32 breaks the program. 
                                {

                                    if (!quietMode) { Console.WriteLine(output + hijackResult); }
                                    // Start processing it through recursion
                                    byte[] newFile = File.ReadAllBytes(targetFile.Path);
                                    RecursiveHunter(targetFile.Path, newFile, false, "static", indent + 6);
                                }
                                else // Handle DLLs that are missing from the search order
                                {
                                    if (!quietMode)
                                    {
                                        Console.WriteLine(output + " --> " + hijackResult);
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                // A NullReferenceException expected to happen at the end of ever recursive search chain
                                if (!(ex is NullReferenceException))
                                {
                                    throw;
                                }
                            }
                        }
                    }
                }
            }
            else if (target == "dynamic")
            {
                foreach (string dll in targetFile.dynamicImports)
                {
                    if (!dll.StartsWith("api-ms-win") && !dll.StartsWith("ext-ms-win")) // We won't process members of the API Set
                    {
                        try
                        {
                            // First see if we can find the DLL in any of the SafeDllSearchMode search order
                            targetFile.Name = dll;
                            string output = spacing + "└─ " + targetFile.Name;
                            targetFile.Path = FindFilePath(dll, Path.GetDirectoryName(targetFile.Path));

                            string hijackResult = HijackChecks(targetFile, true);
                            if (targetFile.Path != null)
                            {
                                // Print out the found DLL...
                                if (!quietMode) { Console.WriteLine(output + hijackResult); }
                                // and start processing it through recursion
                                byte[] newFile = File.ReadAllBytes(targetFile.Path);
                                //RecursiveHunter(targetFile.Path, newFile, false, "static", indent + 6); // No recursion for dynamic loads currently due to bugs. Feel free to PR though :)
                            }
                            else // Handle DLLs that are missing from the search order
                            {
                                if (!quietMode) { Console.WriteLine(output + " [HIJACKABLE]"); }
                            }
                        }
                        catch (Exception ex)
                        {
                            // A NullReferenceException expected to happen at the end of ever recursive search chain
                            if (!(ex is NullReferenceException))
                            {
                                throw;
                            }
                        }
                    }
                }
            }
        }


        static string HijackChecks(PEDetails peDetails, bool isDynamic)
        {
            // Check KnownDLLs
            List<string> knownDlls = GetKnownDlls();
            foreach (string knownDll in knownDlls)
            {
                if (peDetails.Name.ToLower().Equals(knownDll.ToLower()))
                {
                    return " [KnownDLL]";
                }
            }

            // Check against the API set
            if (peDetails.Name.ToLower().StartsWith("api-ms-win-") || peDetails.Name.ToLower().StartsWith("ext-ms-win-"))
            {
                return " [API Set]";
            }

            // Hacky way to catch --> works sometimes. Skipped 1 part and it works
            // CheckDirectoryWritePermissions(g_basePath) && peDetails.Name != "ntdll.dll"
            if (peDetails.Name != "ntdll.dll")
            {
                if (!File.Exists(g_basePath + @"\" + peDetails.Name))
                {
                    peDetails.HijackAttribute = "writableProgDirDllMissing";
                    peDetails.Path = g_basePath + @"\" + peDetails.Name;
                    if (isDynamic) { peDetails.Name = peDetails.Name + " (Delayed Load)"; }
                    g_Hijackables.Add(peDetails);
                    return " [HIJACKABLE] ";
                }
                else
                {
                    peDetails.HijackAttribute = "writableProgDirDllExists";
                    peDetails.Path = g_basePath + @"\" + peDetails.Name;
                    if (isDynamic) { peDetails.Name = peDetails.Name + " (Delayed Load)"; }
                    g_Hijackables.Add(peDetails);
                    return " [HIJACKABLE]";
                }
            }


            // Check if the current user can write to the EXE's directory
            if (peDetails.Path != null &&
                !peDetails.Path.ToLower().StartsWith(Environment.SystemDirectory.ToLower()) && // Check to make sure we aren't hitting hijacks that require modifying a sensitive directory
                !peDetails.Path.ToLower().StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower()))
            {
                if (CheckDirectoryWritePermissions(peDetails.Path))
                {
                    peDetails.HijackAttribute = "writableProgDirDllMissing";
                    if (isDynamic) { peDetails.Name = peDetails.Name + " (Delayed Load)"; }
                    g_Hijackables.Add(peDetails);
                    return " [HIJACKABLE] ";
                }
                else
                {
                    peDetails.HijackAttribute = "writableProgDirDllExists";
                    if (isDynamic) { peDetails.Name = peDetails.Name + " (Delayed Load)"; }
                    g_Hijackables.Add(peDetails);
                    return " [HIJACKABLE]";
                }
            }
            else if (peDetails.Path.ToLower().StartsWith(Environment.SystemDirectory.ToLower()))
            {
                return " [System32]";
            }
            else if (peDetails.Path.ToLower().StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower()))
            {
                return " [Windir]";
            }


            if (peDetails.Path == null)
            {
                peDetails.HijackAttribute = "globallyMissingDll";
                if (isDynamic) { peDetails.Name = peDetails.Name + " (Delayed Load)"; }
                g_Hijackables.Add(peDetails);
                return " [HIJACKABLE]";
            }


            if (peDetails.Path.StartsWith(Environment.CurrentDirectory))
            {
                return " [Current Directory]";
            }

            // %PATH% hijacks
            string pathEnvVar = Environment.GetEnvironmentVariable("PATH");
            string[] envPaths = pathEnvVar.Split(new char[1] { Path.PathSeparator });
            foreach (string envPath in envPaths)
            {
                // If the path is writable
                if (CheckDirectoryWritePermissions(envPath))
                {
                    if (peDetails.Path.StartsWith(envPath))
                    {
                        peDetails.HijackAttribute = "writableEnvPathDllExists";
                        peDetails.Path = envPath;
                        if (isDynamic) { peDetails.Name = peDetails.Name + " (Delayed Load)"; }
                        g_Hijackables.Add(peDetails);
                        return " [HIJACKABLE]";
                    }
                    else
                    {
                        peDetails.HijackAttribute = "writableEnvPathDllMissing";
                        peDetails.Path = envPath;
                        if (isDynamic) { peDetails.Name = peDetails.Name + " (Delayed Load)"; }
                        g_Hijackables.Add(peDetails);
                        return " [HIJACKABLE]";
                    }
                }
            }

            return null;
        }

        static List<string> GetKnownDlls()
        {
            List<string> knownDlls = new List<string>();
            string baseKey = @"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs";

            RegistryKey key = Registry.LocalMachine.OpenSubKey(baseKey);
            string[] values = key.GetValueNames();
            foreach (string value in values)
            {
                knownDlls.Add(key.GetValue(value).ToString());
            }

            // There are some deltas between the registry key and the object manager,
            // so this is a hack to manage that until I want to do it the right way
            string[] knownDllDeltas =
            {
                "bcrypt.dll",
                "bcryptPrimitives.dll",
                "cfgmgr32.dll",
                "COMCTL32.dll",
                "CRYPT32.dll",
                "gdi23full.dll",
                "kernelbase.dll",
                "msvcp_win.dll",
                "ntdll.dll.dll",
                "ucrtbase.dll",
                "win32u.dll",
                "WINTRUST.dll"
            };

            foreach (string delta in knownDllDeltas)
            {
                if (!knownDlls.Contains(delta))
                {
                    knownDlls.Add(delta);
                }
            }

            return knownDlls;
        }

        static bool CheckDirectoryWritePermissions(string path)
        {
            // https://stackoverflow.com/a/1281638
            DirectorySecurity acl;
            bool writeAllow = false;
            bool writeDeny = false;
            try
            {
                acl = Directory.GetAccessControl(path);
            }
            catch (Exception) // null ACL errors out with exceptions regardless of checking for null. 
            {
                return false;
            }
            AuthorizationRuleCollection accessRules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));

            if (accessRules == null)
                return false;

            foreach (FileSystemAccessRule rule in accessRules)
            {
                if ((FileSystemRights.Write & rule.FileSystemRights) != FileSystemRights.Write)
                    continue;

                if (rule.AccessControlType == AccessControlType.Allow)
                    writeAllow = true;
                else if (rule.AccessControlType == AccessControlType.Deny)
                    writeDeny = true;
            }

            return writeAllow && !writeDeny;
        }

        static string FindFilePath(string fileName, string basePath)
        {
            //
            List<string> paths = new List<string>();
            paths.Add(g_basePath); // Global variable indicating where the directory where the target PE is executed from
            paths.Add(Environment.SystemDirectory); // C:\Windows\System32
            paths.Add(Environment.GetFolderPath(Environment.SpecialFolder.Windows)); // C:\Windows
            paths.Add(Environment.CurrentDirectory); // Current working directory

            // Expand the %PATH% environment variable
            string pathEnvVar = Environment.GetEnvironmentVariable("PATH");
            string[] envPaths = pathEnvVar.Split(new char[1] { Path.PathSeparator });
            foreach (string f in envPaths)
            {
                paths.Add(f);
            }

            // Deduplicate the list
            List<string> searchPaths = paths.Distinct().ToList();

            foreach (string path in searchPaths)
            {
                string filePath = path.EndsWith(@"\") ? path : path + @"\";
                if (File.Exists((filePath + fileName).ToLower()))
                {
                    return filePath + fileName;
                }
            }
            return null;
        }
    }
}