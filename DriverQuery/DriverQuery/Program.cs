using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Management;

namespace DriverQuery
{
    class Program
    {
        static void Main(string[] args)
        {
            string usage = "DriverQuery.exe <no-msft> <debug>";
            bool nonMSOnly = false;
            bool debugOutput = false;
            if (args.Length > 2)
            {
                Console.WriteLine(usage);
                return;
            }
            if (args.Length > 0 && args[0].Contains("no-msft"))
            {
                nonMSOnly = true;
            }
            if (args.Length > 1 && args[1].Contains("debug"))
            {
                debugOutput = true;
            }


            GetSignatures(nonMSOnly, debugOutput);
        }

        static void GetSignatures(bool isNotMicrosoftSigned, bool debugOutput)
        {
            Console.WriteLine("[+] Enumerating driver services...");
            Dictionary<string, string> drivers = EnumAllKernelDriverServices();
            FileVersionInfo fileInfo;
            X509Certificate cert;

            Console.WriteLine("[+] Checking file signatures...");
            foreach (KeyValuePair<string, string> kvp in drivers)
            {
                string serviceName = kvp.Key;
                string driverFile = kvp.Value;
                FileInfo finfo = new FileInfo(driverFile);
                X509Certificate2 cert2;

                try
                {
                    fileInfo = FileVersionInfo.GetVersionInfo(driverFile);

                    cert = X509Certificate.CreateFromSignedFile(driverFile);
                    cert2 = new X509Certificate2(cert.Handle);
                }
                catch (CryptographicException)
                {
                    if (debugOutput)
                    {
                        Console.WriteLine("[-] Invalid certificate handle on {0}. Skipping...", driverFile);

                    }
                    continue;
                }
                catch (FileNotFoundException)
                {
                    if (debugOutput)
                    {
                        Console.WriteLine("[-] Couldn't find the file {0}. Skipping...", driverFile);

                    }
                    continue;
                }

                if (isNotMicrosoftSigned)
                {
                    if (Convert.ToString(cert2.Subject).Contains("Microsoft Corporation"))
                    {
                        continue;
                    }
                    else
                    {
                        //Driver details
                        Console.WriteLine("{0}\n" +
                            "    Service Name: {1}\n" +
                            "    Path: {2}\n" +
                            "    Version: {3}\n" +
                            "    Creation Time (UTC): {4}\n" +
                            "    Cert Issuer: {5}\n" +
                            "    Signer: {6}\n",
                            fileInfo.FileDescription, serviceName, driverFile,
                            fileInfo.FileVersion, finfo.CreationTimeUtc,
                            cert2.Issuer.ToString(), cert2.Subject.ToString());
                    }
                }
                else
                {
                    //Driver details
                    Console.WriteLine("{0}\n" +
                            "    Service Name: {1}\n" +
                            "    Path: {2}\n" +
                            "    Version: {3}\n" +
                            "    Creation Time (UTC): {4}\n" +
                            "    Cert Issuer: {5}\n" +
                            "    Signer: {6}\n",
                            fileInfo.FileDescription, serviceName, driverFile,
                            fileInfo.FileVersion, finfo.CreationTimeUtc,
                            cert2.Issuer.ToString(), cert2.Subject.ToString());
                }
            }
        }

        static Dictionary<string, string> EnumAllKernelDriverServices()
        {
            Dictionary<string, string> drivers = new Dictionary<string, string>();

            ServiceController[] services = ServiceController.GetDevices();
            foreach (ServiceController service in services)
            {
                if ((service.ServiceType & ServiceType.KernelDriver) != 0)
                {
                    using (ManagementObject wmiService = new ManagementObject("Win32_Service.Name='" + service.ServiceName + "'"))
                    {
                        try
                        {
                            wmiService.Get();
                            string currentserviceExePath = Environment.ExpandEnvironmentVariables(wmiService["PathName"].ToString());

                            if (currentserviceExePath != string.Empty)
                            {
                                drivers.Add(service.ServiceName, FixPath(currentserviceExePath));
                            }
                        }
                        catch
                        {
                            //Console.WriteLine("Error processing {0}", service.ServiceName);
                            continue;
                        }
                    }
                }
            }

            return drivers;
        }
        //Hack to resolve file location issue due to NT paths
        static string FixPath(string oldPath)
        {
            string newPath = oldPath;

            if (oldPath.StartsWith(@"\SystemRoot\"))
            {
                newPath = oldPath.Replace(@"\SystemRoot\", @"C:\Windows\");

            }
            else if (oldPath.StartsWith(@"system32\"))
            {
                newPath = oldPath.Replace(@"system32\", @"C:\Windows\System32\");
            }
            else if (oldPath.StartsWith(@"System32\"))
            {
                newPath = oldPath.Replace(@"System32\", @"C:\Windows\System32\");
            }
            else if (oldPath.StartsWith(@"\??\"))
            {
                newPath = oldPath.Replace(@"\??\", "");
            }
            return newPath;
        }
    }
}
