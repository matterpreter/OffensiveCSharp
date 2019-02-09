using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

public class SessionSearcher
{
    static void Main()
    {
        Console.WriteLine("[+] Searching all connected drives. This could take a few minutes...");
        string[] drives = Environment.GetLogicalDrives();

        foreach (string drive in drives)
        {
            DriveInfo di = new DriveInfo(drive);

            if (!di.IsReady)
            {
                Console.WriteLine("The drive {0} could not be read", di.Name);
                continue;
            }
            DirectoryInfo rootDir = di.RootDirectory;
            RecursiveFileSearch(rootDir);
        }
        Console.WriteLine("[+] Parsing PPK files\r\n");
        foreach (string ppkFile in ppkList)
        {
            PPKParser(ppkFile);
        }

        Console.WriteLine("[+] Parsing RDP files\r\n");
        foreach (string rdpFile in rdpList)
        {
            RDPParser(rdpFile);
        }

        Console.WriteLine("[+] Collected RSA tokens:\r\n");
        foreach (string sdtidFile in sdtidList)
        {
            Console.WriteLine(sdtidFile);
        }

        //Console.WriteLine("Press any key");
        //Console.ReadKey();
    }

    static List<string> ppkList = new List<string>();
    static List<string> rdpList = new List<string>();
    static List<string> sdtidList = new List<string>();

    static void RecursiveFileSearch(DirectoryInfo root)
    {
        FileInfo[] files = null;
        DirectoryInfo[] subDirs = null;
        //List<string> ppkList = new List<string>();
        //List<string> rdpList = new List<string>();
        //List<string> sdtidList = new List<string>();

        try
        {
            files = root.GetFiles("*.*");
        }

        catch (UnauthorizedAccessException){ }
        catch (DirectoryNotFoundException){ }

        if (files != null)
        {
            foreach (FileInfo fi in files)
            {
                if (fi.Extension.Equals(".ppk"))
                {
                    ppkList.Add(fi.FullName);
                    Console.WriteLine(fi.FullName);
                }
                if (fi.Extension.Equals(".rdp"))
                {
                    rdpList.Add(fi.FullName);
                    Console.WriteLine(fi.FullName);
                }
                if (fi.Extension.Equals(".sdtid"))
                {
                    sdtidList.Add(fi.FullName);
                    Console.WriteLine(fi.FullName);
                }
            }

            subDirs = root.GetDirectories();

            foreach (DirectoryInfo dirInfo in subDirs)
            {
                // Resursive call for each subdirectory.
                RecursiveFileSearch(dirInfo);
            }
        }
    }
    static void PPKParser(string path)
    {
        //string path = @"C:\temp\test.ppk";
        List<string> lines = File.ReadAllLines(path).ToList();

        List<string> protocol = lines[0].Split(':').ToList();
        List<string> encryption = lines[1].Split(':').ToList();
        List<string> comment = lines[2].Split(':').ToList();
        List<string> mac = lines[lines.Count - 1].Split(':').ToList();

        int privateKeyLenIndex = lines.FindIndex(s => new Regex(@"Private-Lines").Match(s).Success);
        List<string> indexofPrivateKeyLen = lines[privateKeyLenIndex].Split(':').ToList();
        int privateKeylen = Convert.ToInt32(indexofPrivateKeyLen[1].Replace(" ", String.Empty));
        int endofPrivateKey = privateKeylen + privateKeyLenIndex;
        string privateKey = null;
        for (int i = privateKeyLenIndex + 1; i <= endofPrivateKey; i++)
        {
            privateKey += lines[i];
        }

        Console.WriteLine("Filename:\t " + path);
        Console.WriteLine("Protocol:\t" + protocol[1]);
        Console.WriteLine("Comment:\t" + comment[1]);
        Console.WriteLine("Encryption:\t" + encryption[1]);
        Console.WriteLine("Private Key:\t " + privateKey);
        Console.WriteLine("Private Mac:\t" + mac[1]);
        Console.WriteLine();
    }

    static void RDPParser(string path)
    {
        //string path = @"C:\temp\test.rdp";
        List<string> rdpFile = File.ReadAllLines(path).ToList();

        int rdpAddressIDX = rdpFile.FindIndex(s => new Regex(@"full address").Match(s).Success);
        int rdpGatewayIDX = rdpFile.FindIndex(s => new Regex(@"gatewayhostname").Match(s).Success);
        //int rdpUsernameIDX = rdpFile.FindIndex(s => new Regex(@"username").Match(s).Success);
        //int rdpIsAdminIDX = rdpFile.FindIndex(s => new Regex(@"administrative session").Match(s).Success);
        int rdpPromptForCredsIDX = rdpFile.FindIndex(s => new Regex(@"prompt for credentials").Match(s).Success);

        List<string> rdpAddress = rdpFile[rdpAddressIDX].Split(':').ToList();
        List<string> rdpGateway = rdpFile[rdpGatewayIDX].Split(':').ToList();
        //List<string> rdpUsername = rdpFile[rdpUsernameIDX].Split(':').ToList(); //This will error out if there is no specified username
        //List<string> rdpIsAdmin = rdpFile[rdpIsAdminIDX].Split(':').ToList(); //This key isn't present in my test files
        List<string> rdpPromptForCredsArr = rdpFile[rdpPromptForCredsIDX].Split(':').ToList();

        Console.WriteLine("Filename:\t\t" + path);
        Console.WriteLine("Address:\t\t" + rdpAddress[2]);
        //Console.WriteLine("Username:\t\t" + rdpUsername[2]);
        Console.WriteLine("Gateway Address:\t" + rdpGateway[2]);
        //Console.WriteLine("Session in Admin:\t" + rdpIsAdmin[1]);
        if (rdpPromptForCredsArr[2].ToString().Equals("0"))
        {
            Console.WriteLine("Prompts for Creds:\tFalse");
        }
        else
        {
            Console.WriteLine("Prompts for Creds:\tTrue");
        }
        Console.WriteLine();
    }
}