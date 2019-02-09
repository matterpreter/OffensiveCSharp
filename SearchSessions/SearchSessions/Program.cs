using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

public class SessionSearcher
{
    static void Main()
    {
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

        Console.WriteLine("Press any key");
        Console.ReadKey();
    }

    static void RecursiveFileSearch(DirectoryInfo root)
    {
        FileInfo[] files = null;
        DirectoryInfo[] subDirs = null;
        var ppkList = new List<string>();
        var rdpList = new List<string>();
        var sdtidList = new List<string>();

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
        //Console.ReadLine();
    }
}