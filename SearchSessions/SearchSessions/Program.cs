using System;
using System.Collections.Generic;
using System.IO;

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
        var txtList = new List<string>();
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
                    txtList.Add(fi.FullName);
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
}