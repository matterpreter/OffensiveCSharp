using System;
using System.IO;

namespace SearchSessions
{
    class Program
    {
        static void Scan(string path)
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(path, "*.exe"))
                {
                    Console.WriteLine("FILE: " + file);
                }
                foreach (var dir in Directory.EnumerateDirectories(path))
                {
                    Console.WriteLine("DIRECTORY: " + dir);
                    Scan(dir);
                }
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("Error: " + path);
            }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("Searching for .TXT files...");
            Scan("C:\\");
            Console.ReadKey();

        }
    }
}
