using System;
using Microsoft.Win32;
using System.Device.Location;

namespace GPSCoordinates
{
    class Program
    {
        static void Main(string[] args)
        {
            RegistryKey osVerKey = Registry.LocalMachine;
            RegistryKey osVerSubKey = osVerKey.OpenSubKey(@"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion");
            string osVer = osVerSubKey.GetValue("ProductName").ToString();
            if (!osVer.Contains("Windows 10"))
            {
                Console.WriteLine("[-] Target does not appear to be Windows 10. Exiting.");
                Environment.Exit(1);
            }

            Location currentLoc = new Location();        

            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location");
            if (key.GetValue("Value").Equals("Deny"))
            {
                Console.WriteLine("[-] Location Services registry key set to 'Deny'");
                Environment.Exit(1);
            }
            else
            {
                currentLoc.GetLocationEvent();
                Console.WriteLine("Hit any key to exit"); //This will likely cause problems with execute-assembly
                Console.ReadKey();
            }
        }

        class Location
        {
            GeoCoordinateWatcher tracker;

            public void GetLocationEvent()
            {
                tracker = new GeoCoordinateWatcher();
                
                tracker.PositionChanged += new EventHandler<GeoPositionChangedEventArgs<GeoCoordinate>>(coordinateCollect);
                bool tryStart = tracker.TryStart(false, TimeSpan.FromMilliseconds(1000));
                if (!tryStart)
                {
                    Console.WriteLine("[-] Coordinate collector timed out");
                }
                
            }

            void coordinateCollect(object sender, GeoPositionChangedEventArgs<GeoCoordinate> e)
            {
                PrintPosition(e.Position.Location.Latitude, e.Position.Location.Longitude);
            }

            void PrintPosition(double Latitude, double Longitude)
            {
                Console.WriteLine("{0},{1}", Latitude, Longitude);
            }
        }
    }
}