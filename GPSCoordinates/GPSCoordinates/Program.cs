using System;
using Microsoft.Win32;
using System.Device.Location;

namespace GPSCoordinates
{
    class Program
    {
        static void Main(string[] args)
        {
            Location currentLoc = new Location();        
            //Implement OS version check?

            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location");
            if (key.GetValue("Value").Equals("Deny"))
            {
                Console.WriteLine("[-] Location Services registry key set to 'Deny'");
                //Environment.Exit(1);
                Console.WriteLine("Hit any key to exit");
                Console.ReadKey();
            }
            else
            {
                currentLoc.GetLocationEvent();
                Console.WriteLine("Hit any key to exit");
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