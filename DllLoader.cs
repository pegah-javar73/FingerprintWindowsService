using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DentalWindowsApp
{
    class DllLoader
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LoadLibrary(string dllToLoad);

        public static void LoadSupremaDlls()
        {
            string dllPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "libs", "UFScanner.dll");
            if (!File.Exists(dllPath))
            {
                throw new FileNotFoundException("❌ فایل UFScanner.dll یافت نشد!", dllPath);
            }

            IntPtr handle = LoadLibrary(dllPath);
            if (handle == IntPtr.Zero)
            {
                throw new Exception("❌ لود کردن UFScanner.dll با خطا مواجه شد!");
            }
        }
    }
}
