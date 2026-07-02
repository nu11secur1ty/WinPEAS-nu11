using System;
using winPEAS.Checks;

namespace winPEAS
{
    public static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            // ============================================================
            // CUSTOM MODULE REGISTRATION
            // To add a new custom module, copy this block and change:
            //   - "new YourModuleName()"  -> Your class name
            //   - "yourmodule"            -> The command to invoke it (e.g. "mymodule")
            // ============================================================
            if (args.Length > 0 && args[0].ToLower() == "lpe")
            {
                var lpe = new LpeChecker();
                lpe.PrintInfo(false);
                return;
            }

            // ============================================================
            // TO ADD ANOTHER CUSTOM MODULE:
            // Uncomment and modify this block:
            // ============================================================
            /*
            if (args.Length > 0 && args[0].ToLower() == "mymodule")
            {
                var myModule = new MyCustomCheck();  // <-- Replace with your class
                myModule.PrintInfo(false);            // <-- Your PrintInfo method
                return;
            }
            */

            // ============================================================
            // DEFAULT BEHAVIOR - Run all standard checks
            // ============================================================
            Checks.Checks.Run(args);
        }
    }
}