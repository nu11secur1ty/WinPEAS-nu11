using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Principal;
using System.Management;
using Microsoft.Win32;
using winPEAS.Helpers;

namespace winPEAS.Checks
{
    public class LpeChecker : ISystemCheck
    {
        public string Id => "LPE_CHECKER";
        public string[] MitreAttackIds => new[] { "T1068", "T1134", "T1574", "T1543", "T1548" };

        public void PrintInfo(bool isDebug) => CheckRunner.Run(PrintLpeInfo, isDebug);

        private void PrintLpeInfo()
        {
            Beaprint.GreatPrint("=== LPE CHECKER - ULTIMATE ESCALATION VECTORS ===", "T1068,T1134,T1574,T1543,T1548");

            CheckAlwaysInstallElevated();
            CheckUnquotedServicePaths();
            CheckUserPrivileges();
            CheckStartupFolders();
            CheckWriteablePathFolders();

            Beaprint.GoodPrint("\n=== LPE CHECKER COMPLETE ===");
        }

        private void CheckAlwaysInstallElevated()
        {
            Beaprint.MainPrint("AlwaysInstallElevated", "");
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Installer");
                if (key != null)
                {
                    var value = key.GetValue("AlwaysInstallElevated");
                    if (value != null && value.ToString() == "1")
                        Beaprint.BadPrint("    [!] ALWAYSINSTALLELEVATED ENABLED - Can install MSI as SYSTEM!");
                    else
                        Beaprint.GoodPrint("    [+] Not vulnerable");
                }
            }
            catch (Exception ex) { Beaprint.PrintException($"    [-] Error: {ex.Message}"); }
        }

        private void CheckUnquotedServicePaths()
        {
            Beaprint.MainPrint("Unquoted Service Paths", "");
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service");
                foreach (ManagementObject service in searcher.Get())
                {
                    string path = service["PathName"]?.ToString() ?? "";
                    string name = service["Name"]?.ToString() ?? "";
                    string startName = service["StartName"]?.ToString() ?? "";
                    if (string.IsNullOrEmpty(path)) continue;
                    if (path.Contains(" ") && !path.StartsWith("\"") && !path.StartsWith("'"))
                    {
                        var firstPart = path.Split(' ')[0];
                        if (firstPart.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            Beaprint.BadPrint($"    [!] Unquoted path: {name} - {path}");
                            Beaprint.ColorPrint($"    Potential hijack: {firstPart}", Beaprint.ansi_color_yellow);
                            Beaprint.ColorPrint($"    Service runs as: {startName}", Beaprint.ansi_color_yellow);
                        }
                    }
                }
            }
            catch (Exception ex) { Beaprint.PrintException($"    [-] Error: {ex.Message}"); }
        }

        private void CheckUserPrivileges()
        {
            Beaprint.MainPrint("User Privileges", "");
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                bool foundPriv = false;
                string[] dangerousPrivs = { "SeDebugPrivilege", "SeImpersonatePrivilege", "SeAssignPrimaryTokenPrivilege",
                                            "SeTakeOwnershipPrivilege", "SeRestorePrivilege", "SeBackupPrivilege",
                                            "SeCreateTokenPrivilege", "SeLoadDriverPrivilege", "SeSystemtimePrivilege" };
                foreach (var claim in identity.Claims)
                    foreach (var priv in dangerousPrivs)
                        if (claim.Value.Contains(priv))
                        {
                            Beaprint.BadPrint($"    [!] Found dangerous privilege: {claim.Value}");
                            foundPriv = true;
                        }
                if (!foundPriv) Beaprint.GoodPrint("    [+] No dangerous privileges found");

                var principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                    Beaprint.ColorPrint("    [+] User is Administrator", Beaprint.ansi_color_yellow);
                else
                    Beaprint.GoodPrint("    [+] User is NOT Administrator");
            }
            catch (Exception ex) { Beaprint.PrintException($"    [-] Error: {ex.Message}"); }
        }

        private void CheckStartupFolders()
        {
            Beaprint.MainPrint("Startup Folders", "");
            try
            {
                foreach (string path in new[] { Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                                                Environment.GetFolderPath(Environment.SpecialFolder.Startup) })
                {
                    if (!Directory.Exists(path)) continue;
                    bool canWrite = true;
                    try { string f = Path.Combine(path, "test.tmp"); using var fs = File.OpenWrite(f); fs.WriteByte(0); File.Delete(f); }
                    catch { canWrite = false; }
                    if (canWrite) Beaprint.BadPrint($"    [!] Writeable startup folder: {path}");
                    else Beaprint.GoodPrint($"    [+] Not writeable: {path}");
                }
            }
            catch (Exception ex) { Beaprint.PrintException($"    [-] Error: {ex.Message}"); }
        }

        private void CheckWriteablePathFolders()
        {
            Beaprint.MainPrint("PATH Folders", "");
            try
            {
                string pathEnv = Environment.GetEnvironmentVariable("PATH");
                if (string.IsNullOrEmpty(pathEnv)) return;
                foreach (string folder in pathEnv.Split(';'))
                {
                    if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
                    bool canWrite = true;
                    try { string f = Path.Combine(folder, "test.tmp"); using var fs = File.OpenWrite(f); fs.WriteByte(0); File.Delete(f); }
                    catch { canWrite = false; }
                    if (canWrite) Beaprint.BadPrint($"    [!] Writeable PATH folder: {folder}");
                }
            }
            catch (Exception ex) { Beaprint.PrintException($"    [-] Error: {ex.Message}"); }
        }
    }
}