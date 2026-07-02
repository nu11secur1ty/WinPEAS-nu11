using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using winPEAS.Helpers;
using winPEAS.Native;
using winPEAS.Native.Enums;

namespace winPEAS.Checks
{
    /// <summary>
    /// Custom LPE (Local Privilege Escalation) Checker
    /// Checks for common privilege escalation vectors
    /// </summary>
    public class LpeChecker : ISystemCheck
    {
        public string Id => "LPE_CHECKER";
        public List<string> MitreAttackIds => new List<string> { "T1068", "T1134", "T1574" };

        public void PrintInfo()
        {
            CheckRunner.Run(PrintLpeInfo, "LPE Checker");
        }

        private void PrintLpeInfo()
        {
            Beaprint.Green("=== LPE CHECKER - COMMON ESCALATION VECTORS ===\n");

            // 1. Проверка за AlwaysInstallElevated
            CheckAlwaysInstallElevated();

            // 2. Проверка за неквотирани пътища на услуги
            CheckUnquotedServicePaths();

            // 3. Проверка за слаби права върху услуги
            CheckWeakServicePermissions();

            // 4. Проверка за интересни привилегии на потребителя
            CheckUserPrivileges();

            // 5. Проверка за закиснати стартиращи програми
            CheckStartupFolders();

            // 6. Проверка за записаеми папки в PATH
            CheckWriteablePathFolders();

            // 7. Проверка за инсталирани антивируси
            CheckInstalledAV();

            Beaprint.Green("\n=== LPE CHECKER COMPLETE ===");
        }

        #region Individual Checks

        private void CheckAlwaysInstallElevated()
        {
            Beaprint.Yellow("\n[+] Checking AlwaysInstallElevated...");
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Installer"))
                {
                    if (key != null)
                    {
                        var value = key.GetValue("AlwaysInstallElevated");
                        if (value != null && value.ToString() == "1")
                        {
                            Beaprint.Red("    [!] ALWAYSINSTALLELEVATED ENABLED - Can install MSI as SYSTEM!");
                            Beaprint.Red("    Exploit: msfvenom -p windows/x64/shell_reverse_tcp ...");
                        }
                        else
                        {
                            Beaprint.Green("    [+] Not vulnerable");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.Yellow($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckUnquotedServicePaths()
        {
            Beaprint.Yellow("\n[+] Checking for unquoted service paths...");
            try
            {
                var services = ServiceHelper.GetServices();
                foreach (var svc in services)
                {
                    if (string.IsNullOrEmpty(svc.Path)) continue;

                    // Ако пътят съдържа интервал и не е в кавички
                    if (svc.Path.Contains(" ") && !svc.Path.StartsWith("\""))
                    {
                        // Вземи първата част от пътя до първия интервал
                        var firstPart = svc.Path.Split(' ')[0];
                        if (firstPart.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                        {
                            Beaprint.Red($"    [!] Unquoted path: {svc.Name} - {svc.Path}");
                            Beaprint.Yellow($"    Potential hijack: {firstPart}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.Yellow($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckWeakServicePermissions()
        {
            Beaprint.Yellow("\n[+] Checking for weak service permissions...");
            try
            {
                var services = ServiceHelper.GetServices();
                foreach (var svc in services)
                {
                    if (string.IsNullOrEmpty(svc.Name)) continue;

                    var sd = ServiceHelper.GetServiceSecurity(svc.Name);
                    if (sd != null)
                    {
                        // Проверка дали текущия потребител има права за промяна на услугата
                        var identity = WindowsIdentity.GetCurrent();
                        if (sd.IsOwner(identity.User) || sd.IsGranted(identity.User, System.Security.AccessControl.ServiceRights.ChangeConfiguration))
                        {
                            Beaprint.Red($"    [!] Weak permissions on: {svc.Name} - Can modify service!");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.Yellow($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckUserPrivileges()
        {
            Beaprint.Yellow("\n[+] Checking current user privileges...");
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                foreach (var claim in identity.Claims)
                {
                    // Проверка за интересни привилегии
                    if (claim.Value.Contains("SeDebugPrivilege") ||
                        claim.Value.Contains("SeImpersonatePrivilege") ||
                        claim.Value.Contains("SeAssignPrimaryTokenPrivilege") ||
                        claim.Value.Contains("SeTakeOwnershipPrivilege") ||
                        claim.Value.Contains("SeRestorePrivilege"))
                    {
                        Beaprint.Red($"    [!] Found privilege: {claim.Value}");
                    }
                }

                // Проверка дали е администратор
                var principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Beaprint.Yellow("    [+] User is Administrator");
                }
                else
                {
                    Beaprint.Green("    [+] User is NOT Administrator");
                }
            }
            catch (Exception ex)
            {
                Beaprint.Yellow($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckStartupFolders()
        {
            Beaprint.Yellow("\n[+] Checking startup folders for write access...");
            try
            {
                var paths = new List<string>
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                    Environment.GetFolderPath(Environment.SpecialFolder.Startup)
                };

                foreach (var path in paths)
                {
                    if (Directory.Exists(path))
                    {
                        var canWrite = FileHelper.HasWriteAccess(path);
                        if (canWrite)
                        {
                            Beaprint.Red($"    [!] Writeable startup folder: {path}");
                        }
                        else
                        {
                            Beaprint.Green($"    [+] Not writeable: {path}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.Yellow($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckWriteablePathFolders()
        {
            Beaprint.Yellow("\n[+] Checking PATH folders for write access...");
            try
            {
                var pathEnv = Environment.GetEnvironmentVariable("PATH");
                if (!string.IsNullOrEmpty(pathEnv))
                {
                    var folders = pathEnv.Split(';');
                    foreach (var folder in folders)
                    {
                        if (!string.IsNullOrEmpty(folder) && Directory.Exists(folder))
                        {
                            var canWrite = FileHelper.HasWriteAccess(folder);
                            if (canWrite)
                            {
                                Beaprint.Red($"    [!] Writeable PATH folder: {folder}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.Yellow($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckInstalledAV()
        {
            Beaprint.Yellow("\n[+] Checking installed antivirus software...");
            try
            {
                using (var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Exclusions"))
                {
                    if (key != null)
                    {
                        Beaprint.Yellow("    [*] Windows Defender found");
                        foreach (var name in key.GetValueNames())
                        {
                            Beaprint.Yellow($"        Exclusion: {name} = {key.GetValue(name)}");
                        }
                    }
                }
            }
            catch
            {
                Beaprint.Yellow("    [-] No AV info found");
            }
        }

        #endregion
    }
}