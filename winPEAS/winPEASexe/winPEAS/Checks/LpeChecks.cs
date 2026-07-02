using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;
using winPEAS.Helpers;

namespace winPEAS.Checks
{
    public class LpeChecker : ISystemCheck
    {
        public string Id => "LPE_CHECKER";
        public string[] MitreAttackIds => new[] { "T1068", "T1134", "T1574", "T1543", "T1548" };

        public void PrintInfo(bool isDebug)
        {
            CheckRunner.Run(PrintLpeInfo, isDebug);
        }

        private void PrintLpeInfo()
        {
            Beaprint.GreatPrint("=== LPE CHECKER - ULTIMATE ESCALATION VECTORS ===", "T1068,T1134,T1574,T1543,T1548");

            // All checks
            CheckAlwaysInstallElevated();
            CheckUnquotedServicePaths();
            CheckWeakServicePermissions();
            CheckUserPrivileges();
            CheckStartupFolders();
            CheckWriteablePathFolders();
            CheckScheduledTasks();
            CheckRegistryAutoRun();
            CheckModifiableServices();
            CheckWritableSystemFiles();
            CheckUnattendedFiles();
            CheckSamBackupFiles();

            Beaprint.GoodPrint("\n=== LPE CHECKER COMPLETE ===");
        }

        private void CheckAlwaysInstallElevated()
        {
            Beaprint.MainPrint("AlwaysInstallElevated", "");
            try
            {
                using (var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows\Installer"))
                {
                    if (key != null)
                    {
                        var value = key.GetValue("AlwaysInstallElevated");
                        if (value != null && value.ToString() == "1")
                        {
                            Beaprint.BadPrint("    [!] ALWAYSINSTALLELEVATED ENABLED - Can install MSI as SYSTEM!");
                        }
                        else
                        {
                            Beaprint.GoodPrint("    [+] Not vulnerable");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckUnquotedServicePaths()
        {
            Beaprint.MainPrint("Unquoted Service Paths", "");
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service"))
                {
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
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckWeakServicePermissions()
        {
            Beaprint.MainPrint("Weak Service Permissions", "");
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        string name = service["Name"]?.ToString() ?? "";
                        string path = service["PathName"]?.ToString() ?? "";
                        string startName = service["StartName"]?.ToString() ?? "";

                        if (string.IsNullOrEmpty(name)) continue;

                        // Check if service is running as SYSTEM and is modifiable
                        if (startName.Contains("LocalSystem") || startName.Contains("SYSTEM"))
                        {
                            // Check if path is writable
                            if (!string.IsNullOrEmpty(path) && File.Exists(path))
                            {
                                try
                                {
                                    var security = File.GetAccessControl(path);
                                    var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                                    foreach (FileSystemAccessRule rule in rules)
                                    {
                                        if (rule.AccessControlType == AccessControlType.Allow)
                                        {
                                            if (rule.FileSystemRights.HasFlag(FileSystemRights.Write) ||
                                                rule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                                            {
                                                if (rule.IdentityReference.Value.Contains("Everyone") ||
                                                    rule.IdentityReference.Value.Contains("Users") ||
                                                    rule.IdentityReference.Value.Contains("Authenticated Users"))
                                                {
                                                    Beaprint.BadPrint($"    [!] Weak service permissions: {name}");
                                                    Beaprint.ColorPrint($"    Path: {path}", Beaprint.ansi_color_yellow);
                                                    Beaprint.ColorPrint($"    Writable by: {rule.IdentityReference.Value}", Beaprint.ansi_color_yellow);
                                                }
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckUserPrivileges()
        {
            Beaprint.MainPrint("User Privileges", "");
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                bool foundPriv = false;
                var dangerousPrivs = new[] {
                    "SeDebugPrivilege",
                    "SeImpersonatePrivilege",
                    "SeAssignPrimaryTokenPrivilege",
                    "SeTakeOwnershipPrivilege",
                    "SeRestorePrivilege",
                    "SeBackupPrivilege",
                    "SeCreateTokenPrivilege",
                    "SeLoadDriverPrivilege",
                    "SeSystemtimePrivilege"
                };

                foreach (var claim in identity.Claims)
                {
                    foreach (var priv in dangerousPrivs)
                    {
                        if (claim.Value.Contains(priv))
                        {
                            Beaprint.BadPrint($"    [!] Found dangerous privilege: {claim.Value}");
                            foundPriv = true;
                        }
                    }
                }
                if (!foundPriv)
                {
                    Beaprint.GoodPrint("    [+] No dangerous privileges found");
                }

                var principal = new WindowsPrincipal(identity);
                if (principal.IsInRole(WindowsBuiltInRole.Administrator))
                {
                    Beaprint.ColorPrint("    [+] User is Administrator", Beaprint.ansi_color_yellow);
                }
                else
                {
                    Beaprint.GoodPrint("    [+] User is NOT Administrator");
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckStartupFolders()
        {
            Beaprint.MainPrint("Startup Folders", "");
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
                        bool canWrite = true;
                        try
                        {
                            string testFile = Path.Combine(path, "test.tmp");
                            using (var fs = File.OpenWrite(testFile))
                            {
                                fs.WriteByte(0);
                            }
                            File.Delete(testFile);
                        }
                        catch
                        {
                            canWrite = false;
                        }

                        if (canWrite)
                        {
                            Beaprint.BadPrint($"    [!] Writeable startup folder: {path}");
                        }
                        else
                        {
                            Beaprint.GoodPrint($"    [+] Not writeable: {path}");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckWriteablePathFolders()
        {
            Beaprint.MainPrint("PATH Folders", "");
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
                            bool canWrite = true;
                            try
                            {
                                string testFile = Path.Combine(folder, "test.tmp");
                                using (var fs = File.OpenWrite(testFile))
                                {
                                    fs.WriteByte(0);
                                }
                                File.Delete(testFile);
                            }
                            catch
                            {
                                canWrite = false;
                            }

                            if (canWrite)
                            {
                                Beaprint.BadPrint($"    [!] Writeable PATH folder: {folder}");
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckScheduledTasks()
        {
            Beaprint.MainPrint("Scheduled Tasks", "");
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM ScheduledTasks"))
                {
                    foreach (ManagementObject task in searcher.Get())
                    {
                        string name = task["Name"]?.ToString() ?? "";
                        string command = task["Command"]?.ToString() ?? "";

                        if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(command))
                        {
                            if (File.Exists(command))
                            {
                                try
                                {
                                    var security = File.GetAccessControl(command);
                                    var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                                    foreach (FileSystemAccessRule rule in rules)
                                    {
                                        if (rule.AccessControlType == AccessControlType.Allow)
                                        {
                                            if (rule.FileSystemRights.HasFlag(FileSystemRights.Write) ||
                                                rule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                                            {
                                                if (rule.IdentityReference.Value.Contains("Everyone") ||
                                                    rule.IdentityReference.Value.Contains("Users"))
                                                {
                                                    Beaprint.BadPrint($"    [!] Modifiable scheduled task: {name}");
                                                    Beaprint.ColorPrint($"    Command: {command}", Beaprint.ansi_color_yellow);
                                                }
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckRegistryAutoRun()
        {
            Beaprint.MainPrint("Registry AutoRun", "");
            try
            {
                var regPaths = new[]
                {
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                    @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
                };

                foreach (var regPath in regPaths)
                {
                    using (var key = Registry.LocalMachine.OpenSubKey(regPath))
                    {
                        if (key != null)
                        {
                            foreach (var valueName in key.GetValueNames())
                            {
                                string value = key.GetValue(valueName)?.ToString() ?? "";
                                if (!string.IsNullOrEmpty(value) && File.Exists(value))
                                {
                                    try
                                    {
                                        var security = File.GetAccessControl(value);
                                        var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                                        foreach (FileSystemAccessRule rule in rules)
                                        {
                                            if (rule.AccessControlType == AccessControlType.Allow)
                                            {
                                                if (rule.FileSystemRights.HasFlag(FileSystemRights.Write) ||
                                                    rule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                                                {
                                                    if (rule.IdentityReference.Value.Contains("Everyone") ||
                                                        rule.IdentityReference.Value.Contains("Users"))
                                                    {
                                                        Beaprint.BadPrint($"    [!] Modifiable autorun: {valueName}");
                                                        Beaprint.ColorPrint($"    Path: {value}", Beaprint.ansi_color_yellow);
                                                        Beaprint.ColorPrint($"    Writable by: {rule.IdentityReference.Value}", Beaprint.ansi_color_yellow);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckModifiableServices()
        {
            Beaprint.MainPrint("Modifiable Services", "");
            try
            {
                using (var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_Service"))
                {
                    foreach (ManagementObject service in searcher.Get())
                    {
                        string name = service["Name"]?.ToString() ?? "";
                        string path = service["PathName"]?.ToString() ?? "";

                        if (string.IsNullOrEmpty(name)) continue;

                        // Check if service path is writeable
                        if (!string.IsNullOrEmpty(path) && File.Exists(path))
                        {
                            try
                            {
                                var security = File.GetAccessControl(path);
                                var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                                foreach (FileSystemAccessRule rule in rules)
                                {
                                    if (rule.AccessControlType == AccessControlType.Allow)
                                    {
                                        if (rule.FileSystemRights.HasFlag(FileSystemRights.Write) ||
                                            rule.FileSystemRights.HasFlag(FileSystemRights.Modify) ||
                                            rule.FileSystemRights.HasFlag(FileSystemRights.FullControl))
                                        {
                                            if (rule.IdentityReference.Value.Contains("Everyone") ||
                                                rule.IdentityReference.Value.Contains("Users"))
                                            {
                                                Beaprint.BadPrint($"    [!] Modifiable service binary: {name}");
                                                Beaprint.ColorPrint($"    Path: {path}", Beaprint.ansi_color_yellow);
                                                Beaprint.ColorPrint($"    Writable by: {rule.IdentityReference.Value}", Beaprint.ansi_color_yellow);
                                            }
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckWritableSystemFiles()
        {
            Beaprint.MainPrint("Writable System Files", "");
            try
            {
                var systemPaths = new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Environment.GetFolderPath(Environment.SpecialFolder.Windows)
                };

                foreach (var path in systemPaths)
                {
                    if (Directory.Exists(path))
                    {
                        var files = Directory.GetFiles(path, "*.exe").Take(100);
                        foreach (var file in files)
                        {
                            try
                            {
                                var security = File.GetAccessControl(file);
                                var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                                foreach (FileSystemAccessRule rule in rules)
                                {
                                    if (rule.AccessControlType == AccessControlType.Allow)
                                    {
                                        if (rule.FileSystemRights.HasFlag(FileSystemRights.Write) ||
                                            rule.FileSystemRights.HasFlag(FileSystemRights.Modify))
                                        {
                                            if (rule.IdentityReference.Value.Contains("Everyone") ||
                                                rule.IdentityReference.Value.Contains("Users"))
                                            {
                                                Beaprint.BadPrint($"    [!] Writable system file: {Path.GetFileName(file)}");
                                                Beaprint.ColorPrint($"    Path: {file}", Beaprint.ansi_color_yellow);
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckUnattendedFiles()
        {
            Beaprint.MainPrint("Unattended Files", "");
            try
            {
                var patterns = new[] { "unattend.xml", "sysprep.inf", "sysprep.xml", "autounattend.xml" };
                var drives = DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed);

                foreach (var drive in drives)
                {
                    foreach (var pattern in patterns)
                    {
                        var files = Directory.GetFiles(drive.RootDirectory.FullName, pattern, SearchOption.AllDirectories);
                        foreach (var file in files)
                        {
                            try
                            {
                                var content = File.ReadAllText(file);
                                if (content.Contains("Administrator") ||
                                    content.Contains("Password") ||
                                    content.Contains("UserPassword"))
                                {
                                    Beaprint.BadPrint($"    [!] Unattended file with credentials: {file}");
                                }
                            }
                            catch { }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }

        private void CheckSamBackupFiles()
        {
            Beaprint.MainPrint("SAM Backup Files", "");
            try
            {
                var paths = new[]
                {
                    @"C:\Windows\Repair\SAM",
                    @"C:\Windows\System32\config\RegBack\SAM",
                    @"C:\Windows\System32\config\SAM"
                };

                foreach (var path in paths)
                {
                    if (File.Exists(path))
                    {
                        try
                        {
                            var security = File.GetAccessControl(path);
                            var rules = security.GetAccessRules(true, true, typeof(NTAccount));

                            foreach (FileSystemAccessRule rule in rules)
                            {
                                if (rule.AccessControlType == AccessControlType.Allow)
                                {
                                    if (rule.FileSystemRights.HasFlag(FileSystemRights.Read))
                                    {
                                        Beaprint.BadPrint($"    [!] Accessible SAM file: {path}");
                                        Beaprint.ColorPrint($"    Readable by: {rule.IdentityReference.Value}", Beaprint.ansi_color_yellow);
                                    }
                                }
                            }
                        }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                Beaprint.PrintException($"    [-] Error: {ex.Message}");
            }
        }
    }
}