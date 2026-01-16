/*
 * 
 * To switch between AKM-Fileserver and any other fileserver, see and change these lines:
 * Search "for fileserver"
 * 446
 * 478
 * 563
 * 
 */


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.Mail;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Xml.Linq;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.Text.RegularExpressions;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Reflection;
using OfficeOpenXml;  // EPPlus Namespace
using OfficeOpenXml.Style;
using OfficeOpenXml.Filter;
using System.Drawing;
using System.Data;
using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Security;
using System.Diagnostics;
using System.Diagnostics.Metrics;

using System.Threading.Tasks;

public class Program
{

    #region Parameters

    /// <summary>
    /// This will be set to true if the User cancels the program. 
    /// </summary>
    public static bool userCancelled = false;

    /// <summary>
    /// This will be set to true if the program has finished as it should.
    /// </summary>
    public static bool fullyExecuted = false;

    /// <summary>
    /// For percentage display when analyzing the folder structure.
    /// </summary>
    public static int numberOfFolders = 0;

    /// <summary>
    /// The sum of all permissions to be used in statistics output.
    /// </summary>
    public static int numberOfPermissions = 0;

    /// <summary>
    /// List of AD users generated at start to distinct NTFS accounts
    /// </summary>
    public static List<string> userList = new List<string>();

    /// <summary>
    /// List of AD groups generated at start to distinct NTFS accounts
    /// </summary>
    public static List<string> groupList = new List<string>();

    /// <summary>
    /// A list of found(!) accounts that are configured to ignore
    /// users and groups
    /// Are shown in statistics (accounts with explicit permissions)
    /// </summary>
    public static List<string> ignoredAccountsList = new List<string>();

    /// <summary>
    /// Path to store the CSV file.
    /// </summary>
    public static string outfilePath = String.Empty;

    /// <summary>
    /// Path to store the log file.
    /// </summary>
    public static string logfilePath = String.Empty;

    /// <summary>
    /// Path to store the excel file.
    /// </summary>
    public static string excelfilePath = String.Empty;

    /// <summary>
    /// Read from config.xml to set mode (all or only non-inherited)
    /// \todo I think this is deprecated
    /// \deprecated Not used anywhere
    /// </summary>
    public static int showOnlyBroken = 0;

    /// <summary>
    /// Accounts to ignore, read from config.xml
    /// </summary>
    public static List<string> ignoredNames = ReadConfigList("//ignoredAccounts/account");

    /// <summary>
    /// Accounts to ignore (by wildcard), read from config.xml
    /// </summary>
    public static List<string> ignoredNamesWildcard = ReadConfigList("//ignoredAccountsWildcard/account");

    /// <summary>
    /// Unique list of user with explicit permissions
    /// </summary>
    public static List<string> explicitPermissionUsers = new List<string>();

    /// <summary>
    /// Unique list of groups with explicit permissions
    /// </summary>
    public static List<string> explicitPermissionGroups = new List<string>();

    /// <summary>
    /// Unique list of folders with explicit permissions for users
    /// </summary>
    public static List<string> explicitPermissionFoldersUsers = new List<string>();

    /// <summary>
    /// Unique list of folders with explicit permissions for groups
    /// </summary>
    public static List<string> explicitPermissionFoldersGroups = new List<string>();

    /// <summary>
    /// List of folders with explicit non-inherited permissions for users
    /// </summary>
    public static List<string> explicitPermissionFoldersUsersInherited = new List<string>();

    /// <summary>
    /// List of folders with explicit non-inherited permissions for groups
    /// </summary>
    public static List<string> explicitPermissionFoldersGroupsInherited = new List<string>();

    /// <summary>
    /// The generated excel file
    /// </summary>
    public static ExcelPackage excelPackage; // = new ExcelPackage();

    /// <summary>
    /// Overview Sheet
    /// </summary>
    public static ExcelWorksheet overviewSheet; // = excelPackage.Workbook.Worksheets.Add("Overview");
    public static int overviewSheetRowCounter = 1; // 1st row is header

    /// <summary>
    /// Group Member Sheet
    /// </summary>
    public static ExcelWorksheet groupMemberSheet; // = excelPackage.Workbook.Worksheets.Add("Group Member");
    public static int groupMemberSheetRowCounter = 1; // 1st row is header

    /// <summary>
    /// Explicit User Permissions Sheet
    /// </summary>
    public static ExcelWorksheet explicitUserPermissionsSheet; // = excelPackage.Workbook.Worksheets.Add("Explicit User Permissions");
    public static int explicitUserPermissionsSheetRowCounter = 1; // 1st row is header

    /// <summary>
    /// Explicit Group Permissions Sheet
    /// </summary>
    public static ExcelWorksheet explicitGroupPermissionsSheet; // = excelPackage.Workbook.Worksheets.Add("Explicit Group Permissions");
    public static int explicitGroupPermissionsSheetRowCounter = 1; // 1st row is header

    /// <summary>
    /// Permissions are split into several sheets because there is a limit of 1.048.576 (2^20) rows per sheet.
    /// </summary>
    public static ExcelWorksheet currentSheet;

    /// <summary>
    /// The index of the current sheet.
    /// </summary>
    public static int currentSheetCounter = 1;

    /// <summary>
    /// The row counter of the current permissions sheet.
    /// </summary>
    public static int currentSheetRowCounter = 1;

    /// <summary>
    /// Holds recursive groups which have to be resolved
    /// </summary>
    public static List<string> recursiveGroupsToResolve = new List<string>();

    /// <summary>
    /// The name of the share to examine
    /// </summary>
    public static string sharename = String.Empty;

    /// <summary>
    /// The manager responsible for the share
    /// </summary>
    public static string shareManager = String.Empty;

    /// <summary>
    /// The OU of the share manager to distinct foreign users.
    /// Foreign users are users that are in a different OU than the share manager.
    /// </summary>
    public static string shareManagerOU = String.Empty;

    /// <summary>
    /// Groups that contains foreign members
    /// </summary>
    public static List<string> groupsWithForeignMembers = new List<string>();

    /// <summary>
    /// A list of all foreign members to mark them in permissions sheets
    /// </summary>
    public static List<string> foreignMembers = new List<string>();

    /// <summary>
    /// The full domain name read from config file
    /// </summary>
    public static string domain = String.Empty;

    /// <summary>
    /// The domain name read from config file domainName.domainExtension
    /// </summary>
    public static string domainName = String.Empty;

    /// <summary>
    /// The domain extension read from config file domainName.domainExtension
    /// </summary>
    public static string domainExtension = String.Empty;

    #endregion

    #region Methods

    /// <summary>
    /// Main function
    /// </summary>
    /// <param name="args">Commandline parameters (sharename, managerName)</param>
    public static int Main(string[] args)
    {

        // watch for ctrl-c
        Console.CancelKeyPress += new ConsoleCancelEventHandler(CancelKeyPressHandler);

        // watch for program exit
        AppDomain.CurrentDomain.ProcessExit += new EventHandler(ProcessExitHandler);

        // watch for unhandled exceptions
        AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
        {
            Exception ex = (Exception)e.ExceptionObject;
            WriteCustomEventLog($"Unbehandelte Ausnahme: {ex.Message}\n\nStackTrace: {ex.StackTrace}", EventLogEntryType.Error, 1, 1);
            Console.WriteLine($"Unbehandelte Ausnahme: {ex.Message}\n\nStackTrace: {ex.StackTrace}");
            Environment.Exit(1);

        };

        // thank you epplus
        // deprecated
        // ExcelPackage.LicenseContext = OfficeOpenXml.LicenseContext.NonCommercial;
        ExcelPackage.License.SetNonCommercialPersonal("Manuel Zarat");

        excelPackage = new ExcelPackage();

        // vba code
        // excelPackage.Workbook.CreateVBAProject();

        // change order according to WG
        overviewSheet = excelPackage.Workbook.Worksheets.Add("Übersicht");
        explicitUserPermissionsSheet = excelPackage.Workbook.Worksheets.Add("Explizite Userberechtigungen");
        explicitGroupPermissionsSheet = excelPackage.Workbook.Worksheets.Add("Explizite Gruppenberechtigungen");
        groupMemberSheet = excelPackage.Workbook.Worksheets.Add("Gruppenmitglieder");
        currentSheet = excelPackage.Workbook.Worksheets.Add("Alle Berechtigungen " + currentSheetCounter);
        currentSheet.View.FreezePanes(2, 1);

        overviewSheet.TabColor = System.Drawing.Color.Orange;
        groupMemberSheet.TabColor = System.Drawing.Color.Blue;
        currentSheet.TabColor = System.Drawing.Color.Green;

        Console.WriteLine("\n\tNTFSAuditor\n\t(C) 2024 - AKM AustroMechana\n");

        if (args.Length == 0)
        {
            Console.WriteLine($"\tUsage: {Assembly.GetExecutingAssembly().GetName().Name}.exe <ShareName> [<ShareManager>]\n");
            Environment.Exit(1);
            //return 1;
        }

        sharename = args[0];


        // read domain name from config file
        string domain_tmp = (string)ReadConfig("/config/general/domain");
        if (domain_tmp != null && domain_tmp != "")
        {
            domain = domain_tmp;
            string[] domainParts = domain_tmp.Split('.');
            domainName = domainParts[0];
            domainExtension = domainParts[1];
        }

        // after "domain" was read from config
        // \todo
        if (args.Length == 2)
        {
            shareManager = args[1];
            shareManagerOU = GetMemberOU(shareManager);
            Console.WriteLine($"[debug] {shareManager} hat die OU {shareManagerOU}");
        }

        WriteCustomEventLog($"Berechtigungsaudit für \"{sharename}\" hat begonnen.", EventLogEntryType.Information, 1, 1);

        // Use current directory
        //string year = DateTime.Now.ToString("yyyy");
        //string outdir = $@"C:\Scripts\Berechtigungsaudit\Shares\{year}";
        string outdir = Path.Combine(AppContext.BaseDirectory, "output");

        string outdir_tmp = (string)ReadConfig("/config/general/outdir");
        if (outdir_tmp != null && outdir_tmp != "")
        {
            outdir = outdir_tmp;
        }

        if (!Directory.Exists(outdir))
        {
            Directory.CreateDirectory(outdir);
        }

        string datenow = DateTime.Now.ToString("yyyy-MM-dd");
        string shareNameForFile = sharename.Contains(@"\") ? sharename.Split('\\').Last() : sharename;
        string outfile = $"{shareNameForFile}_ntfs_{datenow}.csv";

        outfilePath = Path.Combine(outdir, outfile);
        // xlsm to support VBA macros
        excelfilePath = outfilePath.Replace("csv", "xlsx");

        overviewSheet.Cells[overviewSheetRowCounter++, 1].Value = "Bericht generiert am " + DateTime.Now.ToString("dd.MM.yyyy") + " um " + DateTime.Now.ToString("HH:mm");
        overviewSheet.Cells[overviewSheetRowCounter++, 1].Value = "Netzwerkfreigabe: " + sharename;

        if (shareManager != String.Empty)
        {
            overviewSheet.Cells[overviewSheetRowCounter++, 1].Value = $"Verantwortlicher: {shareManager}";
            overviewSheet.Cells[overviewSheetRowCounter++, 1].Value = $"Als \"Foreign Member\" werden Benutzer bezeichnet, deren OU von der des Shareverantwortlichen ({shareManager}) abweichen.";
        }

        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.WrapText = true;
        overviewSheet.Cells[overviewSheetRowCounter, 1].Value = "Achtung: Bitte aktivieren Sie die Bearbeitung damit Verlinkungen korrekt dargestellt werden.";
        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.BackgroundColor.SetColor(Color.Yellow);

        overviewSheetRowCounter++;
        overviewSheet.Column(1).Width = 100;

        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 1].Value = "FolderPath";
        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 2].Value = "IdentityReference";
        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 3].Value = "Berechtigung";
        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 4].Value = "Berechtigung vererbt";
        explicitUserPermissionsSheetRowCounter++;

        // set column width
        explicitUserPermissionsSheet.Column(1).Width = 50;
        explicitUserPermissionsSheet.Column(2).Width = 50;
        explicitUserPermissionsSheet.Column(3).Width = 50;
        explicitUserPermissionsSheet.Column(4).Width = 50;

        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 1].Value = "FolderPath";
        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 2].Value = "IdentityReference";
        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 3].Value = "Berechtigung";
        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 4].Value = "Berechtigung vererbt";
        explicitGroupPermissionsSheetRowCounter++;

        // set column width
        explicitGroupPermissionsSheet.Column(1).Width = 50;
        explicitGroupPermissionsSheet.Column(2).Width = 50;
        explicitGroupPermissionsSheet.Column(3).Width = 50;
        explicitGroupPermissionsSheet.Column(4).Width = 50;

        currentSheet.Cells[currentSheetRowCounter, 1].Value = "FolderPath";
        currentSheet.Cells[currentSheetRowCounter, 2].Value = "IdentityReference";
        currentSheet.Cells[currentSheetRowCounter, 3].Value = "Berechtigung";
        currentSheet.Cells[currentSheetRowCounter, 4].Value = "Berechtigung vererbt";
        if (shareManager != String.Empty)
            currentSheet.Cells[currentSheetRowCounter, 5].Value = "beinhaltet bereichsfremde Mitglieder";
        currentSheetRowCounter++;

        // set column width
        currentSheet.Column(1).Width = 50;
        currentSheet.Column(2).Width = 50;
        currentSheet.Column(3).Width = 50;
        currentSheet.Column(4).Width = 25;
        if (shareManager != String.Empty)
            currentSheet.Column(5).Width = 25;

        CreateUserList();
        CreateGroupList();

        // log found users and groups
        //foreach(string s in userList) { File.AppendAllText(outfilePath + ".log", s + " (user)" + Environment.NewLine); }
        //foreach(string s in groupList) { File.AppendAllText(outfilePath + ".log", s + " (group)" + Environment.NewLine); }

        if (File.Exists(outfilePath)) { File.Delete(outfilePath); }

        string outputString = "FolderPath;IdentityReference;FileSystemRights;IsInherited";
        File.AppendAllText(outfilePath, outputString + Environment.NewLine);

        DateTime startDate = DateTime.Now;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Start am \"{startDate}\"");
        Console.ResetColor();

        string remoteComputer = "fileserver";
        string remoteComputer_tmp = (string)ReadConfig("/config/general/servername");
        if (remoteComputer_tmp != null && remoteComputer_tmp != "")
        {
            remoteComputer = remoteComputer_tmp;
        }

        try
        {

            ManagementScope scope = new ManagementScope($@"\\{remoteComputer}\root\cimv2");
            scope.Connect();

            // Find all shares
            string query1 = "SELECT * FROM Win32_Share";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query1));

            Console.Write("[info] Ermittle verfügbare Shares.. ");

            ManagementObjectCollection results = searcher.Get();

            // Ausgabe aller Shares (debug)
            /*
            foreach (ManagementObject obj in results)
            {
                foreach (PropertyData property in obj.Properties)
                {
                    Console.WriteLine($"{property.Name}: {property.Value}");
                }

                Console.WriteLine(new string('-', 50)); // Trennlinie für Übersichtlichkeit
            }
            */

            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OK!");
            Console.ResetColor();

            /*
             * Find the corresponding share
             */
            //var foundShare = results.Cast<ManagementObject>().FirstOrDefault(s => s["Name"].ToString() == sharename);

            // For fileserver
            // \todo uncpath as sharename ...
            var foundShare = results.Cast<ManagementObject>().FirstOrDefault(s => s["Name"].ToString().ToLower() == "\\\\" + remoteComputer + "\\" + sharename.ToLower());

            // any other
            //var foundShare = results.Cast<ManagementObject>().FirstOrDefault(s => s["Name"].ToString().ToLower() == sharename.ToLower());

            // Todo: Error code when no share was found
            if (foundShare != null)
            {

                string found_shareName = foundShare["Name"].ToString();
                string found_sharePath = foundShare["Path"].ToString();

                // Get Share permissions
                Console.WriteLine($"[info] Ermittle Share-Berechtigungen (SMB) für \"{found_shareName}\"");

                string escapedShareName = found_shareName.Replace("\\", "\\\\");

                ObjectQuery query2 = new ObjectQuery($"SELECT * FROM Win32_Share WHERE name LIKE '{escapedShareName}'");
                searcher = new ManagementObjectSearcher(scope, query2);

                foreach (ManagementObject share in searcher.Get())
                {

                    //Console.WriteLine("[debug] foundSharename = " + found_shareName + "; excapedSharename = " + escapedShareName);

                    int foundSMBPermissions = 0;

                    try
                    {

                        // \todo
                        // for fileserver
                        // has UNC path in its name!!!
                        DirectoryInfo dirInfo = new DirectoryInfo(share["Name"].ToString());

                        // any other
                        //DirectoryInfo dirInfo = new DirectoryInfo("\\\\" + remoteComputer + "\\" + share["Name"].ToString());

                        DirectorySecurity dirSecurity = dirInfo.GetAccessControl();
                        AuthorizationRuleCollection rules = dirSecurity.GetAccessRules(true, true, typeof(NTAccount));

                        overviewSheetRowCounter++;
                        overviewSheet.Cells[overviewSheetRowCounter, 1].Value = "Share Berechtigungen:";
                        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
                        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.BackgroundColor.SetColor(Color.LightBlue);
                        overviewSheetRowCounter++;

                        foreach (FileSystemAccessRule rule in rules)
                        {

                            string identity = rule.IdentityReference.Value;

                            // Skip ignored identities
                            if (ignoredNames.Contains(identity))
                            {
                                continue;
                            }

                            bool doContinue = false;

                            // Check for wildcard ignored patterns
                            foreach (var pattern in ignoredNamesWildcard)
                            {
                                if (Regex.IsMatch(identity, pattern))
                                {
                                    doContinue = true;
                                    break;
                                }
                            }

                            if (doContinue)
                            {
                                continue;
                            }

                            overviewSheet.Cells[overviewSheetRowCounter, 1].Value = $"{rule.IdentityReference.Value}";
                            overviewSheet.Cells[overviewSheetRowCounter, 2].Value = $"{rule.FileSystemRights}";
                            overviewSheetRowCounter++;

                            foundSMBPermissions++;

                        }

                    }
                    catch (UnauthorizedAccessException ex)
                    {

                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[error] Zugriff auf SMB Berechtigungen verweigert: {ex.Message}");
                        Console.ResetColor();
                        WriteCustomEventLog($"Zugriff auf SMB Berechtigungen für \"{found_shareName}\" verweigert.\n{ex.Message}", EventLogEntryType.Error, 1, 1);

                    }
                    catch (Exception ex)
                    {

                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[error] Unbekannter Fehler beim Zugriff auf SMB Berechtigungen für \"{found_shareName}\": {ex.Message}");
                        Console.ResetColor();
                        WriteCustomEventLog($"Unbekannter Fehler beim Zugriff auf SMB Berechtigungen für \"{found_shareName}\":\n\n{ex.Message}", EventLogEntryType.Error, 1, 1);

                    }
                    finally
                    {

                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine($"[info] OK! {foundSMBPermissions} SMB Berechtigungen protokolliert.");
                        Console.ResetColor();

                    }

                }

                try
                {

                    // \todo
                    // for fileserver
                    ProcessRootDirectory(found_shareName, outfilePath);
                    // any other
                    //ProcessRootDirectory("\\\\" + remoteComputer + "\\" + found_shareName, outfilePath);

                }
                catch (UnauthorizedAccessException ex)
                { }
                catch (Exception ex)
                { }

            }
            else
            {

                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[error] Share \"{sharename}\" konnte nicht gefunden werden.");
                Console.ResetColor();
                WriteCustomEventLog($"Share \"{sharename}\" konnte nicht gefunden werden. Audit wird beendet.", EventLogEntryType.Error, 1, 1);
                Environment.Exit(1);

            }

        }
        catch (Exception ex)
        {

            Console.WriteLine($"Der WMI Zugriff zum Auslesen der SMB Berechtigungen auf {remoteComputer} wurde verweigert");
            WriteCustomEventLog($"Der WMI Zugriff zum Auslesen der SMB Berechtigungen auf {remoteComputer} wurde verweigert", EventLogEntryType.Error, 1, 1, "WMI Fehler");
            Environment.Exit(1);

        }

        DateTime endDate = DateTime.Now;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Beendet am \"{endDate}\"");
        Console.ResetColor();

        TimeSpan executionTime = endDate - startDate;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Ausführungsdauer: \"{executionTime}\"");
        Console.ResetColor();

        // mark nested groups
        GenerateGroupMember();

        // resolve nested groups before releasing memory!
        ResolveRecursiveGroups();
        UpdateResolvedGroupLinks();

        // mark groups with foreign members in accessrights sheets
        // \todo check nested groups
        // \todo only execute when a sharemanager has been passed
        if (shareManager != String.Empty)
        {

            for (int i = 1; i <= currentSheetCounter; i++)
            {

                string sheetName_tmp = "Alle Berechtigungen " + i;

                var _ws = excelPackage.Workbook.Worksheets[sheetName_tmp];

                _ws.TabColor = System.Drawing.Color.Green;

                // skip 1st row, its the header
                for (int r = 2; r <= _ws.Dimension.End.Row; r++)
                {

                    // get the account name
                    string v = _ws.Cells[r, 2].Value.ToString();

                    // mark Groups with foreign OUs
                    if (groupsWithForeignMembers.Contains(v))
                    {
                        _ws.Cells[r, 5].Value = true;
                    }

                    // mark Users with foreign OUs
                    //else if( !IsUserAGroup(v.Replace(domainName + "\\", "")) && !GetMemberOU(v.Replace(domainName + "\\", "")).StartsWith(shareManagerOU) )
                    else if (foreignMembers.Contains(v.Replace(domainName + "\\", "")))
                    {
                        _ws.Cells[r, 5].Value = true;
                    }

                    else
                        _ws.Cells[r, 5].Value = false;
                }

                /*
                //_ws.Cells["D2:D"+ _ws.Dimension.End.Row].AutoFilter = true;
                var colCompany = _ws.AutoFilter.Columns.AddValueFilterColumn(4);
                colCompany.Filters.Add("False");
                _ws.AutoFilter.ApplyFilter();
                */

            }

        }

        double fileSizeInKB = new FileInfo(outfilePath).Length / 1024.0;

        FileInfo fi = new FileInfo(excelfilePath);
        excelPackage.SaveAs(fi);

        Console.Write($"[info] Excel Mappe wird aufbereitet.. ");

        // \todo release memory?
        // do WeakReference really need this?
        ReleaseMemory();

        for (int i = 1; i <= currentSheetCounter; i++)
        {
            UpdateGroupReferences("Alle Berechtigungen " + i, 2, "Gruppenmitglieder", 1);
        }
        UpdateGroupReferences("Explizite Gruppenberechtigungen", 2, "Gruppenmitglieder", 1);
        UpdateGroupReferences("Übersicht", 1, "Gruppenmitglieder", 1);

        double excelFileSizeInKB = new FileInfo(excelfilePath).Length / 1024.0;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("OK!");
        Console.ResetColor();

        try
        {

            string sendto = "meldungen.ber-audit.gbi@akm.at";
            string sendfrom = $"Berechtigungsaudit@{Environment.MachineName}.akm.at";

            string mail_tmp = (string)ReadConfig("/config/email/sendto");
            if (mail_tmp != null && mail_tmp != "")
            {
                sendto = mail_tmp;
            }
            mail_tmp = (string)ReadConfig("/config/email/sendfrom");
            if (mail_tmp != null && mail_tmp != "")
            {
                sendfrom = $"" + mail_tmp;
            }

            MailMessage mail = new MailMessage();
            mail.From = new MailAddress(sendfrom);
            //mail.To.Add("meldungen.ber-audit.gbi@akm.at");
            mail.To.Add(sendto);
            mail.Subject = shareNameForFile + " - CSV erstellt und abgelegt";
            mail.Body = $"{outfile} wurde erstellt und unter \"{outdir}\" abgelegt.\n\n";

            mail.BodyEncoding = System.Text.Encoding.UTF8;
            mail.SubjectEncoding = System.Text.Encoding.UTF8;

            string statistics = $"Startzeit: {startDate}\nEndzeit: {endDate}\nAusführungsdauer: {executionTime}\nDateigröße: {fileSizeInKB:F2} KB\nAnzahl an Verzeichnissen: {numberOfFolders}\nAnzahl an Berechtigungen: {numberOfPermissions}";

            mail.Body += statistics;

            /*
            string logText = String.Empty;
            logText += $"Statistik für: {sharename}\n\n";
            logText += statistics; // + "\n\n";
            logText += "\n\nAus der Erfassung ausgeschlossene Accounts:\n";
            logText += String.Join(Environment.NewLine, ignoredAccountsList.Distinct());
            logText += "\n\nUser mit expliziten Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionUsers.Distinct());
            logText += "\n\nGruppen mit expliziten Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionGroups.Distinct());
            logText += "\n\nOrdner mit unterbrochenen (expliziten) User-Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionFoldersUsers.Distinct());
            logText += "\n\nOrdner mit unterbrochenen (expliziten) Gruppen-Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionFoldersGroups.Distinct());
            logText += "\n\nOrdner mit vererbten (expliziten) User-Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionFoldersUsersInherited.Distinct());
            logText += "\n\nOrdner mit vererbten (expliziten) Gruppen-Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionFoldersGroupsInherited.Distinct());
            File.AppendAllText(logfilePath, logText);
            double logfileSizeInKB = new FileInfo(logfilePath).Length / 1024.0;
            */

            double maxattachmentsize = 50000;
            double maxattachmentsize_tmp = Double.Parse((string)ReadConfig("/config/email/maxattachmentsize"));
            if (maxattachmentsize_tmp != null && maxattachmentsize_tmp.GetType() == typeof(double))
            {
                maxattachmentsize = maxattachmentsize_tmp;
            }

            if (excelFileSizeInKB < maxattachmentsize)
            {
                Attachment attachment = new Attachment(excelfilePath);
                mail.Attachments.Add(attachment);
                mail.Body += $"\n\nIm Anhang finden Sie den Bericht im Excel Format.";
            }
            else
            {
                mail.Body += $"\n\nDie Excel Datei ist zu groß um an die Mail angehängt zu werden ({excelFileSizeInKB:F2} KB) und ist ebenfalls unter \"{outdir}\" abgelegt.";
            }

            //File.AppendAllText(logfilePath, mail.Body);

            string relay = "relay.akm.at";
            string relay_tmp = (string)ReadConfig("/config/email/relay");
            if (relay_tmp != null && relay_tmp != "")
            {
                relay = relay_tmp;
            }
            SmtpClient smtpClient = new SmtpClient(relay);
            smtpClient.UseDefaultCredentials = true;

            smtpClient.Send(mail);
            Console.WriteLine($"[info] E-Mail wurde erfolgreich an \"{sendto}\" gesendet.");

            WriteCustomEventLog($"Email wurde erfolgreich an \"{sendto}\" gesendet.", EventLogEntryType.Information, 1, 1);

        }
        catch (Exception ex)
        {

            Console.WriteLine($"[error] Fehler beim Senden der E-Mail: " + ex.Message);
            WriteCustomEventLog($"Email wurde nicht versendet: " + ex.Message, EventLogEntryType.Error, 1, 1);

        }

        fullyExecuted = true;
        WriteCustomEventLog($"Berechtigungsaudit für \"{sharename}\" wurde beendet.", EventLogEntryType.Information, 1, 1);
        return 0;

    }

    /// <summary>
    /// Find all folders in a Share. This will fail if a directory is inaccessible so <see cref="GetDirectories"/> recursively creates a list of directories to iterate over.
    /// </summary>
    /// <param name="folderPath">The folder path to examine</param>
    /// <param name="outfilePath">The path of the CSV file</param>
    public static void ProcessRootDirectory(string folderPath, string outfilePath)
    {

        Console.WriteLine("[info] Analysiere Verzeichnisstruktur..");

        List<string> allDirectories = new List<string>();

        try
        {

            // recursive lookup
            GetDirectories(folderPath, allDirectories);

        }
        catch (Exception ex)
        {

            Console.WriteLine($"Beim Analysieren der Verzeichnisstruktur ist ein Fehler aufgetreten: {ex.Message}");
            WriteCustomEventLog($"Beim Analysieren der Verzeichnisstruktur ist ein Fehler aufgetreten:\n\n{ex.Message}", EventLogEntryType.Error, 1, 1);

        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] OK! {numberOfFolders} Verzeichnisse gefunden.");
        Console.ResetColor();

        Console.WriteLine("[info] Analysiere Verzeichnisse.. ");

        double percentage = 0;
        int i = 1;
        int max = allDirectories.Count;
        foreach (var dir in allDirectories)
        {

            percentage = (i * 100) / numberOfFolders;
            if (i < max) Console.Write("\r[info] " + percentage + "%");
            else Console.WriteLine("\r[info] " + percentage + "% done!");

            ProcessFolder(dir, outfilePath);
            i++;

        }

    }

    /// <summary>
    /// Faster, but order of processing is not guaranteed.
    /// </summary>
    /// <param name="folderPath"></param>
    /// <param name="outfilePath"></param>
    public static void ProcessRootDirectoryParallel(string folderPath, string outfilePath)
    {
        Console.WriteLine("[info] Analysiere Verzeichnisstruktur..");

        List<string> allDirectories = new List<string>();

        try
        {
            GetDirectories(folderPath, allDirectories);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Ein Fehler ist aufgetreten: {ex.Message}");
            WriteCustomEventLog($"Fehler beim Analysieren der Verzeichnisstruktur.\n\n{ex.Message}", EventLogEntryType.Error, 1, 1);
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] OK! {numberOfFolders} Verzeichnisse gefunden.");
        Console.ResetColor();

        Console.WriteLine("[info] Analysiere Verzeichnisse parallel.. ");

        double percentage = 0;
        int i = 1;
        int max = allDirectories.Count;

        object lockObj = new object(); // Für synchronisierte Ausgabe

        Parallel.ForEach(allDirectories, new ParallelOptions { MaxDegreeOfParallelism = Environment.ProcessorCount }, dir =>
        {
            ProcessFolder(dir, outfilePath);

            lock (lockObj)
            {
                percentage = (i * 100) / numberOfFolders;
                if (i < max) Console.Write("\r[info] " + percentage + "%");
                else Console.WriteLine("\r[info] " + percentage + "% done!");
                i++;
            }
        });
    }

    /// <summary>
    /// Recursive helper function to collect directories even if some paths are non-accessible.
    /// Usually the method <see cref="ProcessRootDirectory"/> will cancel if a path cannot be accessed. 
    /// To prevent that behavior, we first store all directories in a list to iterate over.
    /// </summary>
    /// <param name="folderPath">The folder path to examine</param>
    /// <param name="allDirectories">A list of all directories (recursively filled)</param>
    public static void GetDirectories(string folderPath, List<string> allDirectories)
    {
        try
        {
            // Hole alle Verzeichnisse im aktuellen Verzeichnis
            string[] directories = Directory.GetDirectories(folderPath);

            // Füge das aktuelle Verzeichnis der Liste hinzu
            allDirectories.AddRange(directories);

            // Gehe rekursiv durch jedes Unterverzeichnis
            foreach (string directory in directories)
            {
                // Count folder to compare it to folders we dont have permission!!!
                numberOfFolders++;
                GetDirectories(directory, allDirectories);
            }

        }
        catch (UnauthorizedAccessException ex)
        {
            // Ignoriere die UnauthorizedAccessException und gehe weiter
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[error] Zugriff verweigert auf: {folderPath}");
            Console.ResetColor();

            WriteCustomEventLog($"Beim Zugriff auf\n\n\"{folderPath}\"\n\nist ein Fehler aufgetreten.\n\n{ex.Message}", EventLogEntryType.Warning, 1, 1);
        }
        catch (Exception ex)
        {
            // Behandle andere Ausnahmen (optional)
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[warning] {ex.Message}");
            Console.ResetColor();

            WriteCustomEventLog($"Beim Zugriff auf\n\n\"{folderPath}\"\n\nist ein Fehler aufgetreten.\n\n{ex.Message}", EventLogEntryType.Warning, 1, 1);
        }

    }

    /// <summary>
    /// Get the ACLs of a specific folder
    /// </summary>
    /// <param name="folderPath">The path of the folder to examine.</param>
    /// <param name="outfilePath">The path of the CSV file.</param>
    public static void ProcessFolder(string folderPath, string outfilePath)
    {

        try
        {

            DirectoryInfo directoryInfo = new DirectoryInfo(folderPath);
            DirectorySecurity directorySecurity = directoryInfo.GetAccessControl();
            AuthorizationRuleCollection acl = directorySecurity.GetAccessRules(true, true, typeof(NTAccount));

            foreach (FileSystemAccessRule rule in acl)
            {

                string identity = rule.IdentityReference.Value;

                // Skip ignored identities
                if (ignoredNames.Contains(identity))
                {

                    ignoredAccountsList.Add(identity);
                    continue;

                }

                bool doContinue = false;

                // Check for wildcard ignored patterns
                foreach (var pattern in ignoredNamesWildcard)
                {

                    if (Regex.IsMatch(identity, pattern))
                    {

                        ignoredAccountsList.Add(identity);
                        doContinue = true;
                        break;

                    }

                }

                if (doContinue)
                {
                    continue;
                }

                // If its a user, add him to explicit user permissions list
                if (userList.Contains(identity))
                {

                    if (rule.IsInherited)
                    {

                        explicitPermissionFoldersUsersInherited.Add("\"" + folderPath + "\"");

                    }
                    else
                    {

                        explicitPermissionFoldersUsers.Add("\"" + folderPath + "\"");

                        string outputString_user = $"\"{folderPath}\";{identity};{rule.FileSystemRights.ToString()};{rule.IsInherited}";

                        // \todo
                        // Dont add this - leads to duplicates!
                        //File.AppendAllText(outfilePath, outputString_user + Environment.NewLine);

                        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 1].Value = folderPath;
                        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 2].Value = identity;
                        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 3].Value = rule.FileSystemRights.ToString();
                        explicitUserPermissionsSheet.Cells[explicitUserPermissionsSheetRowCounter, 4].Value = rule.IsInherited;

                        explicitUserPermissionsSheetRowCounter++;

                    }

                    explicitPermissionUsers.Add(identity);

                }

                // If its a group
                if (groupList.Contains(identity))
                {
                    // and the rule IS inherited
                    if (rule.IsInherited)
                    {

                        explicitPermissionFoldersGroupsInherited.Add("\"" + folderPath + "\"");

                    }
                    // otherwise
                    else
                    {

                        explicitPermissionFoldersGroups.Add("\"" + folderPath + "\"");

                        string outputString_group = $"\"{folderPath}\";{identity};{rule.FileSystemRights.ToString()};{rule.IsInherited}";

                        // \todo
                        // Dont add this - leads to duplicates!
                        //File.AppendAllText(outfilePath, outputString_group + Environment.NewLine);

                        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 1].Value = folderPath;
                        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 2].Value = identity;
                        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 3].Value = rule.FileSystemRights.ToString();
                        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 4].Value = rule.IsInherited;

                        explicitGroupPermissionsSheetRowCounter++;

                    }

                    explicitPermissionGroups.Add(identity);

                }

                string rights = rule.FileSystemRights.ToString();

                bool isInherited = rule.IsInherited;

                numberOfPermissions++;

                // write to csv file
                string outputString = $"\"{folderPath}\";{identity};{rights};{isInherited}";
                File.AppendAllText(outfilePath, outputString + Environment.NewLine);

                // write to excel sheet
                currentSheet.Cells[currentSheetRowCounter, 1].Value = folderPath;
                currentSheet.Cells[currentSheetRowCounter, 2].Value = identity;
                currentSheet.Cells[currentSheetRowCounter, 3].Value = rights;
                currentSheet.Cells[currentSheetRowCounter, 4].Value = rule.IsInherited;

                // check rule inheritance
                // todo column 5 == foreign members if any
                // 08.04.2025: changed to column 6
                string show_inheritance = (string)ReadConfig("/config/general/show_inheritance");
                if (rule.IsInherited && show_inheritance == "true")
                {
                    string inheritedFrom = FindRootOfInheritance(folderPath, rule);
                    currentSheet.Cells[currentSheetRowCounter, 6].Value = inheritedFrom;
                }

                string show_detailed_rights = (string)ReadConfig("/config/general/show_detailed_rights");
                if (show_detailed_rights == "true")
                {
                    List<string> detailedRightsList = GetDetailedRights(rule.FileSystemRights);
                    string detailedRights = string.Join(", ", detailedRightsList.Distinct());
                    currentSheet.Cells[currentSheetRowCounter, 7].Value = detailedRights;
                }

                currentSheetRowCounter++;

                // Max rows per sheet is 1.048.576 (2^20)
                if (currentSheetRowCounter > 1000000)
                {

                    currentSheetCounter++;

                    currentSheetRowCounter = 1;
                    currentSheet = excelPackage.Workbook.Worksheets.Add($"Alle Berechtigungen {currentSheetCounter}");
                    currentSheet.Cells[currentSheetRowCounter, 1].Value = "FolderPath";
                    currentSheet.Cells[currentSheetRowCounter, 2].Value = "IdentityReference";
                    currentSheet.Cells[currentSheetRowCounter, 3].Value = "Berechtigung";
                    currentSheet.Cells[currentSheetRowCounter, 4].Value = "Berechtigung vererbt";
                    if (shareManager != String.Empty)
                        currentSheet.Cells[currentSheetRowCounter, 5].Value = "beinhaltet bereichsfremde Mitglieder";
                    currentSheet.View.FreezePanes(2, 1);

                    currentSheetRowCounter++;

                    currentSheet.Column(1).Width = 50;
                    currentSheet.Column(2).Width = 50;
                    currentSheet.Column(3).Width = 50;
                    currentSheet.Column(4).Width = 25;
                    if (shareManager != String.Empty)
                        currentSheet.Column(5).Width = 25;

                }

            }

        }
        catch (UnauthorizedAccessException ex)
        {

            WriteCustomEventLog($"Der Zugriff auf\n\n\"{folderPath}\"\n\nwurde verweigert:\n\n{ex.Message}", EventLogEntryType.Error, 1, 1);

        }
        catch (Exception ex)
        {

            WriteCustomEventLog($"Ein Fehler beim Zugriff auf\n\n\"{folderPath}\"\n\nist aufgetreten:\n\n{ex.Message}", EventLogEntryType.Error, 1, 1);

        }

    }

    #endregion

    #region Helper Methods

    static string ConvertToApplyTo(InheritanceFlags inheritance, PropagationFlags propagation)
    {
        if (inheritance == InheritanceFlags.None)
            return "Nur dieser Ordner";

        if (inheritance == InheritanceFlags.ContainerInherit && propagation == PropagationFlags.None)
            return "Dieser Ordner und Unterordner";

        if (inheritance == InheritanceFlags.ContainerInherit && propagation == PropagationFlags.InheritOnly)
            return "Nur Unterordner";

        if (inheritance == InheritanceFlags.ObjectInherit && propagation == PropagationFlags.None)
            return "Dieser Ordner und Dateien";

        if (inheritance == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit))
            return "Dieser Ordner, Unterordner und Dateien";

        return "Unbekannt";
    }

    static string FindRootOfInheritance(string folderPath, FileSystemAccessRule inheritedRule)
    {
        DirectoryInfo parent = Directory.GetParent(folderPath);
        string lastFoundAt = "Unbekannt";

        while (parent != null)
        {
            DirectorySecurity parentSecurity = parent.GetAccessControl();
            AuthorizationRuleCollection parentAcl = parentSecurity.GetAccessRules(true, true, typeof(NTAccount));

            bool ruleExists = false;
            foreach (FileSystemAccessRule parentRule in parentAcl)
            {
                if (RulesMatch(inheritedRule, parentRule))
                {
                    ruleExists = true;
                    lastFoundAt = parent.FullName;
                    break;
                }
            }

            // Wenn die Regel hier nicht mehr existiert, dann war der letzte gefundene Ordner der Ursprung
            if (!ruleExists)
            {
                return lastFoundAt;
            }

            parent = Directory.GetParent(parent.FullName);
        }

        return lastFoundAt;
    }

    static bool RulesMatch(FileSystemAccessRule inheritedRule, FileSystemAccessRule parentRule)
    {
        return inheritedRule.IdentityReference == parentRule.IdentityReference &&
               inheritedRule.FileSystemRights == parentRule.FileSystemRights &&
               inheritedRule.AccessControlType == parentRule.AccessControlType &&
               inheritedRule.InheritanceFlags == parentRule.InheritanceFlags &&
               inheritedRule.PropagationFlags == parentRule.PropagationFlags;
    }


    /// <summary>
    /// Read extended ntfs rights
    /// </summary>
    /// <param name="rights"></param>
    /// <returns></returns>
    private static List<string> GetDetailedRights(FileSystemRights rights)
    {
        List<string> detailedRights = new List<string>();

        foreach (FileSystemRights value in Enum.GetValues(typeof(FileSystemRights)))
        {
            if (value == 0) continue; // Ignore 'None'
            if (rights.HasFlag(value))
            {
                detailedRights.Add(value.ToString());
            }
        }

        return detailedRights;
    }

    /// <summary>
    /// Free temporary Lists to free memory
    /// \deprecated PermissionSheet got split so this is not needed anymore
    /// </summary>
    static void ReleaseMemory()
    {

        recursiveGroupsToResolve = null;

        userList = null;

        groupList = null;

        ignoredAccountsList = null;

        ignoredNames = null;

        ignoredNamesWildcard = null;

        explicitPermissionUsers = null;

        explicitPermissionGroups = null;

        explicitPermissionFoldersUsers = null;

        explicitPermissionFoldersGroups = null;

        explicitPermissionFoldersUsersInherited = null;

        explicitPermissionFoldersGroupsInherited = null;

        GC.Collect();
        GC.WaitForPendingFinalizers();

    }

    /// <summary>
    /// Write an eventlog. Requires administrative rights
    /// </summary>
    /// <param name="eventLogEntryType"></param>
    /// <param name="eventID"></param>
    /// <param name="taskID"></param>
    /// <param name="tempEventSourceName"></param>
    static void WriteCustomEventLog(string message, EventLogEntryType eventLogEntryType = EventLogEntryType.Information, int eventID = 1, short taskID = 1, string tempEventSourceName = "")
    {

        string logName = "Berechtigungsaudit";
        string eventSourceName = sharename;

        if (tempEventSourceName != "")
        {
            eventSourceName = tempEventSourceName;
        }

        try
        {

            if (!EventLog.SourceExists(eventSourceName))
            {

                EventSourceCreationData sourceData = new EventSourceCreationData(eventSourceName, logName);
                EventLog.CreateEventSource(sourceData);

            }

            using (EventLog eventLog = new EventLog(logName, Environment.MachineName, eventSourceName))
            {

                eventLog.WriteEntry(message, eventLogEntryType, eventID, taskID);

            }

        }
        catch (Exception ex)
        {

            Console.WriteLine("[warning] Konnte nicht in den EventLog schreiben, bitte das Programm mit ausreichenden administrativen Berechtigungen ausführen: " + ex.Message);
            //throw ex;

        }

    }

    /// <summary>
    /// Read config from config.xml should be placed beside the executable
    /// </summary>
    static object ReadConfig(string elem)
    {
        string configFile = System.AppDomain.CurrentDomain.BaseDirectory + "config.xml";

        if (!File.Exists(configFile))
        {
            WriteCustomEventLog($"Fehler beim Lesen der Konfigurationsdatei \"{configFile}\". Die Datei konnte nicht gefunden werden.", EventLogEntryType.Error, 1, 1);
            //Console.WriteLine($"Fehler beim Lesen der Konfigurationsdatei \"{configFile}\". Die Datei konnte nicht gefunden werden.");
            Environment.FailFast("Die Konfigurationsdatei fehlt. Beende das Programm sofort.");  //Environment.Exit(1);
        }

        XmlDocument doc = new XmlDocument();
        doc.Load(configFile);
        XmlNode node = doc.DocumentElement.SelectSingleNode(elem);
        if (node != null)
        {
            string text = node.InnerText;
            return text;
        }

        WriteCustomEventLog($"Fehler beim Lesen des Attributs \"{elem}\" aus der Konfigurationsdatei. Ziel war null.", EventLogEntryType.Error, 1, 1);

        return null;
    }

    /// <summary>
    /// Read a list from config.xml
    /// </summary>
    /// <param name="elem"></param>
    /// <returns></returns>
    static List<string> ReadConfigList(string elem)
    {
        string configFile = System.AppDomain.CurrentDomain.BaseDirectory + "config.xml";

        if (!File.Exists(configFile))
        {
            WriteCustomEventLog($"Fehler beim Lesen der Konfigurationsdatei \"{configFile}\".", EventLogEntryType.Error, 1, 1);
            //Console.WriteLine($"Fehler beim Lesen der Konfigurationsdatei \"{configFile}\"");
            Environment.FailFast("Die Konfigurationsdatei fehlt. Beende das Programm sofort.");  //Environment.Exit(1);
        }

        XmlDocument doc = new XmlDocument();
        doc.Load(configFile);

        // Liste für die Benutzernamen
        List<string> userList = new List<string>();

        // Wähle die entsprechenden Knoten
        XmlNodeList nodeList = doc.DocumentElement.SelectNodes(elem);

        if (nodeList != null)
        {
            foreach (XmlNode node in nodeList)
            {
                userList.Add(node.InnerText);
            }

            return userList;
        }

        WriteCustomEventLog($"Fehler beim Lesen des Attributs \"{elem}\" aus der Konfigurationsdatei.", EventLogEntryType.Error, 1, 1);

        return null;
    }

    /// <summary>
    /// Create a list of users from active directory to compare.
    /// \todo extensionAttribute10
    /// </summary>
    static void CreateUserList()
    {

        Console.Write("[info] Generiere Liste der AD-User.. ");
        string ldapPath = "LDAP://DC=" + domainName + ",DC=" + domainExtension;

        try
        {

            userList = new List<string>();

            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(ldapPath);
            DirectorySearcher searcher = new DirectorySearcher(entry);

            //searcher.Filter = "(|(objectClass=user)(objectClass=group))";
            searcher.Filter = "(&(objectClass=user)(objectCategory=person))"; // user + person, some implementations add computers as users
            searcher.PageSize = 100000;
            searcher.PropertiesToLoad.Add("sAMAccountName");
            searcher.PropertiesToLoad.Add("extensionAttribute10");

            foreach (SearchResult result in searcher.FindAll())
            {

                System.DirectoryServices.DirectoryEntry userEntry = result.GetDirectoryEntry();

                if (userEntry.Properties.Contains("sAMAccountName"))
                {

                    string samAccountName = userEntry.Properties["sAMAccountName"].Value?.ToString();
                    string extensionAttribute10 = null;
                    // \todo
                    if (userEntry.Properties.Contains("extensionAttribute10"))
                    {

                        extensionAttribute10 = userEntry.Properties["extensionAttribute10"].Value?.ToString();
                        if (null != extensionAttribute10 && extensionAttribute10 != "User")
                        {
                            continue;
                        }

                    }

                    string n = domainName + "\\" + samAccountName.Trim();
                    userList.Add(n);

                }

            }

        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception: {ex.Message}");

            WriteCustomEventLog($"Fehler beim Erstellen der Liste der AD-User. {ex.Message}", EventLogEntryType.Error, 1, 1);
            Environment.Exit(1);

        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(userList.Count() + " User gefunden. OK!");
        Console.ResetColor();

    }

    /// <summary>
    /// Create a list of groups from active directory to compare
    /// </summary>
    static void CreateGroupList()
    {

        Console.Write("[info] Generiere Liste der AD-Gruppen.. ");
        string ldapPath = "LDAP://DC=" + domainName + ",DC=" + domainExtension;

        try
        {

            groupList = new List<string>();
            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(ldapPath);
            DirectorySearcher searcher = new DirectorySearcher(entry);

            searcher.Filter = "(&(objectClass=group))";
            searcher.PageSize = 100000; // Optional
            searcher.PropertiesToLoad.Add("sAMAccountName");

            foreach (SearchResult result in searcher.FindAll())
            {

                System.DirectoryServices.DirectoryEntry userEntry = result.GetDirectoryEntry();
                if (userEntry.Properties.Contains("sAMAccountName"))
                {

                    string samAccountName = userEntry.Properties["sAMAccountName"].Value?.ToString();
                    string n = domainName + "\\" + samAccountName.Trim();
                    groupList.Add(n);

                }

            }

        }
        catch (Exception ex)
        {

            Console.WriteLine($"Exception: {ex.Message}");
            WriteCustomEventLog($"Fehler beim Erstellen der Liste der AD-Gruppen. {ex.Message}", EventLogEntryType.Error, 1, 1);
            Environment.Exit(1);

        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(groupList.Count() + " Gruppen gefunden. OK!");
        Console.ResetColor();

    }

    /// <summary>
    /// List all groups and their members in a separate sheet we can link to.
    /// If a member is a group by itself, the row get marked as "group" so we know we have to resolve it.
    /// </summary>
    static void GenerateGroupMember()
    {

        // set column width
        groupMemberSheet.Column(1).Width = 50;
        groupMemberSheet.Column(2).Width = 50;

        // int rowIndex = 1;
        // changed to groupMemberSheetRowCounter

        foreach (string group in explicitPermissionGroups.Distinct())
        {

            groupMemberSheet.Cells[groupMemberSheetRowCounter, 1, groupMemberSheetRowCounter, 2].Merge = true;
            groupMemberSheet.Cells[groupMemberSheetRowCounter, 1].Value = group;
            groupMemberSheet.Cells[groupMemberSheetRowCounter, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
            groupMemberSheet.Cells[groupMemberSheetRowCounter, 1].Style.Fill.BackgroundColor.SetColor(Color.LightBlue);
            groupMemberSheetRowCounter++;

            List<string> members = GetGroupMembers(group);

            foreach (string member in members)
            {

                groupMemberSheet.Cells[groupMemberSheetRowCounter, 1].Value = member;

                if (IsUserAGroup(member))
                {

                    recursiveGroupsToResolve.Add(member);
                    // here we mark the group so we know we have to resolve this name later on
                    groupMemberSheet.Cells[groupMemberSheetRowCounter, 2].Value = "Group";

                }
                else
                {

                    string memberOU = GetMemberOU(member);
                    groupMemberSheet.Cells[groupMemberSheetRowCounter, 2].Value = memberOU;

                    if (!memberOU.StartsWith(shareManagerOU))
                    {

                        groupsWithForeignMembers.Add(group);
                        foreignMembers.Add(member);

                    }
                }

                groupMemberSheetRowCounter++;

            }

            // Empty row between groups
            groupMemberSheetRowCounter++;

        }

    }

    /// <summary>
    /// Check if an account is a user or a group
    /// </summary>
    /// <param name="accountName"></param>
    /// <returns></returns>
    static bool IsUserAGroup(string accountName)
    {
        if (string.IsNullOrWhiteSpace(accountName))
        {
            return false; // Oder ggf. throw new ArgumentException("Account name is invalid.");
        }

        try
        {
            using (PrincipalContext context = new PrincipalContext(ContextType.Domain, domain))
            {
                GroupPrincipal group = GroupPrincipal.FindByIdentity(context, accountName);

                return group != null;
            }
        }
        catch (PrincipalOperationException ex)
        {
            // Console.WriteLine($"Fehler beim Überprüfen der Gruppe: {ex.Message}");
            return false;
        }
        catch (Exception ex)
        {
            // Console.WriteLine($"Allgemeiner Fehler: {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Get the OU of a user.
    /// </summary>
    /// <param name="sAMAccountName"></param>
    /// <returns></returns>
    static string GetMemberOU(string sAMAccountName)
    {

        string ldapPath = "LDAP://" + domain;

        try
        {

            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(ldapPath);
            DirectorySearcher searcher = new DirectorySearcher(entry)
            {
                Filter = $"(sAMAccountName={sAMAccountName})"
            };

            // Suchergebnis
            SearchResult result = searcher.FindOne();

            if (result != null)
            {
                // DN (Distinguished Name) des Benutzers
                string distinguishedName = result.Properties["distinguishedName"][0].ToString();

                // OU extrahieren
                string[] dnParts = distinguishedName.Split(',');
                List<string> ouParts = new List<string>();

                foreach (string part in dnParts)
                {

                    if (part.StartsWith("OU=", StringComparison.OrdinalIgnoreCase))
                    {

                        // "OU=" entfernen
                        string t = part.Substring(3);

                        // skip special OUs
                        // \todo only AKM fileserver
                        if (t.Contains("Microsoft365") || t.Contains("Microsoft-365") || t.Contains("USER"))
                            continue;

                        ouParts.Add(t);

                    }

                }

                ouParts.Reverse();

                // OU-Teile in eine lesbare Form zusammensetzen
                return string.Join("/", ouParts);

            }
            else
            {

                return "Benutzer nicht gefunden.";

            }

        }
        catch (Exception ex)
        {

            Console.WriteLine("Fehler (GetMemberOU): " + ex.Message);
            return "Fehler";

        }

    }

    /// <summary>
    /// This method is currently unused
    /// \deprecated
    /// </summary>
    /// <param name="filter">LDAP Filter for Lookup</param>
    /// <param name="propertyToLookup">The LDAP property we're looking for</param>
    /// <param name="propertiesToLoad">An array of Strings of properties to load by the directorysearcher</param>
    /// <param name="isArray">If the result holds multiple entries, its an array. So this should be set to true</param>
    /// <param name="arrayIndex">The index of the array which property we want</param>
    /// <returns>string</returns>
    static string GetAccountAttribute(string filter, string propertyToLookup, string[] propertiesToLoad = null, bool isArray = false, int arrayIndex = 0)
    {

        string ldapPath = "LDAP://" + domain;

        try
        {

            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(ldapPath);
            System.DirectoryServices.DirectorySearcher searcher = new System.DirectoryServices.DirectorySearcher(entry)
            {
                Filter = $"{filter}"
            };

            foreach (string prop in propertiesToLoad)
            {
                searcher.PropertiesToLoad.Add(prop);
            }

            // Suchergebnis
            SearchResult result = searcher.FindOne();

            string attribute = null;

            if (result != null)
            {

                if (isArray == false)
                {

                    attribute = result.Properties[propertyToLookup][0].ToString();

                }
                else
                {

                    attribute = result.Properties[propertyToLookup][arrayIndex].ToString();

                }

                return attribute;

            }
            else
            {

                return "";

            }

        }
        catch (Exception ex)
        {
            //Console.WriteLine("Fehler: " + ex.Message);
            return "";
        }

    }

    /// <summary>
    /// Add links to groups in group member sheet.
    /// This is called after the excelpackage was written to file, so we read the file from disk!
    /// </summary>
    /// <param name="src"></param>
    /// <param name="srcColumn"></param>
    /// <param name="target"></param>
    /// <param name="targetColumn"></param>
    static void UpdateGroupReferences(string src, int srcColumn, string target, int targetColumn)
    {

        string filePath = excelfilePath;
        FileInfo file = new FileInfo(filePath);

        using (var package = new ExcelPackage(file))
        {

            var srcWorksheet = package.Workbook.Worksheets[src];
            var targetWorksheet = package.Workbook.Worksheets[target];

            // 1st row is the header
            int row = 2;

            while (row <= srcWorksheet.Dimension.End.Row)
            {

                try
                {

                    string groupName = srcWorksheet.Cells[row, srcColumn].Value.ToString();

                    // Find the row with the group name in group members Sheet
                    for (int groupRow = 1; groupRow <= targetWorksheet.Dimension.End.Row; groupRow++)
                    {

                        if (targetWorksheet.Cells[groupRow, targetColumn].Value != null && targetWorksheet.Cells[groupRow, targetColumn].Value.ToString() == groupName)
                        {

                            string cellReference = $"=HYPERLINK(\"#'{target}'!A{groupRow}\",\"{groupName}\")";
                            srcWorksheet.Cells[row, srcColumn].Formula = cellReference;
                            srcWorksheet.Cells[row, srcColumn].Style.Font.Color.SetColor(System.Drawing.Color.Blue);
                            break;

                        }

                    }

                }

                catch (NullReferenceException nre) { }

                row++;

            }

            package.Save();

        }

    }

    /// <summary>
    /// Get all the members of a group.
    /// Domain users are resolved using GetDomainUsers().
    /// \todo use distinguishedname instead of cn
    /// \todo extensionAttribute10
    /// \todo Special domain users
    /// </summary>
    /// <param name="groupName">The common name of the group</param>
    /// <returns></returns>
    static List<string> GetGroupMembers(string groupName)
    {

        // special method for internal group "domain members"
        if (groupName == domainName + "\\Domänen-Benutzer"
            || groupName == domainName + "\\Domain-Users"
            || groupName == domainName + "\\Domain Users")
        {

            return GetDomainUsers();

        }

        List<string> membersList = new List<string>();

        try
        {

            string ldapPath = "LDAP://DC=" + domainName + ",DC=" + domainExtension;

            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(ldapPath);
            DirectorySearcher searcher = new DirectorySearcher(entry);

            groupName = groupName.Replace(domainName + "\\", "");

            searcher.Filter = $"(&(objectClass=group)(cn={groupName}))";
            searcher.PropertiesToLoad.Add("member");

            SearchResult result = searcher.FindOne();

            if (result != null)
            {

                // Get property member
                var members = result.Properties["member"];

                foreach (var member in members)
                {

                    // add domain to account
                    // "member" is the DN
                    string samAccountName = GetSamAccountName(member.ToString());
                    string samAccountNameToSearch = domainName + "\\" + samAccountName;

                    // Skip ignored identities
                    if (ignoredNames.Contains(samAccountNameToSearch))
                    {

                        continue;

                    }

                    bool doContinue = false;

                    // Check for wildcard ignored patterns
                    foreach (var pattern in ignoredNamesWildcard)
                    {

                        if (Regex.IsMatch(samAccountNameToSearch, pattern))
                        {

                            doContinue = true;
                            break;

                        }

                    }

                    if (doContinue)
                    {

                        continue;

                    }

                    membersList.Add(samAccountName);

                }

            }

        }
        catch (Exception ex)
        {

            Console.WriteLine($"[error] Fehler beim Abrufen der Mitglieder der Gruppe \"{groupName}\": {ex.Message}");

        }

        return membersList;

    }

    /// <summary>
    /// Domain users cannot simply be read. 
    /// We must look for all members having primaryGroupID 513.
    /// \todo extensionAttribute10
    /// </summary>
    /// <returns></returns>
    static List<string> GetDomainUsers()
    {

        Console.WriteLine("[debug] Trying to get domain users");


        List<string> membersList = new List<string>();

        try
        {

            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry("LDAP://DC=" + domainName + ",DC=" + domainExtension);
            DirectorySearcher searcher = new DirectorySearcher(entry);

            // load specific attributes
            // by default only standard attributes get loaded
            searcher.PropertiesToLoad.Add("sAMAccountName");
            searcher.PropertiesToLoad.Add("extensionAttribute10");
            searcher.PropertiesToLoad.Add("userAccountControl");

            // Look for accounts having primaryGroupID = 513 (for "Domänen-Benutzer")
            searcher.Filter = "(&(objectCategory=person)(objectClass=user)(primaryGroupID=513))";

            SearchResultCollection results = searcher.FindAll();

            if (results != null)
            {

                foreach (SearchResult result in results)
                {

                    // skip deactivated accounts
                    int userAccountControl = (int)result.Properties["userAccountControl"][0];

                    if (userAccountControl == 0)
                    {

                        continue;

                    }

                    System.DirectoryServices.DirectoryEntry userEntry = result.GetDirectoryEntry();

                    // skip accounts without extensionAttribute10
                    if (userEntry.Properties["extensionAttribute10"].Value == null || userEntry.Properties["extensionAttribute10"].Value.ToString() != "User")
                    {

                        continue;

                    }

                    // add domain name to account name
                    string samAccountName = userEntry.Properties["sAMAccountName"].Value.ToString();
                    string samAccountNameToSearch = domainName + "\\" + samAccountName;

                    // Skip ignored identities
                    if (ignoredNames.Contains(samAccountNameToSearch))
                    {

                        continue;

                    }

                    bool doContinue = false;

                    // Check for wildcard ignored patterns
                    foreach (var pattern in ignoredNamesWildcard)
                    {

                        if (Regex.IsMatch(samAccountNameToSearch, pattern))
                        {

                            doContinue = true;
                            break;

                        }

                    }

                    if (doContinue)
                    {

                        continue;

                    }

                    membersList.Add(samAccountName);

                }

            }

        }
        catch (Exception ex)
        {

            Console.WriteLine($"[error] Fehler beim Abrufen der Gruppe \"Domänen-Benutzer\": {ex.Message}");

        }

        return membersList;

    }

    /// <summary>
    /// Get the SAMAccountName by distinguishedName
    /// </summary>
    /// <param name="distinguishedName"></param>
    /// <returns></returns>
    static string GetSamAccountName(string distinguishedName)
    {

        try
        {

            using (System.DirectoryServices.DirectoryEntry memberEntry = new System.DirectoryServices.DirectoryEntry($"LDAP://{distinguishedName}"))
            {

                object samAccountNameObj = memberEntry.Properties["sAMAccountName"].Value;
                return samAccountNameObj != null ? samAccountNameObj.ToString() : null;

            }

        }
        catch (Exception ex)
        {

            Console.WriteLine($"[error]Error fetching sAMAccountName for {distinguishedName}: {ex.Message}");
            return null;

        }

    }

    /// <summary>
    /// Resolve nested groups until there are no more unresolved groups
    /// Unresolved groups has the string "group" in the 2nd column
    /// If they got resolved the "group" changes to "resolved" to better be found when adding Hyperlinks
    /// </summary>
    static void ResolveRecursiveGroups()
    {

        Console.WriteLine("[info] Löse verschachtelte Gruppen auf..");

        recursiveGroupsToResolve = new List<string>();

        List<string> recursiveGroupsToResolveTemp = new List<string>();

        // if we have no group permissions at all Sheet.Dimension.End.Row returns a nullreference exception
        if (groupMemberSheet.Dimension == null) { return; }

        // find all marked rows and replace "group" by "resolved"
        for (int i = 1; i <= groupMemberSheet.Dimension.End.Row; i++)
        {

            if (groupMemberSheet.Cells[i, 2].Value != null && groupMemberSheet.Cells[i, 2].Value.ToString() == "Group")
            {

                recursiveGroupsToResolve.Add(groupMemberSheet.Cells[i, 1].Value.ToString());
                groupMemberSheet.Cells[i, 2].Value = "Resolved";

            }

        }

        // if there are no more unresolved groups, return here!
        if (recursiveGroupsToResolve.Count == 0) { return; }

        int lastRow = groupMemberSheet.Dimension.End.Row;

        lastRow += 2;

        foreach (string v in recursiveGroupsToResolve.Distinct())
        {

            // check if its already resolved
            bool shouldContinue = false;

            for (int i = 1; i <= groupMemberSheet.Dimension.End.Row; i++)
            {

                if (groupMemberSheet.Cells[i, 1].Value != null && groupMemberSheet.Cells[i, 1].Value.ToString() == domainName + "\\" + v)
                {

                    shouldContinue = true;

                }

            }

            if (shouldContinue)
                continue;

            groupMemberSheet.Cells[lastRow, 1, lastRow, 2].Merge = true;
            groupMemberSheet.Cells[lastRow, 1].Value = domainName + "\\" + v;
            groupMemberSheet.Cells[lastRow, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
            groupMemberSheet.Cells[lastRow, 1].Style.Fill.BackgroundColor.SetColor(Color.LightBlue);

            lastRow++;

            List<string> tmp = GetGroupMembers(domainName + "\\" + v);

            foreach (string u in tmp)
            {

                groupMemberSheet.Cells[lastRow, 1].Value = u;

                if (IsUserAGroup(u))
                {

                    recursiveGroupsToResolveTemp.Add(u);
                    groupMemberSheet.Cells[lastRow, 2].Value = "Group";

                }
                else
                {

                    string memberOU = GetMemberOU(u);
                    groupMemberSheet.Cells[lastRow, 2].Value = memberOU;

                    if (!memberOU.StartsWith(shareManagerOU))
                    {

                        groupsWithForeignMembers.Add(v);
                        foreignMembers.Add(u);

                    }

                }

                lastRow++;

            }

            lastRow++;

        }

        // update list
        recursiveGroupsToResolve = recursiveGroupsToResolveTemp;

        // recursive call
        ResolveRecursiveGroups();

    }

    /// <summary>
    /// Update all the links for nested groups in the group members sheet
    /// </summary>
    static void UpdateResolvedGroupLinks()
    {

        Console.WriteLine("[info] Löse Links auf verschachtelte Gruppen auf..");

        // if we have no group permissions at all Sheet.Dimension.End.Row returns a nullreference exception
        if (groupMemberSheet.Dimension == null) { return; }

        // find all marked rows
        for (int i = 1; i <= groupMemberSheet.Dimension.End.Row; i++)
        {

            if (groupMemberSheet.Cells[i, 2].Value != null && groupMemberSheet.Cells[i, 2].Value.ToString() == "Resolved")
            {

                string groupName = groupMemberSheet.Cells[i, 1].Value.ToString();

                // find resolved group
                for (int j = 1; j <= groupMemberSheet.Dimension.End.Row; j++)
                {

                    if (groupMemberSheet.Cells[j, 1].Value != null && groupMemberSheet.Cells[j, 1].Value.ToString() == domainName + "\\" + groupName)
                    {

                        // insert hyperlink
                        string cellReference = $"=HYPERLINK(\"#'Gruppenmitglieder'!A{j}\",\"{groupName}\")";
                        groupMemberSheet.Cells[i, 1].Formula = cellReference;
                        groupMemberSheet.Cells[i, 1].Style.Font.Color.SetColor(System.Drawing.Color.Blue);

                    }

                }

                // clear the "resolved" placeholder.
                groupMemberSheet.Cells[i, 2].Value = "";

            }

        }

    }

    /// <summary>
    /// To write an event when Ctrl+C is clicked
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="e"></param>
    static void CancelKeyPressHandler(object sender, ConsoleCancelEventArgs e)
    {

        WriteCustomEventLog("Der Prozess wurde durch den Benutzer durch drücken von \"Ctrl-C\" abgebrochen.", EventLogEntryType.Error, 1, 1);
        //e.Cancel = true; // prevent immediate exit!
        userCancelled = true;

    }

    /// <summary>
    /// To write an event when the process exits unexpectedly
    /// </summary>
    /// <param name="sender"></param>
    /// <param name="e"></param>
    static void ProcessExitHandler(object sender, EventArgs e)
    {

        if (!fullyExecuted)
        {

            if (userCancelled)
            {

                WriteCustomEventLog("Der Prozess wurde vom Benutzer durch drücken von \"Ctrl-C\" abgebrochen.", EventLogEntryType.Error, 1, 1);

            }
            else
            {

                WriteCustomEventLog("Der Prozess wurde unerwartet beendet.", EventLogEntryType.Error, 1, 1);

            }

        }

    }

    #endregion

}
