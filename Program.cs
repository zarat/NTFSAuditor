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
using System.Drawing;
using System.Data;
using System.ComponentModel;
using System.Reflection.PortableExecutable;
using System.Security;
using System.Diagnostics;
using System.Diagnostics.Metrics;

class Program
{

    #region Parameters

    public static bool userCancelled = false;
    public static bool fullyExecuted = false;

    /// <summary>
    /// For percentage display
    /// </summary>
    public static int numberOfFolders, numberOfPermissions = 0;

    /// <summary>
    /// List of AD users generated at start to compare
    /// </summary>
    public static List<string> userList = new List<string>();

    /// <summary>
    /// List of AD groups generated at start to compare
    /// </summary>
    public static List<string> groupList = new List<string>();

    /// <summary>
    /// A list of found(!) accounts that are configured to ignore
    /// users and groups
    /// Are shown in statistics (accounts with explicit permissions)
    /// </summary>
    public static List<string> ignoredAccountsList = new List<string>();

    /// <summary>
    /// Path for output file
    /// </summary>
    public static string outfilePath = String.Empty;

    /// <summary>
    /// Path for log file
    /// </summary>
    public static string logfilePath = String.Empty;

    /// <summary>
    /// Path for excel file
    /// </summary>
    public static string excelfilePath = String.Empty;

    /// <summary>
    /// Read from config.xml to set mode (all or only non-inherited)
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
    static List<string> explicitPermissionUsers = new List<string>();

    /// <summary>
    /// Unique list of groups with explicit permissions
    /// </summary>
    static List<string> explicitPermissionGroups = new List<string>();

    /// <summary>
    /// Unique list of folders with explicit permissions for users
    /// </summary>
    static List<string> explicitPermissionFoldersUsers = new List<string>();

    /// <summary>
    /// Unique list of folders with explicit permissions for groups
    /// </summary>
    static List<string> explicitPermissionFoldersGroups = new List<string>();

    /// <summary>
    /// List of folders with explicit non-inherited permissions for users
    /// </summary>
    static List<string> explicitPermissionFoldersUsersInherited = new List<string>();

    /// <summary>
    /// List of folders with explicit non-inherited permissions for groups
    /// </summary>
    static List<string> explicitPermissionFoldersGroupsInherited = new List<string>();

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
    public static int sheet4RowCounter = 1; // 1st row is header

    /// <summary>
    /// Explicit User Permissions Sheet
    /// </summary>
    public static ExcelWorksheet explicitUserPermissionsSheet; // = excelPackage.Workbook.Worksheets.Add("Explicit User Permissions");
    public static int groupMemberSheetRowCounter = 1; // 1st row is header

    /// <summary>
    /// Explicit Group Permissions Sheet
    /// </summary>
    public static ExcelWorksheet explicitGroupPermissionsSheet; // = excelPackage.Workbook.Worksheets.Add("Explicit Group Permissions");
    public static int explicitGroupPermissionsSheetRowCounter = 1; // 1st row is header

    /// <summary>
    /// Auto numbered Permissions Sheet
    /// </summary>
    public static ExcelWorksheet currentSheet;
    public static int currentSheetCounter = 1;
    public static int currentSheetRowCounter = 1;

    /// <summary>
    /// \todo Resolve nested groups recursive
    /// </summary>
    static List<string> recursiveGroupsToResolve = new List<string>();

    static string sharename = "Fehler";

    #endregion

    #region Methods

    /// <summary>
    /// Free temporary Lists to free memory
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
    /// Write an eventlog
    /// </summary>
    /// <param name="message"></param>
    /// <param name="eventLogEntryType"></param>
    /// <param name="eventID"></param>
    /// <param name="taskID"></param>
    public static void WriteCustomEventLog(string message, EventLogEntryType eventLogEntryType = EventLogEntryType.Information, int eventID = 1, short taskID = 1, string tempEventSourceName = "")
    {

        string logName = "Berechtigungsaudit";
        string eventSourceName = sharename; // "NTFSAudit";

        if (tempEventSourceName != "")
        {
            eventSourceName = tempEventSourceName;
        }

        try
        {
            // Überprüfen, ob das EventLog schon existiert
            if (!EventLog.SourceExists(eventSourceName))
            {
                // EventLog und Quelle erstellen
                EventSourceCreationData sourceData = new EventSourceCreationData(eventSourceName, logName);
                EventLog.CreateEventSource(sourceData);
            }

            // Mit dem EventLog verbinden und Einträge schreiben
            using (EventLog eventLog = new EventLog(logName, Environment.MachineName, eventSourceName))
            {
                // Einen Eintrag in das EventLog schreiben
                eventLog.WriteEntry(message, eventLogEntryType, eventID, taskID);

                //Console.WriteLine("Eintrag wurde ins EventLog geschrieben.");
            }

        } catch(Exception ex) {

            Console.WriteLine("[error] Konnte nicht in den EventLog schreiben, bitte das Programm mit ausreichenden administrativen Berechtigungen ausführen: " + ex.Message);
            //throw ex;
        
        }

    }

    /// <summary>
    /// Main function
    /// </summary>
    /// <param name="args"></param>
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

        ExcelPackage.LicenseContext = OfficeOpenXml.LicenseContext.NonCommercial;

        excelPackage = new ExcelPackage();

        overviewSheet = excelPackage.Workbook.Worksheets.Add("Overview");
        explicitUserPermissionsSheet = excelPackage.Workbook.Worksheets.Add("Explicit User Permissions");
        explicitGroupPermissionsSheet = excelPackage.Workbook.Worksheets.Add("Explicit Group Permissions");
        groupMemberSheet = excelPackage.Workbook.Worksheets.Add("Group Member");
        currentSheet = excelPackage.Workbook.Worksheets.Add("All Permissions " + currentSheetCounter);

        Console.WriteLine("\n\tNTFSAuditor\n\t(C) 2024 - AKM AustroMechana\n");

        if (args.Length == 0)
        {
            Console.WriteLine($"\tUsage: {Assembly.GetExecutingAssembly().GetName().Name}.exe <Sharename>\n");
            Environment.Exit(1);
            //return 1;
        }

        sharename = args[0];

        WriteCustomEventLog($"Berechtigungsaudit für \"{sharename}\" hat begonnen.", EventLogEntryType.Information, 1, 1);

        string year = DateTime.Now.ToString("yyyy");
        string outdir = $@"C:\Scripts\Berechtigungsaudit\Shares\{year}";
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
        excelfilePath = outfilePath.Replace("csv", "xlsx");

        overviewSheet.Cells[overviewSheetRowCounter++, 1].Value = "Bericht generiert am " + DateTime.Now.ToString("dd.MM.yyyy") + " um " + DateTime.Now.ToString("HH:mm");
        overviewSheet.Cells[overviewSheetRowCounter++, 1].Value = "Netzwerkfreigabe: " + sharename;
        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.WrapText = true;
        overviewSheet.Cells[overviewSheetRowCounter, 1].Value = "Achtung: Bitte aktivieren Sie die Bearbeitung damit Verlinkungen korrekt dargestellt werden.";
        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.BackgroundColor.SetColor(Color.Yellow);
        overviewSheetRowCounter++;
        overviewSheet.Column(1).Width = 100;

        explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 1].Value = "FolderPath";
        explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 2].Value = "IdentityReference";
        explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 3].Value = "FileSystemRights";
        explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 4].Value = "IsInherited";
        groupMemberSheetRowCounter++;

        // set column width
        explicitUserPermissionsSheet.Column(1).Width = 50;
        explicitUserPermissionsSheet.Column(2).Width = 50;
        explicitUserPermissionsSheet.Column(3).Width = 50;
        explicitUserPermissionsSheet.Column(4).Width = 50;

        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 1].Value = "FolderPath";
        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 2].Value = "IdentityReference";
        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 3].Value = "FileSystemRights";
        explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 4].Value = "IsInherited";
        explicitGroupPermissionsSheetRowCounter++;

        // set column width
        explicitGroupPermissionsSheet.Column(1).Width = 50;
        explicitGroupPermissionsSheet.Column(2).Width = 50;
        explicitGroupPermissionsSheet.Column(3).Width = 50;
        explicitGroupPermissionsSheet.Column(4).Width = 50;

        currentSheet.Cells[currentSheetRowCounter, 1].Value = "FolderPath";
        currentSheet.Cells[currentSheetRowCounter, 2].Value = "IdentityReference";
        currentSheet.Cells[currentSheetRowCounter, 3].Value = "FileSystemRights";
        currentSheet.Cells[currentSheetRowCounter, 4].Value = "IsInherited";
        currentSheetRowCounter++;

        // set column width
        currentSheet.Column(1).Width = 50;
        currentSheet.Column(2).Width = 50;
        currentSheet.Column(3).Width = 50;
        currentSheet.Column(4).Width = 50;

        /*
         * Create lists of users and groups for comparision
         */
        CreateUserList();
        CreateGroupList();

        /*
         * Delete existing files
         */
        if (File.Exists(outfilePath)) { File.Delete(outfilePath); }

        string outputString = "FolderPath;IdentityReference;FileSystemRights;IsInherited";
        File.AppendAllText(outfilePath, outputString + Environment.NewLine);

        DateTime startDate = DateTime.Now;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Starting at \"{startDate}\"");
        Console.ResetColor();

        /*
         * Connect to fileserver
         */
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
        

            /*
             * Find all shares
             */
            string query1 = "SELECT Name, Path FROM Win32_Share";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query1));
            Console.Write("[info] Ermittle verfügbare Shares.. ");
            ManagementObjectCollection results = searcher.Get();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("OK!");
            Console.ResetColor();

            /*
             * Find the corresponding share
             */
            //var foundShare = results.Cast<ManagementObject>().FirstOrDefault(s => s["Name"].ToString() == sharename);
            var foundShare = results.Cast<ManagementObject>().FirstOrDefault(s => s["Name"].ToString().ToLower() == "\\\\fileserver\\" + sharename.ToLower());

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

                    int foundSMBPermissions = 0;

                    try
                    {

                        DirectoryInfo dirInfo = new DirectoryInfo(share["Name"].ToString());
                        DirectorySecurity dirSecurity = dirInfo.GetAccessControl();
                        AuthorizationRuleCollection rules = dirSecurity.GetAccessRules(true, true, typeof(NTAccount));

                        overviewSheetRowCounter++;
                        overviewSheet.Cells[overviewSheetRowCounter, 1].Value = "Share Berechtigungen:";
                        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
                        overviewSheet.Cells[overviewSheetRowCounter, 1].Style.Fill.BackgroundColor.SetColor(Color.LightBlue);
                        overviewSheetRowCounter++;

                        foreach (FileSystemAccessRule rule in rules)
                        {
                            //Console.WriteLine($"\t{rule.IdentityReference.Value}: {rule.AccessControlType}, {rule.FileSystemRights}");

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

                            //overviewSheet.Cells[overviewSheetRowCounter, 1].Value = $"{rule.IdentityReference.Value}: {rule.AccessControlType}, {rule.FileSystemRights}";
                            overviewSheet.Cells[overviewSheetRowCounter, 1].Value = $"{rule.IdentityReference.Value}";
                            overviewSheet.Cells[overviewSheetRowCounter, 2].Value = $"{rule.FileSystemRights}";
                            overviewSheetRowCounter++;

                            foundSMBPermissions++;

                        }
                    }
                    catch (UnauthorizedAccessException ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[error] Zugriff verweigert: {ex.Message}");
                        Console.ResetColor();

                        WriteCustomEventLog($"Zugriff auf SMB Berechtigungen für \"{found_shareName}\" verweigert.\n{ex.Message}", EventLogEntryType.Error, 1, 1);
                    }
                    catch (Exception ex)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine($"[error] Fehler: {ex.Message}");
                        Console.ResetColor();

                        WriteCustomEventLog($"Fehler beim Zugriff auf SMB Berechtigungen für \"{found_shareName}\".\n{ex.Message}", EventLogEntryType.Error, 1, 1);
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
                    ProcessDirectory(found_shareName, outfilePath);
                }
                catch (UnauthorizedAccessException ex)
                {
                    //Console.WriteLine($"[warning] Test1: {ex}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[warning] Test2: {ex}");
                }

            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"[error] Share \"{sharename}\" konnte nicht gefunden werden.");
                Console.ResetColor();

                WriteCustomEventLog($"Share \"{sharename}\" konnte nicht gefunden werden. Audit wird beendet.", EventLogEntryType.Error, 1, 1);
                return 1;
            }

        }
        catch (Exception ex)
        {
            WriteCustomEventLog($"Zugriff auf {remoteComputer} wurde verweigert", EventLogEntryType.Error, 1, 1, "WMI Fehler");
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

        //FileInfo fileInfo = new FileInfo(outdir + "\\" + outfile);
        //long fileSizeInBytes = fileInfo.Length;
        //double fileSizeInKB = fileSizeInBytes / 1024.0;
        double fileSizeInKB = new FileInfo(outfilePath).Length / 1024.0;
        //double logfileSizeInKB = new FileInfo(logfilePath).Length / 1024.0;


        // ToDo
        //ResolveRecursiveGroups();

        FileInfo fi = new FileInfo(excelfilePath);
        excelPackage.SaveAs(fi);

        Console.Write($"[info] Excel Mappe wird aufbereitet.. ");

        // todo release memory?
        ReleaseMemory();

        //UpdateGroupReferences("All Permissions", 2, "Group Member", 1);
        for(int i = 1; i <= currentSheetCounter; i++)
        {
            UpdateGroupReferences("All Permissions " + i, 2, "Group Member", 1);
        }
        UpdateGroupReferences("Explicit Group Permissions", 2, "Group Member", 1);
        UpdateGroupReferences("Overview", 1, "Group Member", 1);

        // resolve nested groups
        //ResolveRecursiveGroups();

        double excelFileSizeInKB = new FileInfo(excelfilePath).Length / 1024.0;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("OK!");
        Console.ResetColor();


        /*
         * Send email
         */
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
            
            //if (logfileSizeInKB < maxattachmentsize)
            if(excelFileSizeInKB < maxattachmentsize)
            {
                Attachment attachment = new Attachment(excelfilePath); // Excel Datei anhängen
                mail.Attachments.Add(attachment);
                mail.Body += $"\n\nIm Anhang finden Sie den Bericht im Excel Format.";
            }
            else
            {
                mail.Body += $"\n\nDie Excel Datei ist zu groß um an die Mail angehängt zu werden ({excelFileSizeInKB:F2} KB) und ist ebenfalls unter \"{outdir}\" abgelegt.";
            }

            //File.AppendAllText(logfilePath, mail.Body);

            // SMTP Client erstellen
            string relay = "relay.akm.at";
            string relay_tmp = (string)ReadConfig("/config/email/relay");
            if (relay_tmp != null && relay_tmp != "")
            {
                relay = relay_tmp;
            }
            SmtpClient smtpClient = new SmtpClient(relay);
            smtpClient.UseDefaultCredentials = true; // Verwenden der Standardanmeldeinformationen

            // E-Mail senden
            smtpClient.Send(mail);
            Console.WriteLine($"[info] E-Mail wurde erfolgreich an \"{sendto}\" gesendet.");

            WriteCustomEventLog($"Email wurde erfolgreich an \"{sendto}\" gesendet.", EventLogEntryType.Information, 1, 1);

        }
        catch (Exception ex)
        {
            Console.WriteLine($"[error] Fehler beim Senden der E-Mail: " + ex.Message);

            WriteCustomEventLog($"Email wurde nicht versendet.", EventLogEntryType.Error, 1, 1);
        }

        /*
        // ToDo
        ResolveRecursiveGroups();
        */

        fullyExecuted = true;
        WriteCustomEventLog($"Berechtigungsaudit für \"{sharename}\" wurde beendet.", EventLogEntryType.Information, 1, 1);

        return 0;

    }

    /// <summary>
    /// Helper function to collect directories while some paths are non-accessible
    /// </summary>
    /// <param name="folderPath"></param>
    /// <param name="allDirectories"></param>
    static void GetDirectories(string folderPath, List<string> allDirectories)
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
    /// Find all folders in a Share and find the ACLs
    /// </summary>
    /// <param name="folderPath"></param>
    /// <param name="outfilePath"></param>
    static void ProcessDirectory(string folderPath, string outfilePath)
    {
        Console.WriteLine("[info] Analysiere Verzeichnisstruktur..");

        List<string> allDirectories = new List<string>();

        try
        {
            // Starte das rekursive Durchsuchen der Verzeichnisse
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

        /*
         * Main Loop
         */
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
            //Console.SetCursorPosition(0, Console.CursorTop);
            i++;
        }
        //Console.WriteLine("\n");
        //Console.WriteLine("Done");

    }

    /// <summary>
    /// Get the ACLs of a specific folder
    /// </summary>
    /// <param name="folderPath"></param>
    /// <param name="outfilePath"></param>
    static void ProcessFolder(string folderPath, string outfilePath)
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

                // Check for user/group specific permissions
                if (userList.Contains(identity))
                {
                    if (rule.IsInherited)
                    {
                        explicitPermissionFoldersUsersInherited.Add("\"" + folderPath + "\"");
                    }
                    else
                    {
                        explicitPermissionFoldersUsers.Add("\"" + folderPath + "\"");

                        if (1 == 1)
                        {
                            string outputString_user = $"\"{folderPath}\";{identity};{rule.FileSystemRights.ToString()};{rule.IsInherited}";
                            File.AppendAllText(outfilePath, outputString_user + Environment.NewLine);
                            explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 1].Value = folderPath;
                            explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 2].Value = identity;
                            explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 3].Value = rule.FileSystemRights.ToString();
                            explicitUserPermissionsSheet.Cells[groupMemberSheetRowCounter, 4].Value = rule.IsInherited;
                            groupMemberSheetRowCounter++;
                        }

                    }
                    explicitPermissionUsers.Add(identity);
                }

                if (groupList.Contains(identity))
                {
                    if (rule.IsInherited)
                    {
                        explicitPermissionFoldersGroupsInherited.Add("\"" + folderPath + "\"");
                    }
                    else
                    {
                        explicitPermissionFoldersGroups.Add("\"" + folderPath + "\"");

                        if (1 == 1)
                        {
                            string outputString_group = $"\"{folderPath}\";{identity};{rule.FileSystemRights.ToString()};{rule.IsInherited}";
                            File.AppendAllText(outfilePath, outputString_group + Environment.NewLine);
                            explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 1].Value = folderPath;
                            explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 2].Value = identity;
                            explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 3].Value = rule.FileSystemRights.ToString();
                            explicitGroupPermissionsSheet.Cells[explicitGroupPermissionsSheetRowCounter, 4].Value = rule.IsInherited;
                            explicitGroupPermissionsSheetRowCounter++;
                        }

                    }
                    explicitPermissionGroups.Add(identity);
                }

                // Output permissions information
                string rights = rule.FileSystemRights.ToString();
                bool isInherited = rule.IsInherited;
                numberOfPermissions++;

                if (0 == 0)
                {
                    /*
                    string outputString = $"\"{folderPath}\";{identity};{rights};{isInherited}";
                    File.AppendAllText(outfilePath, outputString + Environment.NewLine);
                    sheet3.Cells[sheet3RowCounter, 1].Value = folderPath;
                    sheet3.Cells[sheet3RowCounter, 2].Value = identity;
                    sheet3.Cells[sheet3RowCounter, 3].Value = rule.FileSystemRights.ToString();
                    sheet3.Cells[sheet3RowCounter, 4].Value = rule.IsInherited;
                    sheet3RowCounter++;
                    */

                    string outputString = $"\"{folderPath}\";{identity};{rights};{isInherited}";
                    File.AppendAllText(outfilePath, outputString + Environment.NewLine);
                    currentSheet.Cells[currentSheetRowCounter, 1].Value = folderPath;
                    currentSheet.Cells[currentSheetRowCounter, 2].Value = identity;
                    currentSheet.Cells[currentSheetRowCounter, 3].Value = rule.FileSystemRights.ToString();
                    currentSheet.Cells[currentSheetRowCounter, 4].Value = rule.IsInherited;
                    currentSheetRowCounter++;

                    if (currentSheetRowCounter > 1000000)
                    {
                        currentSheetCounter++;
                        currentSheetRowCounter = 1;
                        currentSheet = excelPackage.Workbook.Worksheets.Add($"All Permissions {currentSheetCounter}");
                        currentSheet.Cells[currentSheetRowCounter, 1].Value = "FolderPath";
                        currentSheet.Cells[currentSheetRowCounter, 2].Value = "IdentityReference";
                        currentSheet.Cells[currentSheetRowCounter, 3].Value = "FileSystemRights";
                        currentSheet.Cells[currentSheetRowCounter, 4].Value = "IsInherited";
                        currentSheetRowCounter++; // Zurücksetzen des Zählers für das neue Arbeitsblatt

                        currentSheet.Column(1).Width = 50;
                        currentSheet.Column(2).Width = 50;
                        currentSheet.Column(3).Width = 50;
                        currentSheet.Column(4).Width = 50;
                    }

                }
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            //throw ex;
            //Console.WriteLine($"[warning] Access denied when processing directory {folderPath}: {ex.Message}");
            // ToDo
            WriteCustomEventLog($"Der Zugriff auf\n\n\"{folderPath}\"\n\nwurde verweigert:\n\n{ex.Message}", EventLogEntryType.Error, 1, 1);
        }
        catch (Exception ex)
        {
            // Interferes with percentage display
            //Console.WriteLine($"[error] An error occurred when processing directory {folderPath}: {ex.Message}");
            WriteCustomEventLog($"Ein Fehler beim Zugriff auf\n\n\"{folderPath}\"\n\nist aufgetreten:\n\n{ex.Message}", EventLogEntryType.Error, 1, 1);
        }
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Read config from config.xml should be placed beside the executable
    /// </summary>
    static object ReadConfig(string elem)
    {
        string configFile = System.AppDomain.CurrentDomain.BaseDirectory + "config.xml";

        if(!File.Exists(configFile))
        {
            WriteCustomEventLog($"Fehler beim Lesen der Konfigurationsdatei \"{configFile}\".", EventLogEntryType.Error, 1, 1);
            //Console.WriteLine($"Fehler beim Lesen der Konfigurationsdatei \"{configFile}\"");
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

        WriteCustomEventLog($"Fehler beim Lesen des Attributs \"{elem}\" aus der Konfigurationsdatei.", EventLogEntryType.Error, 1, 1);

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
    /// Create a list of users from active directory
    /// </summary>
    /// \ToDo Domain
    static void CreateUserList()
    {

        Console.Write("[info] Generiere Liste der AD-User.. ");

        string ldapPath = "LDAP://d2000.local";

        try
        {
            // Liste, um die SamAccountNames zu speichern
            userList = new List<string>();

            // AD-Verbindung herstellen
            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(ldapPath);
            DirectorySearcher searcher = new DirectorySearcher(entry);

            // Suche nach Objekten, die den objectClass "user" oder "group" haben
            //searcher.Filter = "(|(objectClass=user)(objectClass=group))"; // Filter für alle Objekte
            searcher.Filter = "(&(objectClass=user))";
            searcher.PageSize = 100000; // Optional: erhöht die Abfrageleistung bei großen AD-Strukturen
            searcher.PropertiesToLoad.Add("sAMAccountName");  // Lade SamAccountName
            searcher.PropertiesToLoad.Add("extensionAttribute10");  // Lade das extensionAttribute10

            // Durchlaufe alle Suchergebnisse
            foreach (SearchResult result in searcher.FindAll())
            {
                System.DirectoryServices.DirectoryEntry userEntry = result.GetDirectoryEntry();

                // Prüfen, ob "sAMAccountName" vorhanden ist
                if (userEntry.Properties.Contains("sAMAccountName"))
                {

                    //Console.WriteLine("SAMAccountName OK");

                    // Hole den SamAccountName
                    string samAccountName = userEntry.Properties["sAMAccountName"].Value?.ToString();

                    // Prüfen, ob "extensionAttribute10" vorhanden ist
                    string extensionAttribute10 = null;
                    if (userEntry.Properties.Contains("extensionAttribute10"))
                    {
                        extensionAttribute10 = userEntry.Properties["extensionAttribute10"].Value?.ToString();
                    }

                    /*
                    if ((extensionAttribute10 != null && (extensionAttribute10 == "User" || extensionAttribute10 == "technischer User") ) )
                    {
                        string n = "D2000\\" + samAccountName.Trim();
                        userList.Add(n);
                    }
                    */

                    string n = "D2000\\" + samAccountName.Trim();
                    userList.Add(n);

                }
            }
            userList.Add("\n==================\n");

        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception: {ex.Message}");

            WriteCustomEventLog($"Fehler beim Erstellen der Liste der AD-User. {ex.Message}", EventLogEntryType.Error, 1, 1);
            Environment.Exit(1);

        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("OK!");
        Console.ResetColor();
    }

    /// <summary>
    /// Create a list of groups from active directory
    /// </summary>
    /// \ToDo Domain
    static void CreateGroupList()
    {

        Console.Write("[info] Generiere Liste der AD-Gruppen.. ");

        string ldapPath = "LDAP://d2000.local";

        try
        {
            // Liste, um die SamAccountNames zu speichern
            groupList = new List<string>();

            // AD-Verbindung herstellen
            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry(ldapPath);
            DirectorySearcher searcher = new DirectorySearcher(entry);

            // Suche nach Objekten, die den objectClass "user" oder "group" haben
            //searcher.Filter = "(|(objectClass=user)(objectClass=group))"; // Filter für alle Objekte
            searcher.Filter = "(&(objectClass=group))";
            searcher.PageSize = 100000; // Optional: erhöht die Abfrageleistung bei großen AD-Strukturen
            searcher.PropertiesToLoad.Add("sAMAccountName");  // Lade SamAccountName

            // Durchlaufe alle Suchergebnisse
            foreach (SearchResult result in searcher.FindAll())
            {
                System.DirectoryServices.DirectoryEntry userEntry = result.GetDirectoryEntry();

                // Prüfen, ob "sAMAccountName" vorhanden ist
                if (userEntry.Properties.Contains("sAMAccountName"))
                {

                    //Console.WriteLine("SAMAccountName OK");

                    // Hole den SamAccountName
                    string samAccountName = userEntry.Properties["sAMAccountName"].Value?.ToString();

                    string n = "D2000\\" + samAccountName.Trim();
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
        Console.WriteLine("OK!");
        Console.ResetColor();
    }

    /// <summary>
    /// List all groups and their members in a separate sheet we can link to
    /// </summary>
    static void GenerateGroupMember()
    {

        int rowIndex = 1;

        foreach (string group in explicitPermissionGroups.Distinct())
        {

            //Console.WriteLine($"[info] Writing {group}");

            // Setze den Gruppennamen als Spaltenüberschrift
            groupMemberSheet.Cells[rowIndex, 1].Value = group;

            // Set background color
            groupMemberSheet.Cells[rowIndex, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
            groupMemberSheet.Cells[rowIndex, 1].Style.Fill.BackgroundColor.SetColor(Color.LightBlue);

            // set column width
            groupMemberSheet.Column(1).Width = 50;

            rowIndex++;

            // Hole die Mitglieder der Gruppe
            List<string> members = GetGroupMembers(group);

            // Füge die Mitglieder unter der Spaltenüberschrift ein
            foreach (string member in members)
            {
                groupMemberSheet.Cells[rowIndex, 1].Value = member;

                // ToDo
                if (IsUserAGroup(member))
                {

                    //todo
                    recursiveGroupsToResolve.Add(member);

                    groupMemberSheet.Cells[rowIndex, 2].Value = "Group";

                }

                rowIndex++;
            }

            rowIndex++; // Leere Zeile zwischen Gruppen

        }
    }

    /// <summary>
    /// Check if an account is a user or a group
    /// </summary>
    /// <param name="accountName"></param>
    /// <returns></returns>
    static bool IsUserAGroup(string accountName)
    {

        using (PrincipalContext context = new PrincipalContext(ContextType.Domain, "d2000.local"))
        {

            UserPrincipal user = UserPrincipal.FindByIdentity(context, accountName);

            GroupPrincipal group = GroupPrincipal.FindByIdentity(context, accountName);

            if (user != null)
            {
                return false;
            }
            else if (group != null)
            {
                return true;
            }

            return false;
        }

    }

    static void UpdateGroupReferences(string src, int srcColumn, string target, int targetColumn)
    {
        // Pfad zur Excel-Datei
        string filePath = excelfilePath;

        // Öffne die vorhandene Excel-Datei
        FileInfo file = new FileInfo(filePath);
        using (var package = new ExcelPackage(file))
        {
            // Hole das Arbeitsblatt, das die Gruppenreferenzen braucht (z.B. "AnotherSheet")
            // All Permissions
            var srcWorksheet = package.Workbook.Worksheets[src];

            // Hole das Gruppen-Arbeitsblatt
            // Group Member
            var targetWorksheet = package.Workbook.Worksheets[target];

            int row = 2; // Starte bei Zeile 2 (angenommen, Zeile 1 hat Überschriften)

            //Console.WriteLine($"[debug] Bearbeite Links in Src: {src} - target: {target}");

            //while (srcWorksheet.Cells[row, srcColumn].Value != null) // Durchlaufe die Zeilen, bis keine Daten mehr vorhanden sind
            while(row <= srcWorksheet.Dimension.End.Row)
            {

                try
                {
                    string groupName = srcWorksheet.Cells[row, srcColumn].Value.ToString();

                    //Console.WriteLine($"[debug] Zeile {row} - group: {groupName}");

                    //Console.WriteLine($"[debug] Found group {groupName} in AllPermissions");

                    // Finde die Zeile im "Group Members" Sheet, wo der Gruppennamen steht
                    for (int groupRow = 1; groupRow <= targetWorksheet.Dimension.End.Row; groupRow++)
                    {

                        //Console.WriteLine($"[debug] Found group {groupWorksheet.Cells[groupRow, 2].Value} in Group Member");

                        if (targetWorksheet.Cells[groupRow, targetColumn].Value != null && targetWorksheet.Cells[groupRow, targetColumn].Value.ToString() == groupName)
                        {
                            // Setze die Referenz auf die Gruppe
                            // Console.WriteLine($"[debug] Updating {groupName} in AllPermissions to reference group {groupWorksheet.Cells[groupRow, 1].Value} in Group Member");

                            string cellReference = $"=HYPERLINK(\"#'{target}'!A{groupRow}\",\"{groupName}\")";

                            srcWorksheet.Cells[row, srcColumn].Formula = cellReference;
                            srcWorksheet.Cells[row, srcColumn].Style.Font.Color.SetColor(System.Drawing.Color.Blue);
                            break;
                        }
                    
                    }

                } catch (NullReferenceException nre) { }

                row++;
            }

            // Speichere die Änderungen
            package.Save();
        }
    }

    /// <summary>
    /// Get all the members of a group
    /// </summary>
    /// <param name="groupName"></param>
    /// <returns></returns>
    static List<string> GetGroupMembers(string groupName)
    {

        // Spezielle Behandlung für die Gruppe "Domänen-Benutzer"
        if (groupName == "D2000\\Domänen-Benutzer")
        {
            return GetDomainUsers();
        }

        //Console.WriteLine($"[debug] Looking up group members for \"{groupName}\".");
        int foundEntries = 0;

        List<string> membersList = new List<string>();
        try
        {
            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry("LDAP://DC=d2000,DC=local");
            DirectorySearcher searcher = new DirectorySearcher(entry);

            //Console.WriteLine($"[info] Looking up group {groupName}");

            groupName = groupName.Replace("D2000\\", "");

            // Suche nach der Gruppe mit dem angegebenen Namen
            searcher.Filter = $"(&(objectClass=group)(cn={groupName}))";
            searcher.PropertiesToLoad.Add("member");

            SearchResult result = searcher.FindOne();

            if (result != null)
            {

                //Console.WriteLine($"[debug] Found group \"{groupName}\".");

                // Hole alle Mitglieder der Gruppe
                var members = result.Properties["member"];

                //Console.WriteLine($"[debug] It has \"{members.Count}\" member.");
                
                foreach (var member in members)
                {
                    //membersList.Add(member.ToString());
                    //membersList.Add(ExtractCnFromDn(member.ToString()));
                    string samAccountName = GetSamAccountName(member.ToString());
                    string samAccountNameToSearch = "D2000\\" + samAccountName;

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
                    foundEntries++;

                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[error]Error fetching group members: {ex.Message}");
        }

        //Console.WriteLine($"[debug] Found {foundEntries} entries.");
        return membersList;
    }

    static List<string> GetDomainUsers()
    {
        //Console.WriteLine("[debug] Looking up members of 'Domänen-Benutzer' group via primaryGroupID.");
        int foundEntries = 0;

        List<string> membersList = new List<string>();
        try
        {
            System.DirectoryServices.DirectoryEntry entry = new System.DirectoryServices.DirectoryEntry("LDAP://DC=d2000,DC=local");
            DirectorySearcher searcher = new DirectorySearcher(entry);
            searcher.PropertiesToLoad.Add("sAMAccountName");
            searcher.PropertiesToLoad.Add("extensionAttribute10");

            // Suche nach Benutzern mit primaryGroupID = 513 (für "Domänen-Benutzer")
            searcher.Filter = "(&(objectCategory=person)(objectClass=user)(primaryGroupID=513))";

            SearchResultCollection results = searcher.FindAll();

            if (results != null)
            {
                //Console.WriteLine($"[debug] Found \"{results.Count}\" members in 'Domänen-Benutzer'.");

                foreach (SearchResult result in results)
                {
                    System.DirectoryServices.DirectoryEntry userEntry = result.GetDirectoryEntry();
                    string samAccountName = userEntry.Properties["sAMAccountName"].Value.ToString();
                    string samAccountNameToSearch = "D2000\\" + samAccountName;

                    if(userEntry.Properties["extensionAttribute10"].Value == null || userEntry.Properties["extensionAttribute10"].Value.ToString() != "User")
                    {
                        continue;
                    }

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
                    foundEntries++;
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[error] Error fetching members of 'Domänen-Benutzer': {ex.Message}");
        }

        //Console.WriteLine($"[debug] Found {foundEntries} entries.");
        return membersList;
    }

    /// <summary>
    /// Get the SAMAccountName by distinguishedName
    /// </summary>
    /// <param name="distinguishedName"></param>
    /// <returns></returns>
    static string GetSamAccountName(string distinguishedName)
    {

        //Console.WriteLine($"[debug] Looking up user {distinguishedName}");

        try
        {
            using (System.DirectoryServices.DirectoryEntry memberEntry = new System.DirectoryServices.DirectoryEntry($"LDAP://{distinguishedName}"))
            {
                // sAMAccountName aus den Eigenschaften des Mitglieds holen
                object samAccountNameObj = memberEntry.Properties["sAMAccountName"].Value;

                //Console.WriteLine($"[debug] Resolved {samAccountNameObj.ToString()}");

                return samAccountNameObj != null ? samAccountNameObj.ToString() : null;
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[error]Error fetching sAMAccountName for {distinguishedName}: {ex.Message}");
            return null;
        }
    }

    static void ResolveRecursiveGroups()
    {

        Console.WriteLine("[debug] Resolving recursive groups..");

        recursiveGroupsToResolve = new List<string>();

        List<string> recursiveGroupsToResolveTemp = new List<string>();

        // finde alle markierten zeilen
        for (int i = 1; i <= groupMemberSheet.Dimension.End.Row; i++)
        {
            if (groupMemberSheet.Cells[i, 2].Value != null && groupMemberSheet.Cells[i, 2].Value.ToString() == "Group")
            {
                recursiveGroupsToResolve.Add(groupMemberSheet.Cells[i, 1].Value.ToString());
                groupMemberSheet.Cells[i, 2].Value = "Resolved";
            }
        }

        if (recursiveGroupsToResolve.Count == 0) { return; }
       
        int lastRow = groupMemberSheet.Dimension.End.Row;

        lastRow += 2;

        foreach (string v in recursiveGroupsToResolve.Distinct())
        {

            // check if its already resolved
            bool shouldContinue = false;
            for (int i = 1; i <= groupMemberSheet.Dimension.End.Row; i++)
            {
                if (groupMemberSheet.Cells[i, 1].Value != null && groupMemberSheet.Cells[i, 1].Value.ToString() == "D2000\\" + v)
                {
                    shouldContinue = true;
                }
            }
            if (shouldContinue)
                continue;

            groupMemberSheet.Cells[lastRow, 1].Value = "D2000\\" + v;
            // Set background color
            groupMemberSheet.Cells[lastRow, 1].Style.Fill.PatternType = ExcelFillStyle.Solid;
            groupMemberSheet.Cells[lastRow, 1].Style.Fill.BackgroundColor.SetColor(Color.LightBlue);

            lastRow++;

            List<string> tmp = GetGroupMembers("D2000\\" + v);

            foreach (string u in tmp)
            {
                groupMemberSheet.Cells[lastRow, 1].Value = u;

                // ToDo
                if (IsUserAGroup(u))
                {

                    //todo
                    recursiveGroupsToResolveTemp.Add(u);

                    groupMemberSheet.Cells[lastRow, 2].Value = "Group";

                }

                lastRow++;
            }

            lastRow++;

        }

        recursiveGroupsToResolve = recursiveGroupsToResolveTemp;

        ResolveRecursiveGroups();

    }

    static void UpdateResolvedGroupLinks()
    {

        Console.WriteLine("[debug] Resolving recursive group links..");

        // finde alle markierten zeilen
        for (int i = 1; i <= groupMemberSheet.Dimension.End.Row; i++)
        {

            if (groupMemberSheet.Cells[i, 2].Value != null && groupMemberSheet.Cells[i, 2].Value.ToString() == "Resolved")
            {

                string groupName = groupMemberSheet.Cells[i, 1].Value.ToString();

                // find resolved group
                for (int j = 1; j <= groupMemberSheet.Dimension.End.Row; j++)
                {
                    if (groupMemberSheet.Cells[j, 1].Value != null && groupMemberSheet.Cells[j, 1].Value.ToString() == "D2000\\" + groupName)
                    {
                        // insert link
                        string cellReference = $"=HYPERLINK(\"#'Group Member'!A{j}\",\"{groupName}\")";
                        groupMemberSheet.Cells[i, 1].Formula = cellReference;
                        groupMemberSheet.Cells[i, 1].Style.Font.Color.SetColor(System.Drawing.Color.Blue);
                    }
                }

            }

            groupMemberSheet.Cells[i, 2].Value = "";

        }

    }

    static void CancelKeyPressHandler(object sender, ConsoleCancelEventArgs e)
    {
        WriteCustomEventLog("Der Prozess wurde durch den Benutzer durch drücken von \"Ctrl-C\" abgebrochen.", EventLogEntryType.Error, 1, 1);
        //e.Cancel = true; // Verhindert das sofortige Beenden des Programms
        userCancelled = true; // Setzt eine Flag, um zu erkennen, dass Strg+C gedrückt wurde
    }

    static void ProcessExitHandler(object sender, EventArgs e)
    {
        
        if(!fullyExecuted)
        {
            if (userCancelled)
            {
                //Console.WriteLine("Programm wurde durch Strg+C beendet.");
                WriteCustomEventLog("Der Prozess wurde vom Benutzer durch drücken von \"Ctrl-C\" abgebrochen.", EventLogEntryType.Error, 1, 1);
            }
            else
            {
                WriteCustomEventLog("Der Prozess wurde unerwartet beendet.", EventLogEntryType.Error, 1, 1);
            }
        }

        // Hier kannst du Ressourcen aufräumen oder Speicher freigeben
    }

    #endregion

}
