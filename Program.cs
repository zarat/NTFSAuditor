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

class Program
{

    #region Parameters

    public static int numberOfFolders, numberOfPermissions = 0;

    public static List<string> userList = new List<string>();
    public static List<string> groupList = new List<string>();
    public static List<string> ignoredAccountsList = new List<string>();

    public static string outfilePath = String.Empty;
    public static string logfilePath = String.Empty;

    static List<string> ignoredNames = new List<string>
    {
        @"NT-AUTORITÄT\SYSTEM",
        @"NT AUTHORITY\SYSTEM",
        @"BUILTIN\Administrators",
        @"BUILTIN\Users",
        @"VORDEFINIERT\Administratoren",
        @"VORDEFINIERT\Benutzer",
        @"D2000\Administrator",
        @"D2000\Domänen-Admins",
        @"D2000\named_admins",
        @"D2000\folioadmin"
    };

    static List<string> ignoredNamesWildcard = new List<string>
    {
        @"D2000\\s_.*",
        @"D2000\\dom_.*",
        @"D2000\\admin_.*"
    };

    static List<string> explicitPermissionUsers = new List<string>();
    static List<string> explicitPermissionGroups = new List<string>();
    static List<string> explicitPermissionFolders = new List<string>();
    static List<string> explicitPermissionFoldersInherited = new List<string>();

    #endregion

    #region Methods

    /// <summary>
    /// Main function
    /// </summary>
    /// <param name="args"></param>
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Please provide a sharename as argument.");
            return;
        }


        string sharename = args[0];
        string year = DateTime.Now.ToString("yyyy");
        string outdir = $@"C:\Scripts\Berechtigungsaudit\Shares\{year}";

        if (!Directory.Exists(outdir))
        {
            Directory.CreateDirectory(outdir);
        }

        string datenow = DateTime.Now.ToString("yyyy-MM-dd");
        string shareNameForFile = sharename.Contains(@"\") ? sharename.Split('\\').Last() : sharename;
        string outfile = $"{shareNameForFile}_ntfs_{datenow}.csv";
        outfilePath = Path.Combine(outdir, outfile);
        logfilePath = outfilePath.Replace("csv", "log");

        /*
         * Create lists of users and groups for comparision
         */
        CreateUserList();
        CreateGroupList();

        /*
         * Delete existing files
         */
        if (File.Exists(outfilePath)) { File.Delete(outfilePath); }
        if (File.Exists(logfilePath)) { File.Delete(logfilePath); }

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
        ManagementScope scope = new ManagementScope($@"\\{remoteComputer}\root\cimv2");
        scope.Connect();

        /*
         * Find all shares
         */
        string query = "SELECT Name, Path FROM Win32_Share";
        ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
        Console.Write("[info] Ermittle verfügbare Shares.. ");
        ManagementObjectCollection results = searcher.Get();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("OK!");
        Console.ResetColor();

        /*
         * List all shares
         */
        //Console.WriteLine("[info] Available shares on fileserver:");
        //foreach (ManagementObject share in results) Console.WriteLine($"Share: {share["Name"]} - Path: {share["Path"]}"); 

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


            Console.WriteLine($"[info] Share: \"{found_shareName}\" gefunden. Pfad: \"{found_sharePath}\"");

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
        }

        DateTime endDate = DateTime.Now;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Beendet am \"{endDate}\"");
        Console.ResetColor();

        TimeSpan executionTime = endDate - startDate;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Ausführungsdauer: \"{executionTime}\"");
        Console.ResetColor();

        FileInfo fileInfo = new FileInfo(outdir + "\\" + outfile);
        long fileSizeInBytes = fileInfo.Length;
        double fileSizeInKB = fileSizeInBytes / 1024.0;

        /*
         * Send email
         */
        try
        {

            MailMessage mail = new MailMessage();
            mail.From = new MailAddress($"Berechtigungsaudit <Berechtigungsaudit@{Environment.MachineName}.akm.at>");
            //mail.To.Add("meldungen.ber-audit.gbi@akm.at");
            mail.To.Add("meldungen.ber-audit.gbi@akm.at");
            mail.Subject = shareNameForFile + " - CSV erstellt und abgelegt";
            mail.Body = $"{outfile} wurde erstellt und unter {outdir} abgelegt.\n\n";

            mail.BodyEncoding = System.Text.Encoding.UTF8;
            mail.SubjectEncoding = System.Text.Encoding.UTF8;

            string statistics = $"Startzeit: {startDate}\nEndzeit: {endDate}\nAusführungsdauer: {executionTime}\nDateigröße: {fileSizeInKB:F2} KB\nAnzahl an Verzeichnissen: {numberOfFolders}\nAnzahl an Berechtigungen: {numberOfPermissions}";

            mail.Body += statistics;

            string logText = String.Empty;

            logText += $"Statistik für: {sharename}\n\n";

            logText += statistics + "\n\n";

            logText += "Gruppen mit expliziten Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionGroups.Distinct());


            logText += "\n\nAus der Erfassung ausgeschlossene Accounts:\n";
            logText += String.Join(Environment.NewLine, ignoredAccountsList.Distinct());

            logText += "\n\nAccounts mit expliziten Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionUsers.Distinct());

            logText += "\n\nOrdner mit unterbrochenen (expliziten) Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionFolders.Distinct());

            logText += "\n\nOrdner mit vererbten (expliziten) Berechtigungen:\n";
            logText += String.Join(Environment.NewLine, explicitPermissionFoldersInherited.Distinct());

            File.AppendAllText(logfilePath, logText);

            Attachment attachment = new Attachment(logfilePath); // Datei anhängen
            mail.Attachments.Add(attachment);

            //File.AppendAllText(logfilePath, mail.Body);

            // SMTP Client erstellen
            SmtpClient smtpClient = new SmtpClient("relay.akm.at");
            smtpClient.UseDefaultCredentials = true; // Verwenden der Standardanmeldeinformationen

            // E-Mail senden
            smtpClient.Send(mail);
            Console.WriteLine("[info] E-Mail wurde erfolgreich gesendet.");

        }
        catch (Exception ex)
        {
            Console.WriteLine("Fehler beim Senden der E-Mail: " + ex.Message);
        }

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
        }
        catch (Exception ex)
        {
            // Behandle andere Ausnahmen (optional)
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[warning] {ex.Message}");
            Console.ResetColor();
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
                        explicitPermissionFoldersInherited.Add("\"" + folderPath + "\"");
                    }
                    else
                    {
                        explicitPermissionFolders.Add("\"" + folderPath + "\"");
                    }
                    explicitPermissionUsers.Add(identity);
                }

                if (groupList.Contains(identity))
                {
                    explicitPermissionGroups.Add(identity);
                }

                // Output permissions information
                string rights = rule.FileSystemRights.ToString();
                bool isInherited = rule.IsInherited;
                numberOfPermissions++;

                string outputString = $"\"{folderPath}\";{identity};{rights};{isInherited}";
                File.AppendAllText(outfilePath, outputString + Environment.NewLine);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            throw ex;
            //Console.WriteLine($"[warning] Access denied when processing directory {folderPath}: {ex.Message}");
        }
        catch (Exception ex)
        {
            // Interferes with percentage display
            //Console.WriteLine($"[error] An error occurred when processing directory {folderPath}: {ex.Message}");
        }
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Create a list of users from active directory
    /// </summary>
    static void CreateUserList()
    {

        Console.Write("[info] Generiere Liste der AD-User.. ");

        string ldapPath = "LDAP://d2000.local";

        try
        {
            // Liste, um die SamAccountNames zu speichern
            userList = new List<string>();

            // AD-Verbindung herstellen
            DirectoryEntry entry = new DirectoryEntry(ldapPath);
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
                DirectoryEntry userEntry = result.GetDirectoryEntry();

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
        }

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("OK!");
        Console.ResetColor();
    }

    /// <summary>
    /// Create a list of groups from active directory
    /// </summary>
    static void CreateGroupList()
    {

        Console.Write("[info] Generiere Liste der AD-Gruppen.. ");

        string ldapPath = "LDAP://d2000.local";

        try
        {
            // Liste, um die SamAccountNames zu speichern
            groupList = new List<string>();

            // AD-Verbindung herstellen
            DirectoryEntry entry = new DirectoryEntry(ldapPath);
            DirectorySearcher searcher = new DirectorySearcher(entry);

            // Suche nach Objekten, die den objectClass "user" oder "group" haben
            //searcher.Filter = "(|(objectClass=user)(objectClass=group))"; // Filter für alle Objekte
            searcher.Filter = "(&(objectClass=group))";
            searcher.PageSize = 100000; // Optional: erhöht die Abfrageleistung bei großen AD-Strukturen
            searcher.PropertiesToLoad.Add("sAMAccountName");  // Lade SamAccountName

            // Durchlaufe alle Suchergebnisse
            foreach (SearchResult result in searcher.FindAll())
            {
                DirectoryEntry userEntry = result.GetDirectoryEntry();

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
        }
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("OK!");
        Console.ResetColor();
    }

    #endregion

}
