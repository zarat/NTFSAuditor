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
        
        CreateUserList();
        CreateGroupList();

        if (File.Exists(outfilePath)) { File.Delete(outfilePath); }

        string outputString = "FolderPath;IdentityReference;FileSystemRights;IsInherited";
        File.AppendAllText(outfilePath, outputString + Environment.NewLine);

        DateTime startDate = DateTime.Now;
        
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Starting at \"{startDate}\"");
        Console.ResetColor();

        string remoteComputer = "fileserver";
        ManagementScope scope = new ManagementScope($@"\\{remoteComputer}\root\cimv2");

        try
        {
            // Verbindung zum Remote-Computer herstellen
            scope.Connect();
            //Console.WriteLine($"[info] Connected to {remoteComputer}");


            string query = "SELECT Name, Path FROM Win32_Share";
            ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
            ManagementObjectCollection results = searcher.Get();

            //Console.WriteLine("[info] Available shares on fileserver:");
            foreach (ManagementObject share in results)
            {
                //Console.WriteLine($"Share: {share["Name"]} - Path: {share["Path"]}");
            }

            var foundShare = results.Cast<ManagementObject>().FirstOrDefault(s => s["Name"].ToString() == sharename);

            if (foundShare != null)
            {
                string shareName = foundShare["Name"].ToString();
                string sharePath = foundShare["Path"].ToString();

                
                Console.WriteLine($"[info] Found share: {shareName} with path: {sharePath}");
                //ProcessDirectory(sharename, outfilePath);
                

                
                try
                {
                    // ProcessDirectory kann Zugriff verweigert werden, also in try-catch
                    ProcessDirectory(sharename, outfilePath);
                }
                catch (UnauthorizedAccessException ex)
                {
                    // Zugriff verweigert, aber das Skript bleibt nicht stehen
                    Console.WriteLine($"[warning] Access denied when processing directory {sharename}: {ex.Message}");
                }
                catch (Exception ex)
                {
                    // Generelle Fehlerbehandlung
                    Console.WriteLine($"[error] An error occurred while processing the directory {sharename}: {ex.Message}");
                }
                

            }
            else
            {
                Console.WriteLine($"[warning] No shares found with name: {sharename}");
            }

        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"[error] Access denied to {remoteComputer}: {ex.Message}");
        }
        catch (ManagementException ex)
        {
            Console.WriteLine($"[error] WMI query failed: {ex.Message}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[error] An error occurred: {ex.Message}");
        }

        DateTime endDate = DateTime.Now;

        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] Finished at \"{endDate}\"");
        Console.ResetColor();

        TimeSpan executionTime = endDate - startDate;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine($"[info] ExecutionTime \"{executionTime}\"");
        Console.ResetColor();

        FileInfo fileInfo = new FileInfo(outdir + "\\" + outfile);
        long fileSizeInBytes = fileInfo.Length;
        double fileSizeInKB = fileSizeInBytes / 1024.0;

        try
        {
            // E-Mail Nachricht erstellen
            MailMessage mail = new MailMessage();
            mail.From = new MailAddress($"Berechtigungsaudit <Berechtigungsaudit@{Environment.MachineName}.akm.at>");
            //mail.To.Add("meldungen.ber-audit.gbi@akm.at");
            mail.To.Add("meldungen.ber-audit.gbi@akm.at");
            mail.Subject = shareNameForFile + " - CSV erstellt und abgelegt";
            mail.Body = $"{outfile} wurde erstellt und unter {outdir} abgelegt.\n\nStartzeit: {startDate}\nEndzeit: {endDate}\nAusführungsdauer: {executionTime}\nDateigröße: {fileSizeInKB:F2} KB\nAnzahl an Verzeichnissen: {numberOfFolders}\nAnzahl an Berechtigungen: {numberOfPermissions}";

            mail.Body += "\n\nGruppen mit expliziten Berechtigungen:\n";
            mail.Body += String.Join(Environment.NewLine, explicitPermissionGroups.Distinct());

            mail.Body += "\n\nAccounts mit expliziten Berechtigungen:\n";
            mail.Body += String.Join(Environment.NewLine, explicitPermissionUsers.Distinct());

            mail.Body += "\n\nOrdner mit unterbrochenen (expliziten) Berechtigungen:\n";
            mail.Body += String.Join(Environment.NewLine, explicitPermissionFolders.Distinct());

            mail.Body += "\n\nOrdner mit vererbten (expliziten) Berechtigungen:\n";
            mail.Body += String.Join(Environment.NewLine, explicitPermissionFoldersInherited.Distinct());

            

            File.AppendAllText(logfilePath, mail.Body);

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
    /// Find all folders in a Share and find the ACLs
    /// </summary>
    /// <param name="folderPath"></param>
    /// <param name="outfilePath"></param>
    static void ProcessDirectory(string folderPath, string outfilePath)
    {
        // Get all directories
        string[] directories = Directory.GetDirectories(folderPath, "*", SearchOption.AllDirectories);
        
        int directoryCount = directories.Length;
        numberOfFolders = directoryCount;
        Console.WriteLine("[info] Found " + directoryCount + " directories");

        foreach (string folder in directories)
        {
            //Console.WriteLine("[info] Processing folder " + folder);
            //ProcessFolder(folder, outfilePath);

            
            try
            {
                // ProcessDirectory kann Zugriff verweigert werden, also in try-catch
                ProcessFolder(folder, outfilePath);
            }
            catch (UnauthorizedAccessException ex)
            {
                // Zugriff verweigert, aber das Skript bleibt nicht stehen
                Console.WriteLine($"[warning] Access denied when processing directory {folder}: {ex.Message}");
            }
            catch (Exception ex)
            {
                // Generelle Fehlerbehandlung
                Console.WriteLine($"[error] An error occurred while processing the directory {folder}: {ex.Message}");
            }
            

        }
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

                //Console.WriteLine($"[info] Found identity {identity}");

                if (ignoredNames.Contains(identity))
                {
                    //Console.WriteLine($"[info] Found {identity} in ignoredNames");
                    continue;
                }

                bool doContinue = false;

                foreach (var pattern in ignoredNamesWildcard)
                {
                    // Überprüfen, ob der Input-String zum Regex-Muster passt
                    if (Regex.IsMatch(identity, pattern))
                    {
                        doContinue = true;
                    }
                }

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

                if (doContinue)
                {
                    continue;
                }

                string rights = rule.FileSystemRights.ToString();
                bool isInherited = rule.IsInherited;

                numberOfPermissions++;

                // Output format: "Folder;Identity;Rights;IsInherited"
                string outputString = $"\"{folderPath}\";{identity};{rights};{isInherited}";

                //Console.WriteLine("[info] " + outputString);
                //Console.WriteLine("[info] Output in " + outfilePath);

                File.AppendAllText(outfilePath, outputString + Environment.NewLine);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            // Zugriff verweigert, aber das Skript bleibt nicht stehen
            Console.WriteLine($"[warning] Access denied when processing directory {folderPath}: {ex.Message}");
        }
        catch (Exception ex)
        {
            // Generelle Fehlerbehandlung
            Console.WriteLine($"[error] An error occurred while processing the directory {folderPath}: {ex.Message}");
        }
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Create a list of users from active directory
    /// </summary>
    static void CreateUserList()
    {
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

            /*
            // Ausgabe der gefundenen Benutzer
            //Console.WriteLine("Users with objectClass 'user':");
            foreach (var user in userList)
            {
                //Console.WriteLine(user);
                File.AppendAllText(logfilePath, user + Environment.NewLine);
            }

            File.AppendAllText(logfilePath, Environment.NewLine);
            */

        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception: {ex.Message}");
        }
    }

    /// <summary>
    /// Create a list of groups from active directory
    /// </summary>
    static void CreateGroupList()
    {
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
            groupList.Add("\n==================\n");

            /*
            // Ausgabe der gefundenen Benutzer
            //Console.WriteLine("Users with objectClass 'user':");
            foreach (var user in groupList)
            {
                //Console.WriteLine(user);
                File.AppendAllText(logfilePath, user + Environment.NewLine);
            }

            File.AppendAllText(logfilePath, Environment.NewLine);
            */

        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception: {ex.Message}");
        }
    }

    #endregion

}
