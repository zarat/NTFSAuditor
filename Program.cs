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

class Program
{

    public static int numberOfFolders, numberOfPermissions = 0;

    public static List<string> userList = new List<string>();

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

    static List<string> explicitPermissionUsers = new List<string>();
    static List<string> explicitPermissionFolders = new List<string>();

    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Please provide a sharename as argument.");
            return;
        }

        CreateUserList();

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
        string outfilePath = Path.Combine(outdir, outfile);

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
                ProcessDirectory(sharename, outfilePath);
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
            mail.To.Add("manuel.zarat@akm.at");
            mail.Subject = shareNameForFile + " - CSV erstellt und abgelegt";
            mail.Body = $"{outfile} wurde erstellt und unter {outdir} abgelegt.\n\nStartzeit: {startDate}\nEndzeit: {endDate}\nAusführungsdauer: {executionTime}\nDateigröße: {fileSizeInKB:F2} KB\nAnzahl an Verzeichnissen: {numberOfFolders}\nAnzahl an Berechtigungen: {numberOfPermissions}";

            mail.Body += "\n\nOrdner mit expliziten Userberechtigungen:\n";
            mail.Body += String.Join(Environment.NewLine, explicitPermissionFolders.Distinct());

            mail.Body += "\n\nExplizite Userberechtigungen:\n";
            mail.Body += String.Join(Environment.NewLine, explicitPermissionUsers.Distinct());

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
            ProcessFolder(folder, outfilePath);
        }
    }

    static void ProcessFolder(string folderPath, string outfilePath)
    {
        DirectoryInfo directoryInfo = new DirectoryInfo(folderPath);
        DirectorySecurity directorySecurity = directoryInfo.GetAccessControl();
        AuthorizationRuleCollection acl = directorySecurity.GetAccessRules(true, true, typeof(NTAccount));

        foreach (FileSystemAccessRule rule in acl)
        {
            string identity = rule.IdentityReference.Value;

            string[] identityParts = identity.Split(new char[] { '\\' });

            Console.WriteLine($"[info] Found identity {identityParts[1]}");

            if (userList.Contains(identityParts[1])) { 
                Console.WriteLine($"[info] Found {identityParts[1]} in userList");
                explicitPermissionFolders.Add(folderPath);
                explicitPermissionUsers.Add(identityParts[1]);
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

                    if ((extensionAttribute10 != null && extensionAttribute10 == "User") )
                    {
                        string n = samAccountName.Trim();
                        userList.Add(n);
                    }
                    
                    
                }
            }

            // Ausgabe der gefundenen Benutzer
            Console.WriteLine("Users with objectClass 'user' or 'group':");
            foreach (var user in userList)
            {
                Console.WriteLine(user);
            }

            // Hier kannst du mit der Liste weiterarbeiten
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Exception: {ex.Message}");
        }
    }

}
