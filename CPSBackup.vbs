Const ERROR_FILE_NOT_FOUND = 53
Const ERROR_DISK_FULL = &H80070070
ERROR_GENERAL_FAILURE = vbObjectError + 1
TotalBackupSizeMB = 0
Const PARTITION_GRACE = 100

Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

SQLUser = ""
SQLPass = ""
SQLServer = ""
SQLAuth = ""

SQLPASS_ENCRYPTED = ""
SQLKEYL = ""
SQLSEED = ""

On Error Resume Next
shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Websense\Data Security\INSTALLDIR")
If Err.Number = 0 Then
    Wow6432Node = "Wow6432Node\"
Else
    Wow6432Node = ""
End If
On Error Goto 0

installdir = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\INSTALLDIR")
temp = fso.GetSpecialFolder(2) + "\"

cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
        chr(32) & chr(34) & "Info" & chr(34) & _
        chr(32) & chr(34) & "Master" & chr(34) & _
        chr(32) & chr(34) & "Backup" & chr(34) & _
        chr(32) & chr(34) & "BackupStarted" & chr(34)
rc = shell.Run(cmd, 0, True)

'Open global log file for append, in Unicode format
Set GlobalLogFile = fso.OpenTextFile(installdir + "CPSBackup.log", 8, True, -1)
GlobalLogFile.WriteLine(CStr(Now()) + " --- Backup Starting")

version = "DSS-" & shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Microsoft\Windows\CurrentVersion\Uninstall\Data Security\DisplayVersion")
SQLDBName = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\DBNAME")

ConfigFile = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\EIP Infra\SettingsPath")
DlpXMLFile = installdir + "tomcat\conf\Catalina\localhost\dlp.xml"
'Read credentials from DLP.xml first
Set DLPXML = CreateObject("Microsoft.XMLDOM")
DLPXML.Async = "False"
DLPXML.validateOnParse = False
DLPXML.Load(DlpXMLFile)
if DLPXML.parseError.errorcode=0 then
    Set resNode = DLPXML.selectSingleNode("//Context/Resource[@name='jdbc/PaDS']")
    SQLUser = resNode.getAttribute("username")
    SQLPASS_ENCRYPTED = resNode.getAttribute("password")
    SQLSEED = resNode.getAttribute("seed")
    SQLKEYL = resNode.getAttribute("keyLength")
    SQLURL = resNode.getAttribute("url")
    SQLAuth = "SQL"
    
    ' Parse URL for server and domain
    Set r = New RegExp
    r.Global = False
    r.IgnoreCase = False
	
	r.Pattern = ";instance=([^;]+)"
	If r.test(SQLURL) Then
        Set matches = r.Execute(SQLURL)
        SQLINST = matches(0).SubMatches(0)
        set matches = Nothing
    End If
	
    r.Pattern = "sqlserver://([\w\.]+)(\\([^:;]+))?(:(\d+))?;"
    If r.test(SQLURL) Then
        Set matches = r.Execute(SQLURL)
        SQLServer = matches(0).SubMatches(0)
		if SQLINST = "" Then
			SQLINST = matches(0).SubMatches(2)
		End If
		SQLPORT = matches(0).SubMatches(4)
        If SQLPORT <> "" Then
                SQLServer = SQLServer & "," & SQLPORT
        End If
        If SQLINST <> "" Then
                SQLServer = SQLServer & "\" & SQLINST
        End If
		set matches = Nothing
    End If
	
    r.Pattern = ";domain=([^;]+)"
    If r.test(SQLURL) Then
        Set matches = r.Execute(SQLURL)
        SQLDomain = matches(0).SubMatches(0)
        set matches = Nothing
    End If
    If SQLDomain <> "" Then
        SQLUser = SQLDomain & "\" & SQLUser
        SQLAuth = "NT"
    End If
	
    Set r = Nothing
end if
Set DLPXML = Nothing




Set XML = CreateObject("Microsoft.XMLDOM")
XML.Load(ConfigFile)
Set Root = XML.documentElement
Set Properties = CreateObject("Scripting.Dictionary")
RecursiveXMLToProps Root, Root.nodeName, Properties
Set Root = Nothing
Set XML = Nothing

if SQLServer = "" Then
    If Properties.Item("EIPSettings.LogDB.Host") <> "" Then
            SQLServer = Properties.Item("EIPSettings.LogDB.Host")
        If Properties.Item("EIPSettings.LogDB.Port") <> "" Then
                SQLServer = SQLServer & "," & Properties.Item("EIPSettings.LogDB.Port")
        End If
        If Properties.Item("EIPSettings.LogDB.InstanceName") <> "" Then
                SQLServer = SQLServer & "\" & Properties.Item("EIPSettings.LogDB.InstanceName")
        End If
    End If
End If

If SQLUser = "" Then
    If Properties.Item("EIPSettings.LogDB.Username") <> "" Then
            SQLUser = Properties.Item("EIPSettings.LogDB.Username")
        If Properties.Item("EIPSettings.LogDB.Domain") <> "" Then
                SQLUser = Properties.Item("EIPSettings.LogDB.Domain") & "\" & SQLUser
        End If
    End If
End If

if SQLPASS_ENCRYPTED = "" Then
    If Properties.Item("EIPSettings.LogDB.Password") <> "" Then
            logdb_password = Properties.Item("EIPSettings.LogDB.Password")
            parts = Split(logdb_password, ":")
            SQLSEED = parts(0)
            SQLKEYL = parts(1)
            SQLPASS_ENCRYPTED = parts(2)
    End If
End If

If SQLPASS_ENCRYPTED <> "" Then
        'decrypt the password
        java_home = Properties.Item("EIPSettings.INSTALLDIR") + "EIP Infra\jre\"
        catalina_home = Properties.Item("EIPSettings.INSTALLDIR") + "EIP Infra\tomcat\"
        tomcat_ext = Properties.Item("EIPSettings.INSTALLDIR") + "EIP Infra\tomcat\lib\tomcat-ext.jar"
        cmd = chr(34) & java_home & "bin\javaw.exe" & chr(34) & _
                chr(32) & "-cp" & chr(32) & chr(34) & tomcat_ext & chr(34) & chr(59) & chr(34) & catalina_home & "lib\bcprov-jdk15-135.jar" & chr(34) & _
                chr(32) & "com.pa.tomcat.resources.DecryptPassword" & chr(32) & SQLPASS_ENCRYPTED & chr(32) & SQLSEED & chr(32) & SQLKEYL
        Set objExec = shell.Exec(cmd)
        SQLPass = objExec.stdOut.ReadLine()
End If

If SQLAuth <> "" Then
    If Properties.Item("EIPSettings.LogDB.Trusted") = "true" Then
            SQLAuth = "NT"
    Else
        SQLAuth = "SQL"
    End If
End If

SQLConnectionString = "Provider=sqloledb;Data Source="& SQLServer & ";" &_
                        "Initial Catalog=" & SQLDBName

If SQLAuth = "NT" Then
    SQLConnectionString = SQLConnectionString & ";Integrated Security=SSPI"
End If

Set SQLConnection = CreateObject("ADODB.Connection")
On Error Resume Next
SQLConnection.Open SQLConnectionString, SQLUser, SQLPass
If Err.Number <> 0 Then
      GlobalLogFile.WriteLine(CStr(Now()) + " --- Cannot Connection to SQL-Server using connection string " + SQLConnectionString + _
                ". Error: " + Err.Description )
      cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
                chr(32) & chr(34) & "Warn" & chr(34) & _
                chr(32) & chr(34) & "Master" & chr(34) & _
                chr(32) & chr(34) & "Backup" & chr(34) & _
                chr(32) & chr(34) & "BackupFailed" & chr(34) & _
                chr(32) & chr(34) & "Cannot connect to database" & chr(34)
      rc = shell.Run(cmd, 0, True)
      description = "Cannot connect to database"
      EventLoggerError(description)   
      WScript.Quit
End If
On Error Goto 0
backup_max = CInt(GetConfigParam("NUM_OF_COPIES"))
backup_root = GetConfigParam("PATH")
If WScript.Arguments.Count = 1 Then
  backup_root = WScript.Arguments(0)
End If

If backup_root = "" Then
  GlobalLogFile.WriteLine(CStr(Now()) + " --- Exit. Backup path is not defined.")
  cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
        chr(32) & chr(34) & "Warn" & chr(34) & _
      chr(32) & chr(34) & "Master" & chr(34) & _
   chr(32) & chr(34) & "Backup" & chr(34) & _
   chr(32) & chr(34) & "BackupFailed" & chr(34) & _
   chr(32) & chr(34) & "backup path is not defined" & chr(34)
  rc = shell.Run(cmd, 0, True)
  description = "backup path is not defined"
  EventLoggerError(description)
  WScript.Quit
End If  

If Right(backup_root, 1) <> "\" Then
  backup_root = backup_root & "\"
End If
If Left(backup_root, 2) = "\\" Then
  unc = True
Else
  unc = False
  uncuser = ""
End If


If unc Then
  mount_point = Mid(backup_root, 1, Len(backup_root) - 1)
  domain = GetConfigParam("DOMAIN")
  username = GetConfigParam("USER_NAME")
  uncuser = domain & "\" & username
  uncpass = GetConfigParam("PASSWORD")
  parts = Split(uncpass, ":")
  'decrypt the password
  java_home = Properties.Item("EIPSettings.INSTALLDIR") + "EIP Infra\jre\"
  catalina_home = Properties.Item("EIPSettings.INSTALLDIR") + "EIP Infra\tomcat\"
  tomcat_ext = Properties.Item("EIPSettings.INSTALLDIR") + "EIP Infra\tomcat\lib\tomcat-ext.jar"
  cmd = chr(34) & java_home & "bin\javaw.exe" & chr(34) & _
        chr(32) & "-cp" & chr(32) & chr(34) & tomcat_ext & chr(34) & chr(59) & chr(34) & catalina_home & "lib\bcprov-jdk15-135.jar" & chr(34) & _
        chr(32) & "com.pa.tomcat.resources.DecryptPassword" & chr(32) & parts(2) & chr(32) & parts(0) & chr(32) & parts(1)
  Set objExec = shell.Exec(cmd)
  uncpass = objExec.stdOut.ReadLine()
    
  If uncuser <> "" Then
    cmd_set = "NET USE" & _
              chr(32) & mount_point & _
              chr(32) & "/USER:" & uncuser & _
              chr(32) & uncpass
    rc = shell.Run(cmd_set, 0, True)
    If rc <> 0 Then
      GlobalLogFile.WriteLine(CStr(Now()) + " --- " + "network map to" & chr(32) & mount_point & chr(32) & "exited with code" & chr(32) & rc)
    End If
    If Not fso.FolderExists(backup_root) Then
      GlobalLogFile.WriteLine(CStr(Now()) + " --- Exit. Path Not Found. -- Backup Path set to " + backup_root)
      cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
                chr(32) & chr(34) & "Warn" & chr(34) & _
                chr(32) & chr(34) & "Master" & chr(34) & _
                chr(32) & chr(34) & "Backup" & chr(34) & _
                chr(32) & chr(34) & "BackupFailed" & chr(34) & _
                chr(32) & chr(34) & "backup path not found" & chr(34)
      rc = shell.Run(cmd, 0, True)
      description = "backup path not found" 
      EventLoggerError(description)
      WScript.Quit
      Else
        If Not IsPathWriteable(backup_root) Then
            GlobalLogFile.WriteLine(CStr(Now()) + " --- Exit. There is no Write permission for Backup Path set to " + backup_root)
            cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
               chr(32) & chr(34) & "Warn" & chr(34) & _
               chr(32) & chr(34) & "Master" & chr(34) & _
               chr(32) & chr(34) & "Backup" & chr(34) & _
               chr(32) & chr(34) & "BackupFailed" & chr(34) & _
               chr(32) & chr(34) & "There is no Write permission for Backup Path" & chr(34)
      rc = shell.Run(cmd, 0, True)
      description = "There is no Write permission for Backup Path"
      EventLoggerError(description)
      WScript.Quit
        End If
    End If
    If InStr(backup_root, " ") <> 0 Then
      GlobalLogFile.WriteLine(CStr(Now()) + " --- " + backup_root + " must not contain spaces")
      cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
            chr(32) & chr(34) & "Warn" & chr(34) & _
            chr(32) & chr(34) & "Master" & chr(34) & _
            chr(32) & chr(34) & "Backup" & chr(34) & _
            chr(32) & chr(34) & "BackupFailed" & chr(34) & _
            chr(32) & chr(34) & "backup path must not contain spaces" & chr(34)
      rc = shell.Run(cmd, 0, True) 
      description = "backup path must not contain spaces"
      EventLoggerError(description)
      WScript.Quit
    End If
    cmd_del = "NET USE" & _
              chr(32) & mount_point & _
              chr(32) & "/DELETE"
'   rc = shell.Run(cmd_del, 0, True)
  End If
Else
    If Not fso.FolderExists(backup_root) Then
      GlobalLogFile.WriteLine(CStr(Now()) + " --- Exit. Path Not Found. -- Backup Path set to " + backup_root)
      cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
            chr(32) & chr(34) & "Warn" & chr(34) & _
            chr(32) & chr(34) & "Master" & chr(34) & _
            chr(32) & chr(34) & "Backup" & chr(34) & _
            chr(32) & chr(34) & "BackupFailed" & chr(34) & _
            chr(32) & chr(34) & "backup path not found" & chr(34)
      rc = shell.Run(cmd, 0, True)
      description = "backup path not found"
      EventLoggerError(description)
      WScript.Quit
    Else
        If Not IsPathWriteable(backup_root) Then
            GlobalLogFile.WriteLine(CStr(Now()) + " --- Exit. There is no Write permission for Backup Path set to " + backup_root)
            cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
               chr(32) & chr(34) & "Warn" & chr(34) & _
               chr(32) & chr(34) & "Master" & chr(34) & _
               chr(32) & chr(34) & "Backup" & chr(34) & _
               chr(32) & chr(34) & "BackupFailed" & chr(34) & _
               chr(32) & chr(34) & "There is no Write permission for Backup Path" & chr(34)
            rc = shell.Run(cmd, 0, True)
            description = "There is no Write permission for Backup Path"
            EventLoggerError(description)
            WScript.Quit
        End If  
    End If
    If InStr(backup_root, " ") <> 0 Then
      GlobalLogFile.WriteLine(CStr(Now()) + " --- " + backup_root + " must not contain spaces")
      cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
            chr(32) & chr(34) & "Warn" & chr(34) & _
            chr(32) & chr(34) & "Master" & chr(34) & _
            chr(32) & chr(34) & "Backup" & chr(34) & _
            chr(32) & chr(34) & "BackupFailed" & chr(34) & _
            chr(32) & chr(34) & "backup path must not contain spaces" & chr(34)
      rc = shell.Run(cmd, 0, True) 
      description = "backup path must not contain spaces"
      EventLoggerError(description)
      WScript.Quit
    End If
End If





backup_root = backup_root & "DSSBackup\"

backup_marker = Sanitize(Now()) 
backup_folder = backup_root & backup_marker

backup_folder = fso.GetAbsolutePathName(backup_folder)
GlobalLogFile.WriteLine(CStr(Now()) + " --- Backing up to: " & backup_folder)

If Right(backup_folder, 1) <> "\" Then
  backup_folder = backup_folder & "\"
End If

ActualBackupFolder = backup_folder
ActualBackupRoot = backup_root

If Left(backup_folder, 2) = "\\" Then
    ' Calculate free space on the destination backup partition 
    Set NetworkObject = CreateObject("WScript.Network")
    Set fso = CreateObject("Scripting.FileSystemObject")
    
    'GlobalLogFile.WriteLine(CStr(Now()) + " --- mount_point = " & mount_point)
    'GlobalLogFile.WriteLine(CStr(Now()) + " --- UserName: " & uncuser & " Password: " & uncpass)
    
    NetworkObject.MapNetworkDrive "", mount_point, False, uncuser, uncpass
    
    first_slash = InStr(3,backup_folder,chr(92))
    GlobalLogFile.WriteLine(CStr(Now()) + " --- first_slash position: " & first_slash)
    second_slash = InStr(CInt(first_slash)+1,backup_folder,chr(92))
    GlobalLogFile.WriteLine(CStr(Now()) + " --- second_slash position: " & second_slash)
    mount_point = Left(mount_point, second_slash)
    GlobalLogFile.WriteLine(CStr(Now()) + " --- mount_point: " & mount_point)
    
    Set Partition = fso.GetDrive(mount_point)
    GetFreeSpaceMB = Partition.FreeSpace / (1024 * 1024)
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Free space available on: " & mount_point & " is: " & GetFreeSpaceMB & " mb")
    
    ' Calculate backup size
    CalculateBackupSize
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Total backup size is: " & TotalBackupSizeMB & " mb")
    
    ' Message when there isn't enough space at destination
    If CDbl(TotalBackupSizeMB)+PARTITION_GRACE > CDbl(GetFreeSpaceMB) Then
            GlobalLogFile.WriteLine(CStr(Now()) + " --- Exit. Not enough free space on: " & mount_point)
            cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
                chr(32) & chr(34) & "Warn" & chr(34) & _
                chr(32) & chr(34) & "Master" & chr(34) & _
                chr(32) & chr(34) & "Backup" & chr(34) & _
                chr(32) & chr(34) & "BackupFailed" & chr(34) & _
                chr(32) & chr(34) & "Disk space is not enough" & chr(34)
            rc = shell.Run(cmd, 0, True)
            description = "Disk space is not enough"
            EventLoggerError(description)
            'MsgBox "Backup size is: " & TotalBackupSizeMB & " megabyte." & vbCrLf & "Free space at: " & mount_point & " is: " & GetFreeSpaceMB & " megabyte." & vbCrlf & " Get more free space or choose different backup location", 0, "Warning"
            WScript.Quit
    End if
    
    On Error Resume Next
        NetworkObject.RemoveNetworkDrive mount_point, True, False
    On Error Goto 0 
    
    

    
    
    
    Set NetworkObject = Nothing


Else
    ' Calculate free space on the destination backup partition 
    Set fso = CreateObject("Scripting.FileSystemObject")
    GlobalLogFile.WriteLine(CStr(Now()) + " --- backup_folder = " & backup_folder)
    Set Partition = fso.GetDrive(Left(backup_folder,2))
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Partition = " & Partition)
    GetFreeSpaceMB = Partition.FreeSpace / (1024 * 1024)
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Free space available on: " & backup_folder & " is: " & GetFreeSpaceMB & " mb")
    
    ' Calculate backup size
    CalculateBackupSize
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Total backup size is: " & TotalBackupSizeMB & " mb")
    
    ' Message when there isn't enough space at destination
    If CDbl(TotalBackupSizeMB)+PARTITION_GRACE > CDbl(GetFreeSpaceMB) Then
        'MsgBox "Backup size is: " & TotalBackupSizeMB & " megabyte." & vbCrLf & "Free space at: " & backup_folder & " is: " & GetFreeSpaceMB & " megabyte." & vbCrlf & " Get more free space or choose different backup location", 0, "Warning"
        cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
            chr(32) & chr(34) & "Warn" & chr(34) & _
            chr(32) & chr(34) & "Master" & chr(34) & _
            chr(32) & chr(34) & "Backup" & chr(34) & _
            chr(32) & chr(34) & "BackupFailed" & chr(34) & _
            chr(32) & chr(34) & "disk space is not enough" & chr(34)
        rc = shell.Run(cmd, 0, True)
        description = "disk space is not enough"
        EventLoggerError(description)
        WScript.Quit
    End if
        
End if 

Set Directory = Nothing





If unc Then
  backup_root = "C:\"
  backup_root = backup_root & "DSSBackup\"
  backup_folder = backup_root & backup_marker
End If

If Right(backup_folder, 1) <> "\" Then
  backup_folder = backup_folder & "\"
End If

If Not fso.FolderExists(backup_root) Then
  fso.CreateFolder(backup_root)
End If
If Not fso.FolderExists(backup_folder) Then
  fso.CreateFolder(backup_folder)
End If

If Not fso.FolderExists(ActualBackupRoot) Then
    fso.CreateFolder(ActualBackupRoot)
End If
If Not fso.FolderExists(ActualBackupFolder) Then
    fso.CreateFolder(ActualBackupFolder)
End If
LogFileName = backup_folder & "DataBackup.log"
Set LogFile = fso.CreateTextFile(LogFileName, True, False)


On Error Resume Next

Err.Clear
'This is where the magic happens
DoBackup
If Err.Number = 0 And fso.FolderExists(ActualBackupFolder) Then
    If fso.GetFolder(ActualBackupFolder).Size > 0 Then
        HandleUNCAndFinalize
        backup_status_before_files_list_succeeded = TRUE
    Else
        backup_status_before_files_list_succeeded = FALSE
    End If
Else
    backup_status_before_files_list_succeeded = FALSE
End If

If backup_status_before_files_list_succeeded = FALSE Then
    description = Err.Description
    If description = "" Then
        If Err.Number = ERROR_DISK_FULL Then
            description = "Disk is full"
        Else
            description = "Runtime Error " + CStr(Err.Number)
        End If
    End If
    EventLoggerError(description)
    GlobalLogFile.WriteLine(CStr(Now()) + " *** BACKUP FAILED - " + description)
    cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
        chr(32) & chr(34) & "Warn" & chr(34) & _
        chr(32) & chr(34) & "Master" & chr(34) & _
        chr(32) & chr(34) & "Backup" & chr(34) & _
        chr(32) & chr(34) & "BackupFailed" & chr(34) & _
        chr(32) & chr(34) & description & chr(34)
    rc = shell.Run(cmd, 0, True) 
    WScript.Quit
End If

Err.Clear
On Error GoTo 0

GlobalLogFile.WriteLine(CStr(Now()) + " *** BACKUP FINISHED ***")
GlobalLogFile.Close
SQLConnection.Close

'Writing BackupPackage Files List
If backup_status_before_files_list_succeeded Then
    BackupPackageFilesList
End If



cmd = """" & installdir & "python.exe"" """ & installdir & "packages\Utils\SystemLogging.pyc""" &_
        chr(32) & chr(34) & "Info" & chr(34) & _
        chr(32) & chr(34) & "Master" & chr(34) & _
        chr(32) & chr(34) & "Backup" & chr(34) & _
        chr(32) & chr(34) & "BackupCompleted" & chr(34)
rc = shell.Run(cmd, 0, True)
WScript.Quit
'---------------------------------------------------------------------------------------------
Sub DoBackup
    BackupCertificates
    BackupPolicies
    BackupFPRepository
    BackupDiscoveryJobs
    BackupResourceRepositoryData
    BackupSQLDB

    If LCase(CStr(ShouldBackupForensics())) = "true" Then
      BackupForensics
    Else
      LogFile.WriteLine("Skipped Forensics Repository backup.")
      GlobalLogFile.WriteLine(CStr(Now()) + " --- Skipped Forensics Repository backup.")
    End If

    BackupMngFiles
    BackupCrawlers
End Sub

Sub BackupCertificates
    LogFile.WriteLine("Backing Up Certificates ...")
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Backing Up Certificates ...")
    CertsFolder = ActualBackupFolder & "certs\"
    fso.CreateFolder(CertsFolder)
    cert_files = Array (_
      "tomcat\conf\keystore\CA\ca.bcfks",_
      "tomcat\conf\keystore\CA\cacerts.bcfks",_
      "tomcat\conf\keystore\tomcat\tomcat.bcfks",_
      "tomcat\conf\keystore\tomcat\tomcat.cer",_
      "ca.cer",_
      "host.key",_
      "host.cer"_
      )
    BackupFiles installdir, CertsFolder, cert_files
    BackupActivemqCerts
    BackupJettyCerts


    cmd = chr(34) & installdir & "CryptoTool.exe" & chr(34) & _
          chr(32) & "-g" & _
          chr(32) & "-k 2" & _
          chr(32) & "-f" & chr(32) & chr(34) & installdir & "keys/" & chr(34)
    Set p = shell.Exec(cmd)
    out = p.StdOut.ReadAll()
    Do While p.Status = 0
      shell.Run "ping -n 1 127.0.0.1", 0, True
    Loop
    If p.ExitCode = 0 Then
      arr = Split(out, chr(13) & chr(10))
      For i = LBound(arr) To UBound(arr)
        If Len(arr(i)) = 32 Then
          cluster_key = arr(i)
        End If
      Next
      cmd = chr(34) & installdir & "CryptoTool.exe" & chr(34) & _
            chr(32) & "-e" & _
            chr(32) & "-k 4" & _
            chr(32) & "-t" & chr(32) & cluster_key
      out = shell.Exec(cmd).StdOut.ReadAll()
      arr = Split(out, chr(13) & chr(10))
      For i = LBound(arr) To UBound(arr)
        If Mid(arr(i), 1, 3) = "{4;" Then
          cluster_key_g_encrypted = arr(i)
        End If
      Next
      Set keyFile = fso.CreateTextFile(CertsFolder & "key.txt", True, False)
      keyFile.WriteLine(cluster_key_g_encrypted)
      keyFile.Close
    Else
      LogFile.WriteLine(CStr(Now()) + " --- Error returned from CryptoTool. RC=" + CStr(p.ExitCode))
      Err.Raise ERROR_GENERAL_FAILURE, "DSS Backup", "Backup of encryption key failed - Make sure the backup is set to run with the same user that installed the application."
    End If
End Sub

Sub BackupPolicies
    LogFile.WriteLine(CStr(Now()) + " --- Backing Up Policies ...")
    BackupFolder installdir + "policies_store", ActualBackupFolder & "policies_backup\policies_store"
    BackupFolder installdir + "policies", ActualBackupFolder & "policies_backup\policies"
    If fso.FolderExists(installdir + "ExternalCommands") Then
        BackupFolder installdir + "ExternalCommands", ActualBackupFolder & "policies_backup\ExternalCommands"
    End If
    config_files = Array("canonizer.config.xml", "extractor.config.xml", "?extractorlinux.config.xml")
    BackupFiles installdir, ActualBackupFolder & "policies_backup\", config_files
    GeneratePath(ActualBackupFolder & "policies_backup\tomcat\wbsnData")
    fso.CopyFile installdir & "tomcat\wbsnData\policy-templates.properties", ActualBackupFolder & "policies_backup\tomcat\wbsnData\policy-templates.properties"
    fso.CopyFile installdir & "tomcat\wbsnData\policy-templates-in-process.properties", ActualBackupFolder & "policies_backup\tomcat\wbsnData\policy-templates-in-process.properties"
    fso.CopyFile installdir & "tomcat\wbsnData\policy-templates-custom.properties", ActualBackupFolder & "policies_backup\tomcat\wbsnData\policy-templates-custom.properties"
    fso.CopyFile installdir & "tomcat\wbsnData\policy-templates-custom-in-process.properties", ActualBackupFolder & "policies_backup\tomcat\wbsnData\policy-templates-custom-in-process.properties"
    ClearReadOnlyAttribute(ActualBackupFolder & "policies_backup\")
    If fso.FolderExists(ActualBackupFolder & "policies_backup\" & "policies_store\policies\templates\data_in_motion\policies") Then
      Set folder = fso.GetFolder(ActualBackupFolder & "policies_backup\" & "policies_store\policies\templates\data_in_motion\policies")
      RecursiveFlattenFiles folder, folder.Path + "\"
    End If
    If fso.FolderExists(ActualBackupFolder & "policies_backup\" & "policies_store\policies\templates\discovery\policies") Then
      Set folder = fso.GetFolder(ActualBackupFolder & "policies_backup\" & "policies_store\policies\templates\discovery\policies")
      RecursiveFlattenFiles folder, folder.Path + "\"
    End If
End Sub

Sub ClearReadOnlyAttribute(foldername)
  Set folder = fso.GetFolder(foldername)
  Set subfolders = folder.SubFolders
  For Each subfolder In subfolders
    ClearReadOnlyAttribute(subfolder)
    If subfolder.Files.Count > 0 Then
      Set sf = fso.GetFolder(subfolder)
      Set sff = sf.Files
      For Each sfff In sff
        Set f = fso.GetFile(sfff)
        If (f.attributes And 1) Then
          f.attributes = f.attributes - 1
        End If
      Next
    End If
  Next
End Sub

Sub RecursiveFlattenFiles(source, target)
  For Each subfolder In source.SubFolders
    RecursiveFlattenFiles subfolder, target
    subfolder.Delete True
  Next
  If source.Path = target Then
    Exit Sub
  End If
  For Each f In source.Files
    If target <> Mid(f.Path, 1, Len(f.Path) - Len(f.Name)) Then
      targetfile = target & f.Name
      If fso.FileExists(targetfile) Then
        fso.DeleteFile targetfile
      End If
      f.Move target
    End If
  Next
End Sub

Sub BackupFPRepository
    LogFile.WriteLine("Backing Up PreciseID DB (including FPNE) ...")
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Backing Up PreciseID DB ...")
    BackupPreciseID_DB = backup_folder & "PreciseID_DB\"
    BackupFPNE = BackupPreciseID_DB & "FPNE\"
    fso.CreateFolder(BackupPreciseID_DB)
    fso.CreateFolder(BackupFPNE)
    cmd = chr(34) & installdir & "FPRUtils.exe" & chr(34) & _
          chr(32) & "-o" & chr(32) & "WriteLockExclusive" & _
          chr(32) & "-p" & chr(32) & BackupPreciseID_DB & _
          chr(32) & "-f" & chr(32) & BackupFPNE
    rc = shell.Run(cmd, 0, True)
    If rc <> 0 Then
        LogFile.WriteLine(CStr(Now()) + " --- Error returned from FPRUtils. RC=" + CStr(rc))
        Err.Raise ERROR_GENERAL_FAILURE, "DSS Backup", "Backup of PreciseID DB failed"
    End If
    If backup_folder <> ActualBackupFolder Then
        BackupFolder BackupPreciseID_DB, ActualBackupFolder & "PreciseID_DB\"
        fso.DeleteFolder Mid(BackupPreciseID_DB, 1, Len(BackupPreciseID_DB) - 1)
    End If
End Sub

Sub BackupDiscoveryJobs()
    LogFile.WriteLine("Backing Up Discovery Jobs...")
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Discovery Jobs ...")
    BackupDiscoveryJobsFolder = ActualBackupFolder & "DiscoveryJobs\"
    fso.CreateFolder(BackupDiscoveryJobsFolder)
    
    BackupFolder installdir + "DiscoveryJobs", BackupDiscoveryJobsFolder
End Sub

Sub BackupResourceRepositoryData()
    If fso.FolderExists(installdir + "ResourceRepositoryCache") Then
        LogFile.WriteLine("Backing Up Resource Repository Cache...")
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Resource Repository Cache ...")
        BackupResourceRepositoryCacheFolder = ActualBackupFolder & "ResourceRepositoryCache\"
        fso.CreateFolder(BackupResourceRepositoryCacheFolder)
        
        BackupFolder installdir + "ResourceRepositoryCache", BackupResourceRepositoryCacheFolder
    Else
        LogFile.WriteLine("Resource Repository Cache not exists")
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Resource Repository Cache - Not Exists.")
    End If
    
    If fso.FolderExists(installdir + "tomcat\wbsnData\usersRepo\cachedXmls") Then
        LogFile.WriteLine("Backing Up Resource Repository cachedXmls...")
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Resource Repository cachedXmls ...")
        BackupResourceRepositoryCachedXmlsFolder = ActualBackupFolder & "ResourceRepositoryCachedXmls\"
        fso.CreateFolder(BackupResourceRepositoryCachedXmlsFolder)
        
        BackupFolder installdir + "tomcat\wbsnData\usersRepo\cachedXmls", BackupResourceRepositoryCachedXmlsFolder
    End If
End Sub

Sub BackupActivemqCerts()
    If fso.FolderExists(installdir + "MessageBroker\conf\keystore\activemq") Then
        LogFile.WriteLine("Backing Up Activemq Certificates...")
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Activemq Certificates ...")
        BackupActivemqCertsFolder = ActualBackupFolder & "activemq_cert\"
'       MsgBox "BackupActivemqCertsFolder = " & BackupActivemqCertsFolder
        fso.CreateFolder(BackupActivemqCertsFolder)
        
        BackupFolder installdir + "MessageBroker\conf\keystore\activemq", BackupActivemqCertsFolder
    Else
        LogFile.WriteLine("Activemq Certificates not exists")
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Activemq Certificates - Not Exists.")
    End If
End Sub

Sub BackupJettyCerts()
    If fso.FolderExists(installdir + "Data-Batch-Server\etc\keystore\jetty") Then
        LogFile.WriteLine("Backing Up Jetty Certificates...")
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Jetty Certificates ...")
        BackupJettyCertsFolder = ActualBackupFolder & "jetty_cert\"
        fso.CreateFolder(BackupJettyCertsFolder)
        
        BackupFolder installdir + "Data-Batch-Server\etc\keystore\jetty", BackupJettyCertsFolder
    Else
        LogFile.WriteLine("Jetty Certificates not exists")
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Jetty Certificates - Not Exists.")
    End If
End Sub

Sub BackupSQLDB
    LogFile.WriteLine("Backing Up SQL DB ...")
    GlobalLogFile.WriteLine(CStr(Now()) + " --- Backing Up SQL DB ...")
    fso.CreateFolder(ActualBackupFolder & "MngDB")
    prevTimeout = SQLConnection.CommandTimeout
    SQLConnection.CommandTimeout = 0
    Err.Clear
    On Error Resume Next
    SQLConnection.Execute("BACKUP DATABASE ["& SQLDBName &"] TO DISK='"& _
                            ActualBackupFolder & "MngDB\" & SQLDBName & ".bak'")
    If Err.Number <> 0 Then
        On Error Goto 0
        useSharedLocation = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\DB_ARCHIVE\USE_SHARE")
        If useSharedLocation <> "" Then
            GlobalLogFile.WriteLine(CStr(Now()) + " Warning: Backup is set to remote location, Switching to backup through Temporary File Location share")
            LogFile.WriteLine(CStr(Now()) + " Warning: Backup is set to remote location, Switching to backup through Temporary File Location share")
            db_path = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\DB_ARCHIVE\LOCAL_FOLDER")
            our_path = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\DB_ARCHIVE\SHARED_FOLDER")
            If Right(db_path, 1) <> "\" Then
                db_path = db_path & "\"
            End If
            If Right(our_path, 1) <> "\" Then
                our_path = our_path & "\"
            End If
            If Not fso.FolderExists(our_path) Then
                username = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\DB_ARCHIVE\USERNAME")
                pwd_enc = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\DB_ARCHIVE\PASSWORD")
                cmd = "CryptoTool.exe -d -t """ & pwd_enc & """"
                Set objExec = shl.Exec(cmd)
                pwd = objExec.stdOut.ReadLine()
                
                
                cmd_set = "NET USE" & _
                          chr(32) & """" & our_path & """" & _
                          chr(32) & "/USER:" & username & _
                          chr(32) & pwd
                rc = shell.Run(cmd_set, 0, True)
                If rc <> 0 Then
                  LogFile.WriteLine(CStr(Now()) + " --- " + "network map to " & our_path & " exited with code " & rc)
                End If
            End If
        Elseif backup_folder <> ActualBackupFolder Then
            GlobalLogFile.WriteLine(CStr(Now()) + " Warning: Backup directly to UNC failed, backup up through local disk")
            LogFile.WriteLine(CStr(Now()) + " Warning: Backup directly to UNC failed, backup up through local disk")
            db_path = backup_folder
            our_path = backup_folder
        End If
        Err.Clear
        On Error Resume Next
        fso.CreateFolder(our_path & "MngDB")
        SQLConnection.Execute("BACKUP DATABASE ["& SQLDBName &"] TO DISK='"& _
                            db_path & "MngDB\" & SQLDBName & ".bak'")
        If Err.Number <> 0 Then
            ErrNumber = Err.Number
            ErrDescription = Err.Description
            On Error Goto 0
            GlobalLogFile.WriteLine(CStr(Now()) + " Error: SQL Server backup failed: " & ErrDescription)
            LogFile.WriteLine(CStr(Now()) + " Error: SQL Server backup failed: " & ErrDescription)
            If LCase(Properties.Item("EIPSettings.LogDB.External")) <> "false" Then
                Err.Raise ERROR_GENERAL_FAILURE, "DSS Backup", "a temporary file location was not configured in the installer, or it was configured incorrectly."
            Else
                Err.Raise ErrNumber, "DSS Backup", ErrDescription
            End If
        End If
        BackupFolder our_path & "MngDB\", ActualBackupFolder & "MngDB\"
        fso.DeleteFolder our_path & "MngDB"
    End If
    On Error Goto 0
    SQLConnection.CommandTimeout = prevTimeout
End Sub

Function ShouldBackupForensics()
    ShouldBackupForensics = GetConfigParam("INCLUDE_INCIDENT_FORENSICS")
End Function

Sub BackupForensics
  LogFile.WriteLine("Backing Up Archive ...")
  GlobalLogFile.WriteLine(CStr(Now()) + " --- Backing Up Forensics Repository ...")

  ArchiveFolderName = Replace(GetForensicsParam("FR_REPOSITORY_URL"), "/", "\")
  LogFile.WriteLine("Forensics Path is " + ArchiveFolderName)
  ForensicsType = GetForensicsParam("FR_ACCOUNT_TYPE")
  LogFile.WriteLine("Forensics Type is " + ForensicsType)

  If ForensicsType = "SPECIFIED_ACCOUNT" Then
    ForensicsDomain = GetForensicsParam("FR_LOCAL_DOMAIN")
    ForensicsUser = GetForensicsParam("FR_LOCAL_USERNAME")
    frpass = GetForensicsParam("FR_LOCAL_PASSWORD")
    
    
    passlocfile =  temp & "pass.txt"
    cmd = "CryptoTool.exe" & _
    chr(32) & "-d" & _
    chr(32) & "-t" & chr(32) & frpass & _
    chr(32) & "--outputfile " & chr(34) & passlocfile & chr(34)
    
    rc = shell.run(cmd, 0, true)
    if rc = 0 Then
        Set stream = CreateObject("ADODB.Stream")
        stream.Open
        stream.Type = 2 'text
        stream.Charset = "Unicode"
        stream.LoadFromFile passlocfile
        frpass = stream.ReadText
        stream.Close
    else
        frpass = ""
        LogFile.WriteLine("Error: Unable to read the account password to the forensics network location")
    End if
    
    If fso.FileExists(passlocfile) Then
        fso.DeleteFile (passlocfile)
    End if

    fruser = ForensicsDomain + "\" + ForensicsUser
    LogFile.WriteLine("Forensics Identity is " + fruser)
    cmd_set = "NET USE" & _
              chr(32) & ArchiveFolderName & _
              chr(32) & "/USER:" & fruser & _
              chr(32) & frpass            
    rc = shell.Run(cmd_set, 0, True) 
    If rc <> 0 Then
      LogFile.WriteLine("network map to" & chr(32) & ArchiveFolderName & chr(32) & "exited with code" & chr(32) & rc)
    End If
  End If
  ArchiveBackupFolderName = ActualBackupFolder & "forensics_repository"
  BackupFolder ArchiveFolderName, ArchiveBackupFolderName
  If ForensicsType = "SPECIFIED_ACCOUNT" Then
    cmd_del = "NET USE" & _
              chr(32) & ArchiveFolderName & _
              chr(32) & "/DELETE"
    rc = shell.Run(cmd_del, 0, True)
  End If
  
  GetCurrentForensicId
End Sub


Sub GetCurrentForensicId
    forensicsRepoFile = installdir & "tomcat\conf\Catalina\localhost\forensics-repo.xml"

    Set objDOM = CreateObject("Microsoft.XMLDOM")
    objDOM.Async = False
    objDOM.ValidateOnParse = False
    objDOM.ResolveExternals = False
    objDOM.PreserveWhiteSpace = False

    If objDOM.Load(forensicsRepoFile) Then
        Set objNode = objDOM.DocumentElement
        Set EnvironmentNode=objNode.selectSingleNode("//Context/Environment[@name='wbsn/java-fw/mgmt/instance-guid']")
        CurrentForensicsId = EnvironmentNode.GetAttribute("value")
        instanceArr = split(CurrentForensicsId,"-")
        instaceGuid =  replace(instanceArr(4),"}","")
    End If

    BackupRotate(ActualBackupRoot)
    forensicsRepo_id = ActualBackupFolder + "CurrentForensicsRepo.txt"
    Set forensicsRepo_file = fso.CreateTextFile(forensicsRepo_id, True, False)
    forensicsRepo_file.WriteLine(instaceGuid)
    forensicsRepo_file.Close
End Sub

Sub BackupMngFiles
    extra_files = Array(    "?tomcat\wbsnData\backups\ep-profile-keys.zip",_
                "?tomcat\wbsnData\subscription.xml",_
                "apache\conf\wbsn-pairing-map.txt"_
            )
    BackupFiles installdir, ActualBackupFolder, extra_files

    GeneratePath(ActualBackupFolder + "forensics_repository\control")
    fso.CopyFile installdir + "tomcat\wbsnData\forensics-repo\control-record.ser", ActualBackupFolder + "forensics_repository\control\"
End Sub

Sub BackupCrawlers
    ''' Backup the various fingerprint & discovery crawlers...
    fso.CreateFolder(ActualBackupFolder & "crawlers")
    
    ServerCrawlersURLQuery = _
        "SELECT " & _
        "   a.id, " & _
        "   'https://' +  a.ip + ':' + b.port + '/no_ssl/localhost:9797/Configuration' " & _
        "FROM " & _
        "   WS_SM_Site_Elements AS a LEFT OUTER JOIN WS_SM_Site_Elements as b " & _
        "ON a.PARENT_ID = b.ID " & _
        "WHERE " & _
        "   a.Element_Type = 'AGENT_DISCOVERY_WIN' AND a.PARENT_ID is not null; " 
    
    StandAloneCrawlersURLQuery = _
        "SELECT " & _
        "   id, " & _
        "   'http://' +  ip + ':9797/Configuration' " & _
        "FROM " & _
        "   WS_SM_Site_Elements " & _
        "WHERE " & _
        "   Element_Type = 'AGENT_DISCOVERY_WIN' AND PARENT_ID is null; " 
    
    BackupCrawlersByQuery ServerCrawlersURLQuery
    BackupCrawlersByQuery StandAloneCrawlersURLQuery
End Sub

Sub BackupCrawlersByQuery(query)
    Set recordSet = SQLConnection.Execute(query)
    Do While recordSet.EOF <> True
        ID = recordSet(0)
        URL = recordSet(1)
        LogFile.WriteLine("Backing up Discovery & Fingerprint Crawler ID " & ID & _
            " via URL: " & URL)
        cmd = """" & installdir & "python.exe"" """ & installdir & "packages\services\WorkSchedulerWebServiceClient.pyc"" " &_
                "--configURL " & URL & " " & _
                "--configure Backup " & _
                "--file """ & ActualBackupFolder & "crawlers\" & ID & ".tgz"""
        rc = shell.Run(cmd, 0, True)
        If rc <> 0 Then
            LogFile.WriteLine("Backup failed. Return value " & rc)
            Err.Raise ERROR_GENERAL_FAILURE, "DSS Backup", "Backup of crawler on " + URL + " failed"
        End If
        recordSet.MoveNext
    Loop
    recordSet.Close
End Sub

Sub HandleUNCAndFinalize
    BackupRotate(ActualBackupRoot)
    fqdn = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\FQDN")
    ipaddress = shell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\" & Wow6432Node & "Websense\Data Security\IPADDRESS")
    backup_id = ActualBackupFolder + "backup.txt"
    
    query = "SELECT @@MICROSOFTVERSION  / POWER(2,24)"
    Set recordSet = SQLConnection.Execute(query)
    
    Set backup_file = fso.CreateTextFile(backup_id, True, False)
    backup_file.WriteLine(version)
    backup_file.WriteLine(fqdn)
    backup_file.WriteLine(ipaddress)
    backup_file.WriteLine("mssql_version = " & recordSet(0))
    recordSet.Close
    backup_file.Close
    LogFile.WriteLine("*** BACKUP FINISHED ***")
    LogFile.Close
    If backup_folder <> ActualBackupFolder Then
        Set backup_folder_object = fso.GetFolder(backup_folder)
        For Each file in backup_folder_object.Files
          fso.CopyFile file.Path, ActualBackupFolder
        Next
        Set backup_folder_object = Nothing
        fso.DeleteFolder Mid(backup_folder, 1, Len(backup_folder) - 1)
        Set backup_root_object = fso.GetFolder(backup_root)
        fso.DeleteFolder backup_root_object
    End If
'   If unc = True and uncuser <> "" Then
'   cmd_del = "NET USE" & _
'             chr(32) & mount_point & _
'             chr(32) & "/DELETE"
'   rc = shell.Run(cmd_del, 0, True)
'   End If
End Sub

Function BackupFiles(sFolder, dFolder, files)
    For Each file In files
      must_exist = True
      If Left(file, 1) = "?" Then
          must_exist = False
          file = Mid(file,2)
      End If
      sourcePath = sFolder & file
      If fso.FileExists(sourcePath) Then
        LogFile.WriteLine(sourcePath)
        fso.CopyFile sourcePath, dFolder
      Else
        If must_exist Then
        LogFile.WriteLine("file not found:" & sourcePath)
        Err.Raise ERROR_FILE_NOT_FOUND, "DSS Backup", "File Not Found: " + sourcePath
        End If
      End If
    Next
End Function

Function BackupFolder(sFolder, dFolder)
  Set sh = fso.GetFolder(sFolder)
  For Each sf in sh.SubFolders
    target = Replace(LCase(sf.Path), LCase(sFolder), LCase(dFolder))
    GeneratePath(target)
    BackupFolder sf, target
  Next
  ii = 1
  cc = sh.Files.Count
  On Error Resume Next
  For Each f in sh.Files
    rr = ii Mod 10
    fso.CopyFile f.Path, Replace(LCase(f.Path), LCase(sFolder), LCase(dFolder))
    If Err.Number <> 0 Then
        If Err.Number = ERROR_FILE_NOT_FOUND Then
            LogFile.WriteLine("Warning: Failed to copy " & f.Name & ". Error: " & Err.Description)
            Err.Clear
        Else
            LogFile.WriteLine("Error: Failed to copy " & f.Name & ". Error: " & Err.Description)
            Err.Raise Err.Number
        End If
    End If
    If ii = 1 Or rr = 0 Or ii = cc Then
      LogFile.WriteLine(ii & " of " & cc & " - " & f.Name)
    End If
    ii = ii + 1
  Next
  On Error Goto 0
End Function

Function GeneratePath(pFolderPath)
  GeneratePath = False
  If Not fso.FolderExists(pFolderPath) Then
    If GeneratePath(fso.GetParentFolderName(pFolderPath)) Then
      GeneratePath = True
      fso.CreateFolder(pFolderPath)
    End If
  Else
    GeneratePath = True
  End If
End Function

Function BackupRotate(root)
  Set br = fso.GetFolder(root)
  If br.SubFolders.Count > backup_max Then
    GlobalLogFile.WriteLine("Reached maximum number of backups:" & chr(32) & backup_max)
  End If
  Do While br.SubFolders.Count > backup_max
    dsec_max = 0
    For Each brf In br.SubFolders
      dsec = DateDiff("s", brf.DateCreated, Now)
      If dsec > dsec_max Then
        dsec_max = dsec
        to_delete = brf.Name
      End If
    Next
    delme = fso.GetFolder(root & to_delete)
    GlobalLogFile.WriteLine("Removing oldest backup:" & chr(32) & delme)
    fso.DeleteFolder delme, True
    If fso.FolderExists(root & to_delete) Then
    Err.Raise ERROR_GENERAL_FAILURE, "DSS Backup", "Failed to delete old backup folder " & root & to_delete
    End If
  Loop
End Function

Function GetForensicsParam(ParamName)
  GetForensicsParam = GetDBParamByQuery("SELECT STR_VALUE FROM WS_SM_CONFIGURATION_PROPERTIES WHERE NAME = '" + ParamName + "';")
End Function

Function GetConfigParam(ParamName)
  GetConfigParam = GetDBParamByQuery("SELECT VALUE FROM PA_CONFIG_PROPERTIES WHERE GROUP_NAME = 'BACKUP_AND_RESTORE' AND NAME = '" + ParamName + "';")
End Function

Function GetDBParamByQuery(query)
  'WScript.Echo "Running Query: " & query
  Set recordSet  = SQLConnection.Execute(query)
  If Not recordSet.EOF Then
    GetDBParamByQuery = RTrim(recordSet(0))
  Else
    GetDBParamByQuery = ""
  End If
  recordSet.Close
  If VarType(GetDBParamByQuery) = VarType(Null) Then
      GetDBParamByQuery = ""
  End If
End Function

Function Sanitize(x)
    For idx = 1 to Len(x)
        ch = Mid(x, idx, 1)
        If AscW(ch) >= AscW("0") And AscW(ch) <= AscW("9") Then
            sanitized = sanitized & ch
        Elseif AscW(ch) >= AscW("a") And AscW(ch) <= AscW("z") Then
            sanitized = sanitized & ch
        Elseif AscW(ch) >= AscW("A") And AscW(ch) <= AscW("Z") Then
            sanitized = sanitized & ch
        Else
            sanitized = sanitized & "-"
        End If
    Next
    Sanitize = sanitized
End Function

Sub RecursiveXMLToProps(Element, PropertyName, Result)
    For Each child In Element.childNodes
        If child.nodeType = 3 or child.nodeType = 4 Then 'Text Node
            value = Trim(child.nodeValue)
            If value <> "" Then
                    Result.Add PropertyName, value
            End If
        Elseif child.nodeType = 1 Then 'Element
            RecursiveXMLToProps child, PropertyName + "." + child.nodeName, Result
        End If
    Next
End Sub


Sub CalculateBackupSize
    
    ' Backing up Certificates
    cert_files = Array (_
      "tomcat\conf\keystore\CA\ca.bcfks",_
      "tomcat\conf\keystore\CA\cacerts.bcfks",_
      "tomcat\conf\keystore\tomcat\tomcat.bcfks",_
      "tomcat\conf\keystore\tomcat\tomcat.cer",_
      "ca.cer",_
      "host.key",_
      "host.cer"_
      )
    CalculateFilesSize installdir, Cert_files 
        
    ' Backing up Activemq certificates
    CalculateFolderSize installdir, "MessageBroker\conf\keystore\activemq"
        
    ' Backing up Jetty Certificates
    CalculateFolderSize installdir, "Data-Batch-Server\etc\keystore\jetty"
        
    ' Backing Up Policies
    CalculateFolderSize installdir, "policies"
    CalculateFolderSize installdir, "policies_store"
    CalculateFolderSize installdir, "ExternalCommands"
    cert_files = Array("canonizer.config.xml", "extractor.config.xml", "extractorlinux.config.xml")
    CalculateFilesSize installdir, Cert_files 
    CalculateFolderSize installdir, "policies_backup"
        
    'CalculateBackupFPRepository
    CalculateFolderSize installdir, "PreciseID DB"
        
    'CalculateBackupDiscoveryJobs
    CalculateFolderSize installdir, "DiscoveryJobs"
        
    'CalculateBackupResourceRepositoryData
    CalculateFolderSize installdir, "ResourceRepositoryCache"
        
    CalculateFolderSize installdir, "tomcat\wbsnData\usersRepo\cachedXmls"
        
    'Get database size on disk
    CalculateBackupSQLDB
        
    

End Sub



Function CalculateFilesSize (sFolder, files)


For Each file In files
    sourcePath = sFolder & file
        
    If FSO.FileExists(sourcePath ) Then
        Set objFile = FSO.GetFile(sourcePath)
        TotalBackupSizeMB = TotalBackupSizeMB + (objFile.Size / (1024 * 1024)) 
    Else
        GlobalLogFile.WriteLine(CStr(Now()) + " --- File not found: " & sourcePath)
    End If

Next


End Function



Function CalculateFolderSize (sInstallFolder, sFolder)

    sFolderFullPath = sInstallFolder & sFolder
        
    If FSO.FolderExists(sFolderFullPath ) Then
        Set objFolder = FSO.GetFolder(sFolderFullPath)
        TotalBackupSizeMB = TotalBackupSizeMB + (objFolder.Size /  (1024 * 1024)) 
                
    Else
        GlobalLogFile.WriteLine(CStr(Now()) + " --- Folder not found: " & sFolderFullPath)
    End If


End Function


Function CalculateBackupSQLDB

    Const adOpenStatic = 3
    Const adLockOptimistic = 3

    'Set XML = CreateObject("Microsoft.XMLDOM")

    'XML.Load(ConfigFile)
    'Set Root = XML.documentElement
    'Set Properties = CreateObject("Scripting.Dictionary")
    'RecursiveXMLToProps Root, Root.nodeName, Properties
    'Set Root = Nothing
    'Set XML = Nothing

    Set objRecordSet = CreateObject("ADODB.Recordset")

    objRecordSet.Open "SELECT d.name, ROUND(SUM(mf.size) * 8 / 1024, 0) Size_MBs FROM sys.master_files mf INNER JOIN sys.databases d ON d.database_id = mf.database_id WHERE d.database_id > 4 AND d.name='" & SQLDBName & "' AND type_desc <> 'Log' GROUP BY d.name", _
        SQLConnection, adOpenStatic, adLockOptimistic

    While NOT objRecordSet.EOF
        For Each field In objRecordSet.Fields
            dbsize = field.Value
        next
        objRecordSet.MoveNext
    Wend
    TotalBackupSizeMB = TotalBackupSizeMB + dbsize
End Function

Sub BackupPackageFilesList
    backup_files_list_fn = ActualBackupFolder + "dss_backup_files_list.txt"
    Set backup_files_list = fso.CreateTextFile(backup_files_list_fn, True, False)
    objStartFolder = ActualBackupFolder

    Set objFolder = fso.GetFolder(objStartFolder)
    Set colFiles = objFolder.Files
    For Each objFile in colFiles
        If objFile.Name <> "dss_backup_files_list.txt" Then
            file_name_and_size =  Replace(objFile.Path, ActualBackupFolder, "") & "" & CDbl(objFile.size)
            backup_files_list.WriteLine(file_name_and_size) 
        End If  
    Next
    GetSubfolders fso.GetFolder(objStartFolder), backup_files_list
'   If fso.FolderExists(ActualBackupFolder) Then
        If fso.FileExists(backup_files_list_fn) Then 
            If fso.GetFile(backup_files_list_fn).Size = 0 Then
                EventLoggerError(description)
                fso.DeleteFolder(Left(ActualBackupFolder, (Len(ActualBackupFolder)-1)))
            Else
                backup_files_list.Close
                cmd = "EventCreate /T INFORMATION /L Application /ID 264 /SO ""FORCEPOINT AP-DATA"" /D ""System has been backed up successfully"""
                rc = shell.Run(cmd, 0, True)
            End If
        Else
            EventLoggerError(description)
            fso.DeleteFolder(Left(ActualBackupFolder, (Len(ActualBackupFolder)-1)))
        End If
'   Else
'       cmd = "EventCreate /T ERROR /L Application /ID 264 /SO ""FORCEPOINT AP-DATA"" /D ""BACKUP FAILED - " & description & """"
'   End If
    
    If unc = True and uncuser <> "" Then
    cmd_del = "NET USE" & _
              chr(32) & mount_point & _
              chr(32) & "/DELETE"
    rc = shell.Run(cmd_del, 0, True)
    End If
End Sub



Sub GetSubFolders(Folder, backup_files_list)
    For Each Subfolder in Folder.SubFolders
        Set objFolder = fso.GetFolder(Subfolder.Path)
        Set colFiles = objFolder.Files
        For Each objFile in colFiles
            file_name_and_size = Replace(objFile.Path, ActualBackupFolder, "") & "" & objFile.size
            backup_files_list.WriteLine(file_name_and_size)
        Next
        GetSubFolders Subfolder, backup_files_list
    Next
End Sub

Sub EventLoggerError(description)
    cmd = "EventCreate /T ERROR /L Application /ID 264 /SO ""FORCEPOINT AP-DATA"" /D ""BACKUP FAILED - " & description & """"
    rc = shell.Run(cmd, 0, True)
End Sub

Function IsPathWriteable(path)
    Dim temp_path
    'Set fso = CreateObject("Scripting.FileSystemObject")
    temp_path = path & "\" & fso.GetTempName() & ".tmp"    
    On Error Resume Next
        fso.CreateTextFile temp_path
        IsPathWriteable = Err.Number = 0
        fso.DeleteFile temp_path
    On Error Goto 0    
End Function