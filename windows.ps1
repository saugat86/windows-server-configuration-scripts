Function NetTest{

 $test=Get-DnsClientServerAddress -AddressFamily ipv4
 $notempty=""
 foreach($result in $test){
  if($result.ServerAddresses -ne ""){$notempty=$result.ServerAddresses}
 }

 if($notempty -ne ""){
  $testNC=Test-NetConnection -ComputerName $notempty[0] -InformationLevel Quiet
 }
 else{
  Write-Host "No DNS Server assigned. Does the machine have a network connection?"
 }

 return $testNC
}

$option='X'
$global:path = "C:\ServerSoftware"
$global:mediapath="C:\ServerSoftware\SetupMedia"
$global:instanceName="MYDB"
$global:instancedDir="C:\MSSQL"
$global:phpinstallpath = "C:\Program Files\PHP"
$global:phpVer = "8.1"
$global:newDrive = "C:\"
$global:newDir = "IIS-Sites\NewSite"
$global:copyFolder = "D:\SourceDir"
$global:AppPool = "Website-AppPool"
$global:handlerName = "PHP via FastCGI"
$global:CertLocation = "D:\MyCerts\cert.pfx"
$global:SQLServer = "localhost\$instanceName"
$global:fileLocation = "D:\SourceDir\source.sql"
$global:SiteName = "NewSite"
$PortNumber = "443"

while ($option -ne 'Y' -and $option -ne 'N'){
 $option = Read-Host -Prompt "Do you wish do run the first-time configuration? (Y/N)."

 if($option -eq 'Y'){
  Write-Host "Setting Timezone."
  Set-TimeZone -Name "Eastern Standard Time"
  Write-Host "Removing Internet Explorer."
  Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 –Online -NoRestart
  Write-Host "Removing Windows Media Player."  
  Disable-WindowsOptionalFeature -FeatureName WindowsMediaPlayer –Online -NoRestart

  Write-Host "Turning off Server manager autostart."
  Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask -Verbose
 }
}

NetTest

Write-Host "Testing software staging path $path"
if(Test-Path -Path $path){
      Write-Host "Folder already exists."
}
else{
      New-Item -Path $path -ItemType Directory
      Write-Host "Folder created successfully."
}

set-location $path

#Automate Feature Install

$option ='';

while ($option -ne 'Q'){
 Write-Host "Please enter an option."
 Write-Host ""
 Write-Host " 1 - IIS"
 Write-Host " 2 - MSSQL 2022"
 Write-Host " 3 - PHP"
 Write-Host " 4 - PHP SQLSRV - PHP Driver for MSSQL (PHP Req'd)"
 Write-Host " 5 - Microsoft SQL Server Management Studio"
 Write-Host " 6 - Install NuGet package provider"
 Write-Host " 7 - Install IISAdministration powershell module (NuGet Req'd)"
 Write-Host " 8 - Remove Default IIS Website (IISAdministration Req'd)"
 Write-Host " 9 - Create New Website (IISAdministration Req'd)"
 Write-Host "10 - Add PHP Handler Mappings to IIS (PHP & IIS Req'd)"
 Write-Host "11 - Install SqlServer powershell module (NuGet Req'd)"
 Write-Host "12 - Import a PFX Certificate into the Local Machine Cert Store"
 Write-Host "13 - Execute a SQL Server .SQL file in SQL Server (SqlServer Module Req'd)"
 Write-Host "14 - Enable SSL on IIS Website (IISAdministration, Imported PFX Certificate Req'd)"
 Write-Host "15 - Create a Self-Signed Certificate for SQL Always Encrypted (for use in Dev only)"
 
 Write-Host "Q - Quit"

 $option = Read-Host

 if($option -eq 1){
  Install-WindowsFeature -name Web-Server -IncludeManagementTools
 }

 if($option -eq 2){

  NetTest

  Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/p/?linkid=2216019&clcid=0x409&culture=en-us&country=us' -OutFile ./SQL2022-SSEI-Expr.exe

  $temp = Read-Host -Prompt "Please enter where you wish to download the install media (Ex: $mediapath )"

  if($temp -eq ''){$mediapath=$mediapath;}
  else {$mediapath=$temp;}

  $temp = Read-Host -Prompt "Please enter the intended instance name (Ex: $instanceName)"

  if($temp -eq ''){$instanceName=$instanceName;}
  else {$instanceName=$temp;}

  $temp = Read-Host -Prompt "Please enter the instance directory (Ex: $instancedDir )"

  if($temp -eq ''){$instancedDir=$instancedDir;}
  else {$instancedDir=$temp;}

  $pass = Read-Host -Prompt "Enter the SQL System Administrator (SA) password"

  set-location $path

  $ConfigExists=Test-Path -Path "$path\Configuration.ini"

  if($ConfigExists -eq $True){Remove-Item -Path "$path\Configuration.ini"}

  Add-Content "$path\Configuration.ini" ";SQL Server 2022 Configuration File"
  Add-Content "$path\Configuration.ini" "[OPTIONS]"
  Add-Content "$path\Configuration.ini" "; Specifies a Setup work flow, like INSTALL, UNINSTALL, or UPGRADE. This is a required parameter. "
  Add-Content "$path\Configuration.ini" "ACTION=`"Install`""
  Add-Content "$path\Configuration.ini" "; Use the /ENU parameter to install the English version of SQL Server on your localized Windows operating system. "
  Add-Content "$path\Configuration.ini" "ENU=`"True`""
  Add-Content "$path\Configuration.ini" "; Setup roles install SQL Server in a predetermined configuration. "
  Add-Content "$path\Configuration.ini" "ROLE=`"AllFeatures_WithDefaults`""
  Add-Content "$path\Configuration.ini" "; Indicates whether the supplied product key is covered by Service Assurance. "
  Add-Content "$path\Configuration.ini" "PRODUCTCOVEREDBYSA=`"False`""
  Add-Content "$path\Configuration.ini" "; Specifies that SQL Server Setup should not display the privacy statement when ran from the command line. "
  Add-Content "$path\Configuration.ini" "SUPPRESSPRIVACYSTATEMENTNOTICE=`"False`""
  Add-Content "$path\Configuration.ini" "; Setup will not display any user interface. "
  Add-Content "$path\Configuration.ini" "QUIET=`"False`""
  Add-Content "$path\Configuration.ini" "; Setup will display progress only, without any user interaction. "
  Add-Content "$path\Configuration.ini" "QUIETSIMPLE=`"False`""
  Add-Content "$path\Configuration.ini" "; Parameter that controls the user interface behavior. Valid values are Normal for the full UI,AutoAdvance for a simplied UI, and EnableUIOnServerCore for bypassing Server Core setup GUI block. "
  Add-Content "$path\Configuration.ini" ";UIMODE=`"AutoAdvance`""
  Add-Content "$path\Configuration.ini" "; Specify whether SQL Server Setup should discover and include product updates. The valid values are True and False or 1 and 0. By default SQL Server Setup will include updates that are found. "
  Add-Content "$path\Configuration.ini" "UpdateEnabled=`"True`""
  Add-Content "$path\Configuration.ini" "; If this parameter is provided, then this computer will use Microsoft Update to check for updates. "
  Add-Content "$path\Configuration.ini" "USEMICROSOFTUPDATE=`"True`""
  Add-Content "$path\Configuration.ini" "; Specifies that SQL Server Setup should not display the paid edition notice when ran from the command line. "
  Add-Content "$path\Configuration.ini" "SUPPRESSPAIDEDITIONNOTICE=`"True`""
  Add-Content "$path\Configuration.ini" "; Specify the location where SQL Server Setup will obtain product updates. The valid values are `"MU`" to search Microsoft Update, a valid folder path, a relative path such as .\MyUpdates or a UNC share. By default SQL Server Setup will search Microsoft Update or a Windows Update service through the Window Server Update Services. "
  Add-Content "$path\Configuration.ini" "UpdateSource=`"MU`""
  Add-Content "$path\Configuration.ini" "; Specifies features to install, uninstall, or upgrade. The list of top-level features include SQL, AS, IS, MDS, and Tools. The SQL feature will install the Database Engine, Replication, Full-Text, and Data Quality Services (DQS) server. The Tools feature will install shared components. "
  Add-Content "$path\Configuration.ini" "FEATURES=SQLENGINE"
  Add-Content "$path\Configuration.ini" "; Displays the command line parameters usage. "
  Add-Content "$path\Configuration.ini" "HELP=`"False`""
  Add-Content "$path\Configuration.ini" "; Specifies that the detailed Setup log should be piped to the console. "
  Add-Content "$path\Configuration.ini" "INDICATEPROGRESS=`"False`""
  Add-Content "$path\Configuration.ini" "; Specify a default or named instance. MSSQLSERVER is the default instance for non-Express editions and SQLExpress for Express editions. This parameter is required when installing the SQL Server Database Engine (SQL), or Analysis Services (AS). "
  Add-Content "$path\Configuration.ini" "INSTANCENAME=`"$instanceName`""
  Add-Content "$path\Configuration.ini" "; Startup type for the SQL Server CEIP service. "
  Add-Content "$path\Configuration.ini" "SQLTELSVCSTARTUPTYPE=`"Manual`""
  Add-Content "$path\Configuration.ini" "; Account for SQL Server CEIP service: Domain\User or system account. "
  Add-Content "$path\Configuration.ini" "SQLTELSVCACCT=`"NT Service\SQLTELEMETRY`$$instanceName`""
  Add-Content "$path\Configuration.ini" "; Specify the installation directory. "
  Add-Content "$path\Configuration.ini" "INSTANCEDIR=`"$instancedDir`""
  Add-Content "$path\Configuration.ini" "; The default is Windows Authentication. Use `"SQL`" for Mixed Mode Authentication. "
  Add-Content "$path\Configuration.ini" "SECURITYMODE=`"SQL`""
  Add-Content "$path\Configuration.ini" "SAPWD=`"$pass`""
  Add-Content "$path\Configuration.ini" "; Agent account name. "
  Add-Content "$path\Configuration.ini" "AGTSVCACCOUNT=`"NT AUTHORITY\NETWORK SERVICE`""
  Add-Content "$path\Configuration.ini" "; Auto-start service after installation. "
  Add-Content "$path\Configuration.ini" "AGTSVCSTARTUPTYPE=`"Disabled`""
  Add-Content "$path\Configuration.ini" "; Startup type for the SQL Server service. "
  Add-Content "$path\Configuration.ini" "SQLSVCSTARTUPTYPE=`"Automatic`""
  Add-Content "$path\Configuration.ini" "; Level to enable FILESTREAM feature at (0, 1, 2 or 3). "
  Add-Content "$path\Configuration.ini" "FILESTREAMLEVEL=`"0`""
  Add-Content "$path\Configuration.ini" "; The max degree of parallelism (MAXDOP) server configuration option. "
  Add-Content "$path\Configuration.ini" "SQLMAXDOP=`"0`""
  Add-Content "$path\Configuration.ini" "; Set to `"1`" to enable RANU for SQL Server Express. "
  Add-Content "$path\Configuration.ini" "ENABLERANU=`"True`""
  Add-Content "$path\Configuration.ini" "; Specifies a Windows collation or an SQL collation to use for the Database Engine. "
  Add-Content "$path\Configuration.ini" "SQLCOLLATION=`"SQL_Latin1_General_CP1_CI_AS`""
  Add-Content "$path\Configuration.ini" "; Account for SQL Server service: Domain\User or system account. "
  Add-Content "$path\Configuration.ini" "SQLSVCACCOUNT=`"NT Service\MSSQL`$$instanceName`""
  Add-Content "$path\Configuration.ini" "; Set to `"True`" to enable instant file initialization for SQL Server service. If enabled, Setup will grant Perform Volume Maintenance Task privilege to the Database Engine Service SID. This may lead to information disclosure as it could allow deleted content to be accessed by an unauthorized principal. "
  Add-Content "$path\Configuration.ini" "SQLSVCINSTANTFILEINIT=`"True`""
  Add-Content "$path\Configuration.ini" "; Windows account(s) to provision as SQL Server system administrators. "
  Add-Content "$path\Configuration.ini" "SQLSYSADMINACCOUNTS=`".\Administrator`""
  Add-Content "$path\Configuration.ini" "; The number of Database Engine TempDB files. "
  Add-Content "$path\Configuration.ini" "SQLTEMPDBFILECOUNT=`"1`""
  Add-Content "$path\Configuration.ini" "; Specifies the initial size of a Database Engine TempDB data file in MB. "
  Add-Content "$path\Configuration.ini" "SQLTEMPDBFILESIZE=`"8`""
  Add-Content "$path\Configuration.ini" "; Specifies the automatic growth increment of each Database Engine TempDB data file in MB. "
  Add-Content "$path\Configuration.ini" "SQLTEMPDBFILEGROWTH=`"64`""
  Add-Content "$path\Configuration.ini" "; Specifies the initial size of the Database Engine TempDB log file in MB. "
  Add-Content "$path\Configuration.ini" "SQLTEMPDBLOGFILESIZE=`"8`""
  Add-Content "$path\Configuration.ini" "; Specifies the automatic growth increment of the Database Engine TempDB log file in MB. "
  Add-Content "$path\Configuration.ini" "SQLTEMPDBLOGFILEGROWTH=`"64`""
  Add-Content "$path\Configuration.ini" "; Provision current user as a Database Engine system administrator for SQL Server 2022 Express. "
  Add-Content "$path\Configuration.ini" "ADDCURRENTUSERASSQLADMIN=`"True`""
  Add-Content "$path\Configuration.ini" "; Specify 0 to disable or 1 to enable the TCP/IP protocol. "
  Add-Content "$path\Configuration.ini" "TCPENABLED=`"0`""
  Add-Content "$path\Configuration.ini" "; Specify 0 to disable or 1 to enable the Named Pipes protocol. "
  Add-Content "$path\Configuration.ini" "NPENABLED=`"0`""
  Add-Content "$path\Configuration.ini" "; Startup type for Browser Service. "
  Add-Content "$path\Configuration.ini" "BROWSERSVCSTARTUPTYPE=`"Disabled`""
  Add-Content "$path\Configuration.ini" "; Use SQLMAXMEMORY to minimize the risk of the OS experiencing detrimental memory pressure. "
  Add-Content "$path\Configuration.ini" "SQLMAXMEMORY=`"2147483647`""
  Add-Content "$path\Configuration.ini" "; Use SQLMINMEMORY to reserve a minimum amount of memory available to the SQL Server Memory Manager. "
  Add-Content "$path\Configuration.ini" "SQLMINMEMORY=`"0`""

  $installwait=Start-Process "$path\SQL2022-SSEI-Expr.exe" -ArgumentList "/IAcceptSqlServerLicenseTerms /MediaPath=$mediapath /ConfigurationFile=$path\Configuration.ini /Quiet" -Wait

  Remove-Item -Path "$path\Configuration.ini"

 }

 if($option -eq 3){

  NetTest

  $phpVer = Read-Host -Prompt "Please enter the version of PHP you wish to install (Ex: $phpVer)."

  Invoke-WebRequest -Uri "https://aka.ms/vs/16/release/VC_redist.x64.exe" -OutFile ./VC_redist.x64.exe
  
  Start-Process "$path\VC_redist.x64.exe" "/install /quiet /norestart"

  Invoke-WebRequest -Uri "https://windows.php.net/downloads/releases/latest/php-$phpVer-nts-Win32-vs16-x64-latest.zip" -OutFile ./php-$phpVer-nts-Win32-vs16-x64-latest.zip

  $phpinstallpath = Read-Host -Prompt "Please enter the intended base PHP install path (Ex: $phpinstallpath )"

  Expand-Archive -Path "$path\php-$phpVer-nts-Win32-vs16-x64-latest.zip" -DestinationPath $phpinstallpath\$phpVer

  Remove-Item -Path "$phpinstallpath\$phpVer\php.ini-development"

  Move-Item -Path "$phpinstallpath\$phpVer\php.ini-production" -Destination "$phpinstallpath\$phpVer\php.ini"

  Add-Content "$phpinstallpath\$phpVer\php.ini" "[Automate Script Changes]`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "log-errors=On`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "error_log = C:\Windows\Temp\PHP_errors.log`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "upload_tmp_dir = C:\Windows\Temp`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "session.save_path = C:\Windows\Temp\PHPSessions`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "cgi.force_redirect = 0`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "cgi.fix_pathinfo = 1`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "fastcgi.impoersonate = 1`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "fastcgi.logging = 0`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "max_execution_time = 400`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "date.timezone = America/New_York`n"
  Add-Content "$phpinstallpath\$phpVer\php.ini" "extension_dir=$phpinstallpath\$phpVer\ext\`n"

 }

  if($option -eq 4){

   NetTest

   Write-Host "Downloading & Installing MS ODBC Prerequisites. Please wait..."
   Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2214634" -OutFile ./msodbcsql.msi
   Start-Process "msiexec.exe" "/i msodbcsql.msi /qn"

   Write-Host "Downloading & Installing PHP SQLSRV. Please wait..."
   Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/?linkid=2199011" -OutFile ./SQLSRV510.ZIP

   $phpinstallpath = Read-Host -Prompt "Please enter the intended base PHP install path (Ex: $phpinstallpath )"

   $phpVer = Read-Host "Please enter the version of PHP you wish PDO_SQLSRV to support (Ex: $phpVer)."
   $numPHPVer=$phpVer.Replace('.','')

   Expand-Archive -Path "$path\SQLSRV510.ZIP" -DestinationPath "$path\SQLSRV510"

   $filename="$path\SQLSRV510\php_sqlsrv_"+$numPHPVer+"_nts_x64.dll"

   Write-Host "Copying file $filename to destination $phpinstallpath\$phpVer\ext\php_sqlsrv_nts.dll"

   copy-item -path $filename -Destination "$phpinstallpath\$phpVer\ext\php_sqlsrv_nts.dll" -Recurse -force

   Add-Content "$phpinstallpath\$phpVer\php.ini" "[PHP_SQL]`n"
   Add-Content "$phpinstallpath\$phpVer\php.ini" "extension=php_sqlsrv_nts.dll`n"

  }
  if($option -eq 5){

   NetTest

   set-location $path

   Write-Host "Downloading & Installing MS SQL Server Management Studio. Please wait..."
   Invoke-WebRequest -Uri "https://aka.ms/ssmsfullsetup" -OutFile ./SSMS-Setup-ENU.exe

   $installwait=Start-Process ".\SSMS-Setup-ENU.exe" -ArgumentList "/Quiet" -Wait

  }
  if($option -eq 6){
   NetTest

   $packageProviders=Get-PackageProvider -ListAvailable
   $nugetfound=0
   Write-Host "Package Provider - Version"
   foreach($packageProvider in $packageProviders){
    Write-Host $packageProvider.Name "-" $packageProvider.Version
    if($packageProvider.Name -eq "NuGet" -and $packageProvider.Version -ge 2.8.5.201){
     $nugetfound=1
    }
   }

   Write-Host "`n"

   if($nugetfound -eq 1){
    Write-Host "NuGet already installed.`n"
   }
   else{
    Write-Host "Downloading & Installing NuGet package provider. Please wait...`n"
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
   }
  }
  if($option -eq 7){
   Write-Host "Downloading & Installing IISAdministration powershell module. Please wait...`n"   
   Install-Module -Name 'IISAdministration' -Force
  }
  if($option -eq 8){

   Remove-Module IISAdministration
   Import-Module IISAdministration

   $physicalPath = (Get-Website "Default Web Site" | Select-Object).PhysicalPath
   Stop-IISSite -Name "Default Web Site" -Confirm:$false
   Remove-IISSite -Name "Default Web Site" -Confirm:$false

   Get-IISAppPool|Where-Object -Property Name -EQ "DefaultAppPool"|Remove-WebAppPool -Confirm:$false

   Remove-Module IISAdministration
   Import-Module IISAdministration

   $RemoveDefaultDir=""
   while($RemoveDefaultDir -ne "Y" -and $RemoveDefaultDir -ne "N"){
    $RemoveDefaultDir=Read-Host -Prompt "Do you wish to remove the default website directory? (Y/N)"
   }

   if($RemoveDefaultDir -eq "Y"){
    $physicalPath = "%SystemDrive%/inetpub/wwwroot"
    $physicalPath=$physicalPath.Replace("%SystemDrive%","$env:SystemDrive");

    $test=(Get-Location).Path

    Set-Location $physicalPath

    while($test -ne "$env:SystemDrive\"){
     cd ..
     $test=(Get-Location).Path
    }

    Remove-Item -Path $physicalPath -Recurse

   }
   Write-Host "$physicalPath removed."

  }
  if($option -eq 9){

   $newDrive=Read-Host -Prompt "Please enter the drive letter for the new content directory. (Ex: $newDrive)"
   $newDir=Read-Host -Prompt "Please enter the new content directory. (Ex: $newDir)"

   Write-Host "Creating Folder..."
   $folder = New-Item -ItemType Directory -Name $newDir -Path $newDrive

   $ACL = Get-ACL -Path $folder
   $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","Read", "ContainerInherit, ObjectInherit", "None", "Allow")))
   $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","Execute", "ContainerInherit, ObjectInherit", "None", "Allow")))
   $ACL.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("IIS_IUSRS","ReadData", "ContainerInherit, ObjectInherit", "None", "Allow")))

   $ACL | Set-Acl -Path $folder
   (Get-ACL -Path $folder).Access | Format-Table IdentityReference,FileSystemRights,AccessControlType,IsInherited,InheritanceFlags -AutoSize
   Write-Host "Folder Created`n"

   $copyFolderYN=Read-Host -Prompt "Is there a source directory you wish to copy into the $newDrive$newDir directory? (Y/N)"

   if($copyFolderYN -eq "Y"){
    $copyFolder=Read-Host "Please enter source directory (Ex: $copyFolder)"
    Copy-Item -Path $copyFolder/* -Destination $newDrive$newDir
   }


   $localAddr=Test-NetConnection -Hops 1|Select-Object -Property SourceAddress -ExpandProperty SourceAddress
   $localAddr=$localAddr.IPAddress

   $usedPorts=Get-NetTCPConnection -LocalAddress $localAddr|Where-Object -Property LocalPort -LT 10001

   $prefPort=80
   $prefPortSSL=443
   $prefPortUsed=0
   $prefPortSSLUsed=0

   foreach($usedPort in $usedPorts){
    if($usedPort.LocalPort -eq $prefPort){$prefPortUsed=1}
    if($usedPort.LocalPort -eq $prefPortSSL){$prefPortSSLUsed=1}
   }

   $eightyAnswer="";
   if($prefPortUsed -ne 1){
    while($eightyAnswer -ne "Y" -and $eightyAnswer -ne "N"){
     $eightyAnswer=Read-Host -Prompt "Would you like to utilize port 80 for the new website? (Y/N)"
    }
   }

   $fourfourthreeAnswer="";
   if($eightyAnswer -eq "N"){
    while($fourfourthreeAnswer -ne "Y" -and $fourfourthreeAnswer -ne "N"){
     $fourfourthreeAnswer=Read-Host -Prompt "Would you like to utilize port 443 for the new website? (Y/N)"
    }
   }

   if($fourfourthreeAnswer -eq "N" -and $eightyAnswer -eq "N"){
    Write-Host "List of used ports"
    foreach($usedPort in $usedPorts){
     Write-Host "$usedPort.LocalPort`tUTILIZED`n"
    }

    $confAltAnswer="";
    while($confAltAnswer -ne "Y"){
     $altAnswer=Read-Host -Prompt "Custom Port: Please enter the port you wish to utilize"
     $confAltAnswer=Read-Host -Prompt "You selected $altAnswer, is that correct? (Y/N)"
    }
   }
   else{
    if($fourfourthreeAnswer -eq "Y"){$altAnswer = 443;}
    if($eightyAnswer -eq "Y"){$altAnswer = 80;}
   }

   Remove-Module IISAdministration
   Import-Module IISAdministration

   $CountAppPool=(Get-IISAppPool).count

   $AppPoolSelected=""
   if($CountAppPool -gt 0){

    $AppPoolChoice=""
    while($AppPoolChoice -ne 1 -and $AppPoolChoice -ne 2){
     $AppPoolChoice=Read-Host -Prompt "Would you like to use an existing App Pool, or create a new one? (1=Use Existing, 2=Create New)"

     if($AppPoolChoice -eq 1){
      Get-IISAppPool
      $AppPoolSelected=Read-Host -Prompt "Please enter the name of the App Pool you wish to utilize from the list above, or type `"new`" to create a new App Pool, instead"
     }

    }
   }

   if($AppPoolSelected -eq "" -or $AppPoolSelected -eq "new"){
    $AppPool=Read-Host -Prompt "Enter the name for the web site's Application Pool (Ex. $AppPool)"

    New-WebAppPool -Name $AppPool -Force
    Remove-Module IISAdministration
    Import-Module IISAdministration

   }
   else{$AppPool = $AppPoolSelected}

   Write-Host "App Pool to use: $AppPool"

   while($SiteName -eq ""){
    $SiteName = Read-Host -Prompt "Enter the name for the new site (Ex: $SiteName)"
   }

   Start-IISCommitDelay
   $NewSite = New-IISSite -Name $SiteName -BindingInformation "*:${altAnswer}:" -PhysicalPath $folder -Passthru
   $NewSite.Applications["/"].ApplicationPoolName = $AppPool
   Stop-IISCommitDelay

  }
  if($option -eq 10){

   Enable-WindowsOptionalFeature -Online -FeatureName 'IIS-ApplicationDevelopment','IIS-CGI'
   Remove-Module IISAdministration
   Import-Module IISAdministration

   $phpinstallpath = Read-Host -Prompt "Please enter the base PHP install path (Ex: $phpinstallpath )"
   $phps = Get-ChildItem $phpinstallpath

   $phpCorrect=""
   do{
    Write-Host "PHP versions that are currently installed"
    Write-Host $phps|Format-Table -GroupBy Name

    $phpVer = Read-Host -Prompt "Please enter the version of PHP you wish to utilize for handler mappings (Ex: $phpVer)"
    $phpCorrect = Read-Host -Prompt "The version selected is $phpVer. Is this correct?"
   }
   while($phpCorrect -ne "Y")

   $handlerCorrect=""
   do{
    $handlerName = Read-Host -Prompt "Please enter a handler name (Ex: $handlerName)"
    $handlerCorrect = Read-Host -Prompt "The handler name provided is $handlerName. Is this correct?"
   }
   while($handlerCorrect -ne "Y")

   # Adds process pool in IIS
   $configPath = get-webconfiguration 'system.webServer/fastcgi/application' | where-object { $_.fullPath -eq "$phpinstallpath\$phpVer\php-cgi.exe" }
   if (!$configPath) {
    add-webconfiguration 'system.webserver/fastcgi' -value @{'fullPath' = "$phpinstallpath\$phpVer\php-cgi.exe" }
   }

   # Create PHP handler mapping
   $handler = get-webconfiguration 'system.webserver/handlers/add' | where-object { $_.Name -eq $handlerName }
   if (!$handler) {
    add-webconfiguration 'system.webServer/handlers' -Value @{
     Name = $handlerName;
     Path = "*.php";
     Verb = "*";
     Modules = "FastCgiModule";
     scriptProcessor="$phpinstallpath\$phpVer\php-cgi.exe";
     resourceType='Either' 
    }
   }

   #FastCGI Settings
   $configPath = "system.webServer/fastCgi/application[@fullPath=`"$phpinstallpath\$phpVer\php-cgi.exe`"]/environmentVariables/environmentVariable"
   $config = Get-WebConfiguration $configPath
   if(!$config) {
    $configPath = "system.webServer/fastCgi/application[@fullPath=`"$phpinstallpath\$phpVer\php-cgi.exe`"]/environmentVariables"
    Add-WebConfiguration $configPath -Value @{ 'Name' = 'PHP_FCGI_MAX_REQUESTS'; Value = 10050 }
   }

   # Configure the settings
   # monitorChangesTo, stderrMode, maxInstances, idleTimeout, activityTimeout, requestTimeout, instanceMaxRequests, signalBeforeTerminateSeconds, protocol, queueLength, flushNamedPipe, rapidFailsPerMinute

   $configPath = "system.webServer/fastCgi/application[@fullPath=`"$phpinstallpath\$phpVer\php-cgi.exe`"]"
   $mCTCorrect=""
   do{
    $monitorChangeTo = Read-Host -Prompt "Do you wish to monitor changes to the php.ini configuration file? (Y/N)"
    $mCTCorrect = Read-Host -Prompt "You selected $monitorChangeTo. Is this correct?"
    if($mCTCorrect -eq "Y" -and $monitorChangeTo -eq "Y"){
     Set-WebConfigurationProperty $configPath -Name monitorChangesTo -Value "$phpinstallpath\$phpVer\php.ini"
    }
   }
   while($mCTCorrect -ne "Y" -and $mCTCorrect -eq "N")

   $configPath = "system.webServer/fastCgi/application[@fullPath=`"$phpinstallpath\$phpVer\php-cgi.exe`"]"
   Set-WebConfigurationProperty $configPath -Name stderrMode -Value "ReturnStdErrIn500"

   $mICorrect=""
   do{
    $maxInstances = Read-Host -Prompt "Please enter the maximum number of instances (maxInstances). Note: 0 is unlimited. (Ex: 0)"
    $mICorrect = Read-Host -Prompt "The maxInstances value provided is $maxInstances. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name maxInstances -Value $maxInstances
   }
   while($mICorrect -ne "Y")

   $iTCorrect=""
   do{
    $idleTimeout = Read-Host -Prompt "Please enter the idle timeout value (idleTimeout). Note: 0 is unlimited. (Ex: 300)"
    $iTCorrect = Read-Host -Prompt "The idleTimeout value provided is $idleTimeout. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name idleTimeout -Value $idleTimeout
   }
   while($iTCorrect -ne "Y")

   $aTCorrect=""
   do{
    $activityTimeout = Read-Host -Prompt "Please enter the activity timeout value (activityTimeout). Note: 0 is unlimited. (Ex: 2500)"
    $aTCorrect = Read-Host -Prompt "The activityTimeout value provided is $activityTimeout. Is this correct?"
    $activityTimeout=[int]$activityTimeout
    Set-WebConfigurationProperty $configPath -Name activityTimeout -Value [int]$activityTimeout
   }
   while($aTCorrect -ne "Y")

   $rTCorrect=""
   do{
    $requestTimeout = Read-Host -Prompt "Please enter the request timeout value (requestTimeout). Note: 0 is unlimited. (Ex: 90)"
    $rTCorrect = Read-Host -Prompt "The requestTimeout value provided is $requestTimeout. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name requestTimeout -Value $requestTimeout
   }
   while($rTCorrect -ne "Y")

   $iMRCorrect=""
   do{
    $instanceMaxRequests = Read-Host -Prompt "Please enter the maximum requests per instance (instanceMaxRequests). Note: 0 is unlimited. (Ex: 200)"
    $iMRCorrect = Read-Host -Prompt "The instanceMaxRequests value provided is $instanceMaxRequests. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name instanceMaxRequests -Value $instanceMaxRequests
   }
   while($iMRCorrect -ne "Y")

   $sBTSCorrect=""
   do{
    $sBTSeconds = Read-Host -Prompt "Please enter the maximum requests per instance (signalBeforeTerminateSeconds). (Ex: 0)"
    $sBTSCorrect = Read-Host -Prompt "The sBTSeconds value provided is $sBTSeconds. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name signalBeforeTerminateSeconds -Value $sBTSeconds
   }
   while($sBTSCorrect -ne "Y")

   $pCorrect=""
   do{
    $protocol = Read-Host -Prompt "Please enter the protocol (protocol). (Ex: NamedPipe)"
    $pCorrect = Read-Host -Prompt "The protocol value provided is $protocol. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name protocol -Value $protocol
   }
   while($pCorrect -ne "Y")

   $qLCorrect=""
   do{
    $queueLength = Read-Host -Prompt "Please enter the queue length (queueLength). (Ex: 1000)"
    $qLCorrect = Read-Host -Prompt "The queueLength value provided is $queueLength. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name queueLength -Value $queueLength
   }
   while($qLCorrect -ne "Y")

   $fNPCorrect=""
   do{
    $fNPipe = Read-Host -Prompt "Please enter the flush named pipe value (flushNamedPipe). (Ex: False)"
    $fNPCorrect = Read-Host -Prompt "The flush named pipe value provided is $fNPipe. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name flushNamedPipe -Value $fNPipe
   }
   while($fNPCorrect -ne "Y")

   $rFPMCorrect=""
   do{
    $rFPMinute = Read-Host -Prompt "Please enter the rapid fails per minute value (rapidFailsPerMinute). (Ex: 10)"
    $rFPMCorrect = Read-Host -Prompt "The rapid fails per minute value provided is $rFPMinute. Is this correct?"
    Set-WebConfigurationProperty $configPath -Name rapidFailsPerMinute -Value $rFPMinute
   }
   while($rFPMCorrect -ne "Y")

   #Restart IIS to load new configs.
   invoke-command -scriptblock {iisreset /restart }
  }
  if($option -eq 11){
   Write-Host "Downloading & Installing SqlServer powershell module. Please wait...`n"   
   Install-Module -Name 'SqlServer' -Force
  }
  if($option -eq 12){

   $CertLocationCorrect=""
   while($CertLocationCorrect -ne "N" -and $CertLocationCorrect -ne "Y"){
    $CertLocation = Read-Host -Prompt "Please enter the location and filename of the PFX file (Ex: $CertLocation)"
    $CertLocationCorrect = Read-Host -Prompt "Is the location and filename name correct? (Y/N)"
   }

   $PFXPassQuestion=""
   while($PFXPassQuestion -ne "Y" -and $PFXPassQuestion -ne "N"){
    $PFXPassQuestion = Read-Host -Prompt "Does the PFX File have a password (Y/N)?"
   }

   if($PFXPassQuestion -eq "Y"){
    $MyPwd = Read-Host -Prompt "Enter Password" -AsSecureString
    Import-PfxCertificate -Password $MyPwd -CertStoreLocation Cert:\LocalMachine\My -FilePath $CertLocation
   }
   else{
    Import-PfxCertificate -CertStoreLocation Cert:\LocalMachine\My -FilePath $CertLocation
   }
  }
  if($option -eq 13){
   Import-Module -Name SqlServer

   $SQLServerCorrect=""
   do{
    $SQLServer = Read-Host -Prompt "Please enter the SQL Server instance name. (Ex: $SQLServer)"
    $SQLServerCorrect = Read-Host -Prompt "The SQL Server instance name provided is $SQLServer. Is this correct?"
   }
   while($SQLServerCorrect -ne "Y")   

   $SQLUserCorrect=""
   do{
    $SQLUser = Read-Host -Prompt "Please enter the SQL Server user name. (Ex: sa)"
    $SQLUserCorrect = Read-Host -Prompt "The SQL Server use name provided is $SQLUser. Is this correct?"
   }
   while($SQLUserCorrect -ne "Y")   

   $SQLPass = Read-Host -Prompt "Please enter the SQL Server user password"

   $db3 = "master"

   $fileLocation=Read-Host "Please enter file location (Ex: $fileLocation)"

   $connString="Server = " + $SQLServer + "; User = " + $SQLUser + "; Password = " + $SQLPass + "; Database = " + $db3 + "; Column Encryption Setting = Enabled; EncryptConnection = True";

   Invoke-Sqlcmd -inputfile $fileLocation -Verbose -ConnectionString $connString

  }
  if($option -eq 14){
   Import-Module IISAdministration

   $SiteNameCorrect=""
   while($SiteNameCorrect -ne "Y"){
    $SiteName = Read-Host -Prompt "Please enter the website name ($SiteName)"
    $SiteNameCorrect = Read-Host -Prompt "Is the web site name correct? (Y/N)"
   }

   $PortNumberCorrect=""
   while($PortNumberCorrect -ne "N" -and $PortNumberCorrect -ne "Y"){
    $PortNumber = Read-Host -Prompt "Please enter the port number you wish to use for the SSL version of the website (Ex: $PortNumber)"
    $PortNumberCorrect = Read-Host -Prompt "Is the port number correct? (Y/N)"
   }

   $CertificateNameCorrect=""
   while($CertificateNameCorrect -ne "N" -and $CertificateNameCorrect -ne "Y"){
    $CertificateName = Read-Host -Prompt "Please enter the certificate name you wish to use for the SSL version of the website (CN=Stuff)"
    $CertificateNameCorrect = Read-Host -Prompt "Is the certificate name correct? (Y/N)"
   }

   $Cert=Get-ChildItem Cert:\LocalMachine\My|Select-Object -Property Subject, Thumbprint|Where-Object -Property Subject -EQ $CertificateName
   $Thumbprint=$Cert.Thumbprint

   New-WebBinding -Name $SiteName -IP "*" -Port $PortNumber -Protocol https
   $binding=(Get-WebBinding -Name $SiteName -Port $PortNumber -Protocol "https")
   if($binding){
    $binding.AddSslCertificate($Thumbprint, "my")
   }

  }
  if($option -eq 15){
   $cert = New-SelfSignedCertificate -Subject "AlwaysEncryptedCert" -CertStoreLocation cert:\LocalMachine\My -KeyExportPolicy Exportable -Type DocumentEncryptionCert -KeyUsage DataEncipherment -KeySpec KeyExchange
  }
}
