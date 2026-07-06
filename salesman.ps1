param([string]$ProcessDate)

$dtexec = "C:\Program Files\Microsoft SQL Server\140\DTS\Binn\dtexec.exe"

# ambil nama file script → store.ps1
$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)

# jadi store.dtsx
$packageName = $scriptName + ".dtsx"

$cmd = '"' + $dtexec + '" ' +
'/ISSERVER "\SSISDB\SAM FIRESTORE\SAM_FIRESTORE_ETL\' + $packageName + '" ' +
'/SERVER "." ' +
'/Par "$Package::ProcessDate";"' + $ProcessDate + '"'

cmd /c $cmd