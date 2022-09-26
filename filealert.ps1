Set-ExecutionPolicy Unrestricted
$file4659="c:\script\alert1log"+$(Get-Date -format "yyyyMMdd")+".csv"
$file4663="c:\script\alert2log"+$(Get-Date -format "yyyyMMdd")+".csv"
$aftertime=(Get-Date).Addminutes(-32)
$beforetime=(Get-Date)

$result4659 = Get-EventLog  -LogName Security -InstanceId 4659  -After $aftertime -Before $beforetime  |
   ForEach-Object {
     [PSCustomObject]@{
     Time = $_.TimeGenerated
	 File_path = $_.ReplacementStrings[6]
     Access_type = $_.ReplacementStrings[5]
     User = $_.ReplacementStrings[1]
     }
   }

$result4659_1=$result4659 | Where-Object -Property Access_type -Contains 'File'
$result4659_2=$result4659_1| Select-Object Time, User, File_path | Where-Object {($_.File_path -notlike '*\~$*')} | Where-Object {($_.File_path -notlike '*.tmp')}
$result4659_2 | Export-Csv -NoTypeInformation -Path $file4659

$result4663 = Get-EventLog  -LogName Security -InstanceId 4663  -After $aftertime -Before $beforetime  |
   ForEach-Object {
     [PSCustomObject]@{
     Time = $_.TimeGenerated
	 File_path = $_.ReplacementStrings[6]
     Access_type = $_.ReplacementStrings[5]
     User = $_.ReplacementStrings[1]
     Mask = $_.ReplacementStrings[9]

     }
   }

$result4663_1=$result4663 | Where-Object -Property Access_type -Contains 'File' | Where-Object -Property Mask -Contains '0x10000'
$result4663_2=$result4663_1| Select-Object Time, User, File_path | Where-Object {($_.File_path -notlike '*\~$*')} | Where-Object {($_.File_path -notlike '*.tmp')} | Where-Object {($_.User -notlike 'SWCPL-FS5$')}
$result4663_2 | Export-Csv -NoTypeInformation -Path $file4663
