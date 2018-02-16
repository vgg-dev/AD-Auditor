$api_key = "XXXX"
Set-MSRCApiKey -ApiKey $api_key
$months=Get-MsrcSecurityUpdate -After (Get-Date).AddDays(-60) -Before (Get-Date)
foreach ($month in $months) 
{
    $month.ID
    $cvrfDoc = Get-MsrcCvrfDocument -ID $month.ID | Where-Object -FilterScript { ($_.ProductTree.FullProductName.Value) -like "*server 2012*" }
    $a=$cvrfDoc.Vulnerability.Remediations | where Type -eq 2
    $a.Description.Value | Where-Object -filterscript { $_ -match '^\d' } | Get-Unique
    
}


