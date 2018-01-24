function Invoke-ADAudit
{

<#
.Synopsis
    Microsoft Active Directory security assessment tool

.Description
    This script will perform varius security assessments of Active Directory basd on NIST standards and industry best practices

.Parameter
#>


	[CmdletBinding()]
    
	Param (
		[Parameter(Mandatory = $True)]
		[string]$OutFile,
		[Parameter(Mandatory = $False)]
		[switch]$InstallRSAT,
		[Parameter(Mandatory = $False)]
		[string]$Output = "csv"		
	)
	begin
	{
			Import-Module BestPractices
			# Stop on errors
			# $ErrorActionPreference = "Stop"
			# Get start time
			$startTime = (Get-Date)

			# 
	
	
		# Print logo header
		function Show-Header 
		{
			cls
			Write-Host "    _   ___   _          _ _ _           " -ForegroundColor "blue"
			Write-Host "   /_\ |   \ /_\ _  _ __| (_) |_ ___ _ _ " -ForegroundColor "blue"
			Write-Host "  / _ \| |) / _ \ || / _\` | |  _/ _ \ '_|" -ForegroundColor "blue"
			Write-Host " /_/ \_\___/_/ \_\_,_\__,_|_|\__\___/_|  " -ForegroundColor "blue"
			Write-Host " Active Directory Security Audit Framework" -ForegroundColor "blue"
			Write-Host ""
			Write-Host $startTime -ForegroundColor "DarkYellow"
			Write-Host ""
		}


		# Print to the user console
		function Show-Menu 
		{
			Show-Header
			Write-Host "ADAuditor Menu:"
			Write-Host "[1] - MS Best Practices Analyzer (BPA) Module"
			Write-Host "[2] - Domain User Accounts Module"
			Write-Host "[0] - Exit"

		}

		#MS-BPA Module
		function Invoke-BPAModule
		{
			# Show BPA Module menu
			function Show-BPAModuleMenu
			{
				Write-Host "ADAuditor/BPA Module Menu:"
				Write-Host "[1] - List availble model IDs"
				Write-Host "[2] - Scan using all available models"
				Write-Host "[3] - Scan using user specified model (You will be prompted for the model ID)"
				Write-Host "[4] - Scan using Active Directory model (Microsoft/Windows/DirectoryServices)"
				Write-Host "[0] - Back to Main Module"
			}
			
			# List availble BPA model IDs
			function List-BPAModels
			{
				Get-BPAModel | Select-Object id, Name | Format-Table -Wrap
			}

			# Scan with all availble BPA models
			function Scan-AllBPA
			{

			}

			# Scan with specific BPA models
			function Scan-SpecBPA
			{

			}

			# Scan with AD BPA models
			function Scan-ADBPA
			{
				$BPA = "Microsoft/Windows/DirectoryServices"
				
				#Kick-off BPA scan
				Invoke-BPAModel -BestPracticesModelId $BPA -ErrorAction SilentlyContinue
				#Get BPA results, filter and export
				Get-BPAResult -ModelID $BPA -ErrorAction SilentlyContinue |
									Where-Object {$_.Problem -ne $Null} |
									Select-Object ResultNumber,Severity,Category,Title,Problem,Impact,Resolution |
									Export-Csv "filename.csv" -NoTypeInformation -Encoding UTF8


			}

			do
			{
				Show-BPAModuleMenu
				$input = Read-Host "Please make a selection>"
				switch ($input)
				{
					'1'{ List-BPAModels }
					'2'{ Scan-AllBPA }
					'3'{ }
					'4'{ }
					'0'{ return }
				}
				pause
			}
			until ($input -eq '0')
		}
	}
	process
	{
		# Main body here
        
        Show-Header

	}
}