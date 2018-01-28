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
		
			# Get start time
			$startTime = (Get-Date)

			# 
	
	
		# Print logo header
		function Show-Header 
		{
			[console]::ResetColor()
            cls
			Write-Host "    _   ___   _          _ _ _           " -ForegroundColor red
			Write-Host "   /_\ |   \ /_\ _  _ __| (_) |_ ___ _ _ " -ForegroundColor red
			Write-Host "  / _ \| |) / _ \ || / _\` | |  _/ _ \ '_|" -ForegroundColor red
			Write-Host " /_/ \_\___/_/ \_\_,_\__,_|_|\__\___/_|  " -ForegroundColor red
			Write-Host " Active Directory Security Audit Framework" -ForegroundColor red
			Write-Host ""
			Write-Host "-=" $startTime "=-" -ForegroundColor "DarkYellow"
			Write-Host ""
		}


		# Print to the user console
		function Show-Menu 
		{
			Show-Header
			Write-Host "[ADAuditor Menu:]" -ForegroundColor Green
			Write-Host "[1] - MS Best Practices Analyzer (BPA) Module" -ForegroundColor White
			Write-Host "[2] - Domain User Accounts Module" -ForegroundColor White
            Write-Host "[3] - Domain Computers Module" -ForegroundColor White
			Write-Host "[0] - Exit" -ForegroundColor White

		}

    ######################
    # MS BPA  MODULE     #################################################################################
    ######################
		function Invoke-BPAModule
		{
			# Show BPA Module menu
			function Show-BPAModuleMenu
			{
				Write-Host "[ADAuditor]-[BPA Module Menu:]" -ForegroundColor "Green"
				Write-Host "[1] - List availble model IDs for this server ($env:computername)"
				Write-Host "[2] - Scan using all available models"
				Write-Host "[3] - Scan using user specified model (You will be prompted for the model ID)"
				Write-Host "[4] - Scan using Active Directory model (Microsoft/Windows/DirectoryServices)"
				Write-Host "[0] - Back to Main Module"
			}
			
			# List availble BPA model IDs
			function List-BPAModels
			{
				#Get-BPAModel | Select-Object id, Name | Format-Table -Wrap
                Write-Host "Microsoft Windows fetaures installed on $env:computername with applicabe BPAs"
                Get-WindowsFeature | Where-Object {$_. InstallState -eq "Installed" -and $_.BestPracticesModelId -ne ""} | Select-Object DisplayName, BestPracticesModelID | Format-List *
			}

			# Scan with all availble BPA models
			function Scan-AllBPA
			{
                # Get all availble BPA for the server based on installed Windoes features
                $AvailableBPA = Get-WindowsFeature | Where-Object {$_. InstallState -eq "Installed" -and $_.BestPracticesModelId -ne ""} | Select-Object BestPracticesModelID 
                $i=1
                $totalModels = $AvailableBPA.Count
                foreach ($BPAModel in $AvailableBPA) 
                {
                    Write-Progress -Activity "Scanning..." -status "$i Model(s) complete" -percentComplete ($i/$totalModels*100) 
                    Write-Host "Scanning with:" $BPAModel.BestPracticesModelId.ToString() -ForegroundColor Cyan
                    Scan-BPA($BPAmodel.BestPracticesModelId.ToString())         
                    $i++
                }
			}

			# Scan with specific BPA models
			function Scan-SpecBPA
			{
                $AvailableBPA = Get-WindowsFeature | Where-Object {$_. InstallState -eq "Installed" -and $_.BestPracticesModelId -ne ""} | Select-Object BestPracticesModelID 
                $modelID=0
                $totalModels = $AvailableBPA.Count
                foreach ($BPAModel in $AvailableBPA) 
                {
                   
                    Write-Host "[$modelID] ->" $BPAModel.BestPracticesModelId.ToString() -ForegroundColor Cyan      
                    $modelID++
                }
                Write-Host "[q] -> Back to BPA menu"  -ForegroundColor Yellow   
                $input = Read-Host "Please select a model"
      
                if  ($input -eq "q" -or $input -eq "Q") 
                {
                    return
                }
                
                if (([int]$input+1) -le $totalModels) 
                {
                    Write-Host "Scanning with " $AvailableBPA[$input].BestPracticesModelId.ToString() -ForegroundColor Cyan
                    Scan-BPA($AvailableBPA[$input].BestPracticesModelId.ToString())
                }
			}

			# Scan with BPA model in parameter object
			function Scan-BPA ([PSObject] $BPA)
			{
				
                #HTML-header
                $Head = " 
                <title>ADAuditor BPA Report for $BPA on $env:computername</title> 
                <style type='text/css'>  
                   table  { border-collapse: collapse; width: 700px }  
                   body   { font-family: Arial }  
                   td, th { border-width: 2px; border-style: solid; text-align: left;  
                padding: 2px 4px; border-color: black }  
                   th     { background-color: grey }  
                   td.Red { color: Red }  
                </style>"
                
                $BPAName = $BPA.Replace("Microsoft/Windows/","") 
				$Outfile_ADBPA = $OutFile + "_Scan-"+($BPAName)
				#Kick-off BPA scan
				Invoke-BPAModel -BestPracticesModelId $BPA -ErrorAction SilentlyContinue
				#Get BPA results, filter and export
				$BPAResults = Get-BPAResult -ModelID $BPA -ErrorAction SilentlyContinue |
									Where-Object {$_.Problem -ne $Null} |
									Select-Object ResultNumber,Severity,Category,Title,Problem,Impact,Resolution

				# Save as CSV
                $BPAResults | ConvertTo-CSV -NoTypeInformation | Out-File -FilePath $Outfile_ADBPA".csv"
                # Save as HTML
                $BPAResults | ConvertTo-Html -Title "ADAuditor BPA Report for $BPA on $env:computername" -Body "ADAuditor BPA Report for <b>$BPA</b> on server $env:computername <HR>" -Head $Head |
                                 Out-File -FilePath $Outfile_ADBPA".html"

			}

			do
			{
				Show-BPAModuleMenu
				$input = Read-Host "Please make a selection"
				switch ($input)
				{
					'1'{ List-BPAModels }
					'2'{ Scan-AllBPA }
					'3'{ Scan-SpecBPA }
					'4'{ Scan-BPA ("Microsoft/Windows/DirectoryServices") }
					'0'{ return }
				}
				#pause
			}
			until ($input -eq '0')
		}
	
    ########################################################################################################################
    # End of MS BPA module


    function Get-ServerInfo 
    {
        #Write all installed windows features to html/csv
        #Get-WindowsFeature | Where-Object {$_. InstallState -eq "Installed"} | convertto-html | out-file -filepath test.html


    }

    ######################
    # AD COMPUTER MODULE ###################################################################################################
    ######################
    function Invoke-AD-ComputerModule
    {
        function Show-AD-Computer-ModuleMenu # AD Computer Module menu
        {
            Write-Host "[ADAuditor]-[Domain Computer Module Menu:]" -ForegroundColor Green
			Write-Host "[1] - Find unsupported Operating Systems in the Domain"
			Write-Host "[2] - "
			Write-Host "[3] - "
			Write-Host "[4] - "
			Write-Host "[0] - "
        }
        
        function Get-UnsupportedOS # Search for EOL OS (i.e. Windows XP, 2000, 2003, etc.)
        {
            # Search for XP and 200x systems
            $xp= Get-ADComputer -Filter "OperatingSystem -like '*XP*' -or OperatingSystem -like '*200*'" -Properties OperatingSystem, IPv4Address,IPv6Address, OperatingSystemServicePack |Select-Object Name, IPv4Address,IPv6Address, OperatingSystem, OperatingSystemServicePack
            #Search for Win7 w/o SP1
            $win7= Get-ADComputer -Filter "OperatingSystem -like '*Windows 7*' -and OperatingSystemServicePack -ne 'Service Pack 2'" -Properties OperatingSystem, IPv4Address,IPv6Address, OperatingSystemServicePack |Select-Object Name, IPv4Address,IPv6Address, OperatingSystem, OperatingSystemServicePack
            # something causing error here when Win2k8 server is present in the domain.
            $outdatedOS= $xp+$win7
            if ($outdatedOS -ne $Null) 
            {
                Write-Host "** Unsupported Operating Systems found" -ForegroundColor Red
                # Write results to HTML/CSV files
                $Head = " 
                    <title>ADAuditor Unsupported OS Report for Domain</title> 
                    <style type='text/css'>  
                       table  { border-collapse: collapse; width: 700px }  
                       body   { font-family: Arial }  
                       td, th { border-width: 2px; border-style: solid; text-align: left;  
                    padding: 2px 4px; border-color: black }  
                       th     { background-color: grey }  
                       td.Red { color: Red }  
                    </style>"
                $outdatedOS|ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $OutFile"_EOL_OS.html"
                $outdatedOS|ConvertTo-HTML -Title "ADAuditor Unsupported OS Report for domain:"(Get-ADDomain | Select-Object Name).Name.toString() -Body "ADAuditor <b>Unsupported OS Report</b> for domain:"(Get-ADDomain | Select-Object Name).Name.toString() -Head $Head | Out-File -FilePath $OutFile"_EOL_OS.html"
            }
        }


        # Menu loop
        do
			{
				Show-AD-Computer-ModuleMenu
				$input = Read-Host "Please make a selection"
				switch ($input)
				{
					'1'{ Get-UnsupportedOS  }
					'2'{  }
					'3'{  }
					'4'{  }
					'0'{ return }
				}
				
			}
			until ($input -eq '0')


    }

    
    ########################################################################################################################
    # End of AD Computer module



    }
	

    process
	{
		# Main body here
        
        # Need to add folder creation

            do
			{
				Show-Menu
				$input = Read-Host "Please make a selection"
				switch ($input)
				{
					'1'{ Invoke-BPAModule }
					'2'{  }
					'3'{ Invoke-AD-ComputerModule }
					'4'{ }
					'0'{ return }
				}
				#pause
			}
			until ($input -eq '0')

	}
}

invoke-ADAudit test_project.testfile