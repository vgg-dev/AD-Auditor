#Require -runAsAdministrator

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
                    Write-Host "[*] - Scanning with:" $BPAModel.BestPracticesModelId.ToString() -ForegroundColor Cyan
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
                                 foreach {$PSItem -replace "<td>Error", "<td style='background-color:#FF0000'>Error"} |
                                 foreach {$PSItem -replace "<td>Warning", "<td style='background-color:#FFA500'>Warning"} |
                                 foreach {$PSItem -replace "<td>Information", "<td style='background-color:#00FF00'>Information"} |
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
            $outdatedOS =@()
            $outdatedOS= [array]$xp+$win7
            if ($outdatedOS -ne $Null) 
            {
                Write-Host "** Unsupported Operating Systems found" -ForegroundColor Red
                # Write results to HTML/CSV files
                $domainName=(Get-ADDomain | Select-Object Name).Name.toString()
                $Head = " 
                    <title>ADAuditor Unsupported OS Report for Domain: $domainName</title> 
                    <style type='text/css'>  
                       table  { border-collapse: collapse; width: 700px }  
                       body   { font-family: Arial }  
                       td, th { border-width: 2px; border-style: solid; text-align: left;  
                                padding: 2px 4px; border-color: black }  
                       th     { background-color: grey }  
                       td.Red { color: Red }  
                    </style>"
                $outdatedOS|ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $OutFile"_EOL_OS.csv"
                
                $outdatedOS|ConvertTo-HTML -Title "ADAuditor Unsupported OS Report for domain: $domainName" -Body "ADAuditor <b>Unsupported OS Report</b> for domain: $domainName" -Head $Head | Out-File -FilePath $OutFile"_EOL_OS.html"
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



    ######################
    # AD User MODULE ###################################################################################################
    ######################

    function Invoke-AD-UserModule
    {
        function Show-AD-User-ModuleMenu # AD Computer Module menu
        {
            Write-Host "[ADAuditor]-[Domain User Module Menu:]" -ForegroundColor Green
			Write-Host "[1] - Check Domain Account Policies"
			Write-Host "[2] - "
			Write-Host "[3] - "
			Write-Host "[4] - "
			Write-Host "[0] - "
        }
        #Checks based on CIS Win2012R2 benchmark
        function Check-AD-UserAccount-Policies 
        {
            function Get-Policy-Object ($Check, $Condition, $CISCompliance, $NISTControl, $Rationale) # generate a standard policy object for reporting results
            {
                $PolicyObject = New-Object -TypeName PSObject 
                 $PolicyObject |Add-Member -MemberType NoteProperty -Name Check -Value $Check -PassThru | 
                                  Add-Member -MemberType NoteProperty -Name Condition -Value $Condition -PassThru |
                                  Add-Member -MemberType NoteProperty -Name CISCompliance -Value $CISCompliance -PassThru |
                                  Add-Member -MemberType NoteProperty -Name 800-53Control -Value $NISTControl -PassThru |
                                  Add-Member -MemberType NoteProperty -Name Rationale -Value $Rationale
                return [PSObject]$PolicyObject

            }
            
            
            
            $domainName=(Get-ADDomain | Select-Object Name).Name.toString()
            $RootDSE = Get-ADRootDSE -Server $domainName
            $AccountPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property lockoutDuration, lockoutObservationWindow, lockoutThreshold
            $PasswordPolicy = Get-ADObject $RootDSE.defaultNamingContext -Property minPwdAge, maxPwdAge, minPwdLength, pwdHistoryLength, pwdProperties 
            # create a custom adAccountPolicy object
            $adAccountPolicy =@()
            
            #### check password history > 24 (CIS Win 2012R2 benchmark 1.1.1) ####

            $PassHistRationale=[array] "The longer a user uses the same password, the greater the chance that an attacker can determine the password through brute force attacks."+
            " Also, any accounts that may have been compromised will remain exploitable for as long as the password is left unchanged. If password changes are required but password"+
            " reuse is not prevented, or if users continually reuse a small number of passwords, the effectiveness of a good password policy is greatly reduced."

            $PassHistRationale = [system.String]::Join(" ", $PassHistRationale)

            if ($PasswordPolicy.pwdHistoryLength -ge 24) 
            {
                $PassHistory = Get-Policy-Object "Password History (passwords)" $PasswordPolicy.pwdHistoryLength "Compliant" "AC-2" $PassHistRationale
            }
            
            else 
            {
               
               $PassHistory = Get-Policy-Object "Password History (passwords)" $PasswordPolicy.pwdHistoryLength "Not Compliant (>24)" "AC-2" $PassHistRationale
            }

                                 
            ####check password max age 1.1.2 (L1) Ensure 'Maximum password age' is set to '60 or fewer days, but not 0' ####
            
             $PassMaxAgeRationale=[array] "The longer a password exists the higher the likelihood that it will be compromised by a"+
                                            "brute force attack, by an attacker gaining general knowledge about the user, or by the user"+
                                            "sharing the password. Configuring the Maximum password age setting to 0 so that users"+
                                            "are never required to change their passwords is a major security risk because that allows a"+
                                            "compromised password to be used by the malicious user for as long as the valid user is"+
                                            "authorized access."

            $PassMaxAgeRationale = [system.String]::Join(" ", $PassMaxAgeRationale)
            
            if (($PasswordPolicy.maxPwdAge/-864000000000)  -le 60 -and ($PasswordPolicy.maxPwdAge) -ne -9223372036854775808) # compliant
            {
                $PassMaxAge = Get-Policy-Object "Password Max Age (days)" ($PasswordPolicy.maxPwdAge/-864000000000) "Compliant" "AC-2" $PassMaxAgeRationale
            }
            #check if max age is 0 (value -9223372036854775808)
            elseif (($PasswordPolicy.maxPwdAge) -eq -9223372036854775808) 
            {
                
                 $PassMaxAge = Get-Policy-Object "Password Max Age (days)" 0 "Not Compliant (=0)" "AC-2" $PassMaxAgeRationale
            }
           
            else #not compliant
            {
               
               $PassMaxAge = Get-Policy-Object "Password Max Age (days)" ($PasswordPolicy.maxPwdAge/-864000000000) "Not Compliant (>60)" "AC-2" $PassMaxAgeRationale
            }

            
            ####check password min age 1.1.2  (L1) Ensure 'Minimum password age' is set to '1 or more day(s)'  ####
            
            $PassMinAgeRationale=[array] "To address password reuse a combination of"+
                                            "security settings is required. Using this policy setting with the Enforce password history"+
                                            "setting prevents the easy reuse of old passwords. For example, if you configure the Enforce"+
                                            "password history setting to ensure that users cannot reuse any of their last 12 passwords,"+
                                            "they could change their password 13 times in a few minutes and reuse the password they"+
                                            "started with, unless you also configure the Minimum password age setting to a number that"+
                                            "is greater than 0. "

            $PassMinAgeRationale = [system.String]::Join(" ", $PassMinAgeRationale)
            
       
            if (($PasswordPolicy.minPwdAge/-864000000000)  -ge 1 -and ($PasswordPolicy.minPwdAge) -ne -9223372036854775808) # compliant
            {
                $PassMinAge = Get-Policy-Object "Password Min Age (days)" ($PasswordPolicy.minPwdAge/-864000000000) "Compliant" "AC-2" $PassMinAgeRationale
            }
            #check if max age is 0 (value -9223372036854775808)
            elseif (($PasswordPolicy.minPwdAge) -eq -9223372036854775808) 
            {
                
                 $PassMinAge = Get-Policy-Object "Password Min Age (days)" 0 "Not Compliant (=0)" "AC-2" $PassMinAgeRationale
            }
            else #not compliant
            {
               
               $PassMinAge = Get-Policy-Object "Password Min Age (days)" ($PasswordPolicy.minPwdAge/-864000000000) "Not Compliant (<1)" "AC-2" $PassMinAgeRationale
            }
            
            ####check 1.1.4 (L1) Ensure 'Minimum password length' is set to '14 or more character(s)'   ####
            
            $PassMinLenRationale=[array] "Types of password attacks include dictionary attacks (which attempt to use common words"+
                                            "and phrases) and brute force attacks (which try every possible combination of characters)."+
                                            "Also, attackers sometimes try to obtain the account database so they can use tools to"+
                                            "discover the accounts and passwords."

            $PassMinLenRationale = [system.String]::Join(" ", $PassMinLenRationale)
            
            if (($PasswordPolicy.minPwdLength)  -ge 14 ) # compliant
            {
                $PassMinLen = Get-Policy-Object "Password Minimum Lenght (characters)" $PasswordPolicy.minPwdLength "Compliant" "AC-2" $PassMinLenRationale
            }          
            else #not compliant
            {
               
               $PassMinLen = Get-Policy-Object "Password Minimum Lenght (characters)" $PasswordPolicy.minPwdLength "Not Compliant (<14)" "AC-2" $PassMinLenRationale
            }
        

            #### check password complexity ####
            $PassComplexityRationale = [array]"Account with simple passwords are extremely easy to brute-force with"+
                                                "several publicly available tools."
            $PassComplexityRationale = [system.String]::Join(" ", $PassComplexityRationale)

            Switch ($PasswordPolicy.pwdProperties) 
            {

                                      0 {$PwdPropText="Passwords can be simple and the administrator account cannot be locked out"}

                                      1 {$PwdPropText="Passwords must be complex and the administrator account cannot be locked out"}

                                      8 {$PwdPropText="Passwords can be simple, and the administrator account can be locked out"}

                                      9 {$PwdPropText="Passwords must be complex, and the administrator account can be locked out"}

                                      Default {$PwdPropText="Unknown code" }
            }
        
            if ($PasswordPolicy.pwdProperties -eq 1 -or $PasswordPolicy.pwdProperties -eq 9) #compliant
            {
                $PassComplexity = Get-Policy-Object "Password Complexity" $PwdPropText "Compliant" "AC-2"  $PassComplexityRationale

                                 
            }
            else 
            {   $PassComplexity = Get-Policy-Object "Password Complexity" $PwdPropText "Not Compliant" "AC-2"  $PassComplexityRationale
            }
        

            #### check account lockout duration 1.2.1 (L1) Ensure 'Account lockout duration' is set to '15 or more minute(s)

            $AcctLockoutRationale = [array] "A denial of service (DoS) condition can be created if an attacker abuses the Account lockout"+
                                            "threshold and repeatedly attempts to log on with a specific account."+
                                            "If you configure the Account lockout duration setting to 0, then the"+
                                            "account will remain locked out until an administrator unlocks it manually. [CCE-37034-6]"
            $AcctLockoutRationale = [system.String]::Join(" ", $AcctLockoutRationale)

            if (($AccountPolicy.lockoutDuration/-600000000) -ge 15)
            {
                $AcctLockout = Get-Policy-Object "Account Lockout (min)" ($AccountPolicy.lockoutDuration/-600000000) "Compliant" "AC-2" $AcctLockoutRationale
            }
            else
            {
                $AcctLockout = Get-Policy-Object "Account Lockout (min)" ($AccountPolicy.lockoutDuration/-600000000) "Not Compliant (<15)" "AC-2" $AcctLockoutRationale

            }

            #check account threshold 1.2.2 (L1) Ensure 'Account lockout threshold' is set to '10 or fewer invalid logon attempt(s), but not 0' 
            
                      
            $AcctThresholdRationale = [array] "Proper lockout threshold reduces the likelihood of successful a brute"+
                                              "force attack. [CCE-36008-1]"
            $AcctThresholdRationale = [system.String]::Join(" ", $AcctThresholdRationale)
            if ($AccountPolicy.lockoutThreshold -le 10 -and $AccountPolicy.lockoutThreshold -ne 0)
            {
                $AcctThreshold = Get-Policy-Object "Account Lockout Threshold (failed logon attempts)" $AccountPolicy.lockoutThreshold "Compliant" "AC-2" $AcctThresholdRationale
            }
            else
            {
                $AcctThreshold = Get-Policy-Object "Account Lockout Threshold (failed logon attempts)" $AccountPolicy.lockoutThreshold "Not Compliant (>10 or =0)" "AC-2" $AcctThresholdRationale
            }

            #check lockout obseravtion window  (L1) Ensure 'Reset account lockout counter after' is set to '15 or more minute(s)' 

            $LockoutObsWindowRationale = [array] "If you configure the value to an interval that is too long, your environment could be vulnerable to a DoS attack."+
                                                 "[CCE-36883-7]"
            $LockoutObsWindowRationale = [System.String]::Join(" ", $LockoutObsWindowRationale)
            if (($AccountPolicy.lockoutObservationWindow/-600000000) -ge 15) #compliant
            {
                $LockoutObsWindow= Get-Policy-Object "Account Observation Window" ($AccountPolicy.lockoutObservationWindow/-600000000) "Compliant" "AC-2" $LockoutObsWindowRationale
            }
            else
            {
                $LockoutObsWindow= Get-Policy-Object "Account Observation Window" ($AccountPolicy.lockoutObservationWindow/-600000000) "Not Compliant (<15)" "AC-2" $LockoutObsWindowRationale
            }

            # Combine objects into array for export    
            $adAccountPolicy = [array]$PassHistory+$PassMaxAge+$PassMinAge+$PassMinLen+$PassComplexity+$AcctLockout+$AcctThreshold+$LockoutObsWindow
            
            $adAccountPolicy | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $OutFile"_ADAccoutPolicy.csv"
            $domainName=(Get-ADDomain | Select-Object Name).Name.toString()
            $Head = " 
                    <title>ADAuditor AD Account and Password Policies Compliance Report for: $domainName</title> 
                    <style type='text/css'>  
                       table  { border-collapse: collapse; width: 700px }  
                       body   { font-family: Arial }  
                       td, th { border-width: 2px; border-style: solid; text-align: left;  
                                padding: 2px 4px; border-color: black }  
                       th     { background-color: grey }  
                       td.Red { color: Red }  
                    </style>"
         
             $adAccountPolicy | ConvertTo-Html -Title "ADAuditor AD Account and Password Policies Compliance Report for: $domainName" -Body "ADAuditor <b>AD Account and Password Policies Compliance Report for:</b> $domainName" -Head $Head | 
                foreach {$PSItem -replace "<td>Not Compliant", "<td style='background-color:#FF0000'>Not Compliant"} | 
                Out-File -FilePath $OutFile"_ADAccoutPolicy.html"
        
        }

        # Menu loop
        do
			{
				Show-AD-User-ModuleMenu
				$input = Read-Host "Please make a selection"
				switch ($input)
				{
					'1'{ Check-AD-UserAccount-Policies }
					'2'{  }
					'3'{  }
					'4'{  }
					'0'{ return }
				}
				
			}
			until ($input -eq '0')


    }
    
    ########################################################################################################################
    # End of AD User module

    

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
					'2'{ Invoke-AD-UserModule }
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