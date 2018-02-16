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
                $fileDate = Get-Date
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
                $BPAResults | ConvertTo-Html -Title "ADAuditor BPA Report for $BPA on $env:computername" -Body "ADAuditor BPA Report for <b>$BPA</b> on server $env:computername <HR></b><br>Date: $fileDate" -Head $Head |
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
                $fileDate = Get-Date
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
                
                $outdatedOS|ConvertTo-HTML -Title "ADAuditor Unsupported OS Report for domain: $domainName" -Body "ADAuditor <b>Unsupported OS Report</b> for domain: $domainName</b><br>Date: $fileDate" -Head $Head | Out-File -FilePath $OutFile"_EOL_OS.html"
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
			Write-Host "[2] - Check AD Privileged Users"
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
            $fileDate = Get-Date
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
         
             $adAccountPolicy | ConvertTo-Html -Title "ADAuditor AD Account and Password Policies Compliance Report for: $domainName" -Body "ADAuditor <b>AD Account and Password Policies Compliance Report for:</b> $domainName</b><br>Date: $fileDate" -Head $Head | 
                foreach {$PSItem -replace "<td>Not Compliant", "<td style='background-color:#FF0000'>Not Compliant"} | 
                Out-File -FilePath $OutFile"_ADAccoutPolicy.html"
        
        }

        
       
        function Check-Priv-Users 
        {
        <# 1. Get all users withing following groups: (https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory)
                Access Control Assistance Operators
                Account Operators
                Administrators
                Allowed RODC Password Replication
                Backup Operators
                Cert Publishers
                Certificate Service DCOM Access
                Cloneable Domain Controllers
                Cryptographic Operators
                Denied RODC Password Replication Group
                DHCP Administrators
                DHCP Users
                Distributed COM Users
                DnsAdmins
                DnsUpdateProxy
                Domain Admins
                Domain Guests
                Enterprise Admins
                Group Policy Creator Owners
                Hyper-V Administrators 
                Incoming Forest Trust Builders
                Network Configuration Operators
                Performance Log Users
                Performance Monitor Users
                Print Operators
                Remote Desktop Services Users
                Schema Admins
                Server Operators
                Windows Authorization Access
                WinRMRemoteWMIUsers_

        2. For each user, check and flag if:
            * Did NOT logon in 60 days
            * Did NOT change password in 60 days
            * Never logged in
            * Not configured to use SmartCard (PIV)

            

        3. Check for presence of Debugger User.This is neither a default nor a built-in group, but when present in AD DS, is cause for further investigation.	
        The presence of a Debugger Users group indicates that debugging tools have been installed on the system at some point, whether via Visual Studio, SQL, Office, 
        or other applications that require and support a debugging environment. This group allows remote debugging access to computers. 
        When this group exists at the domain level, it indicates that a debugger or an application that contains a debugger has been installed on a domain controller.


        Based on the following code snippet: (https://social.technet.microsoft.com/Forums/ie/en-US/f238d2b0-a1d7-48e8-8a60-542e7ccfa2e8/recursive-retrieval-of-all-ad-group-memberships-of-a-user?forum=ITCG)
            $userdn = 'CN=Domain Admins,CN=Users,DC=saitslab2,DC=local'
            $strFilter = "(memberof:1.2.840.113556.1.4.1941:=$userdn)"
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://rootDSE")
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $objSearcher.SearchRoot = "LDAP://$($objDomain.rootDomainNamingContext)"
            $objSearcher.PageSize = 1000
            $objSearcher.Filter = $strFilter
            $objSearcher.SearchScope = "Subtree"
            $colProplist = "name","objectclass"
            foreach ($i in $colPropList){
               $objSearcher.PropertiesToLoad.Add($i) > $nul
               }
            $colResults = $objSearcher.FindAll()
            foreach ($objResult in $colResults)
                {
      
                  $objItem = $objResult.Properties
                  $objItem.name
                  #$objItem.objectclass
                        } 

        #>



        $PrivGroups =@("Access Control Assistance Operators",
                       "Account Operators",
                        "Administrators",
                        "Allowed RODC Password Replication",
                        "Backup Operators",
                        "Cert Publishers",
                        "Certificate Service DCOM Access",
                        "Cloneable Domain Controllers",
                        "Cryptographic Operators",
                        "Denied RODC Password Replication Group",
                        "DHCP Administrators",
                        "DHCP Users",
                        "Distributed COM Users",
                        "DnsAdmins",
                        "DnsUpdateProxy",
                        "Domain Admins",
                        "Domain Guests",
                        "Enterprise Admins",
                        "Group Policy Creator Owners",
                        "Hyper-V Administrators", 
                        "Incoming Forest Trust Builders",
                        "Network Configuration Operators",
                        "Performance Log Users",
                        "Performance Monitor Users",
                        "Print Operators",
                        "Remote Desktop Services Users",
                        "Schema Admins",
                        "Server Operators",
                        "Windows Authorization Access",
                        "WinRMRemoteWMIUsers_")

        #generate DN string for each group
        $GrpDNStrings =@()
        $UserNames =@()
        foreach ($PrivGrp in $PrivGroups) 
            {
            $GrpDN=Get-ADGroup -Filter 'name -like $PrivGrp' | Select-Object DistinguishedName            
            if ($GrpDN -ne $Null)
            {
                $GrpDNStrings +=[array]$GrpDN.DistinguishedName.toString()
                
            }

            }
    
        foreach ($GrpDNStr in $GrpDNStrings) 
            { 
            $strFilter = "(memberof:1.2.840.113556.1.4.1941:=$GrpDNStr)"
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry("LDAP://rootDSE")
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
            $objSearcher.SearchRoot = "LDAP://$($objDomain.rootDomainNamingContext)"
            $objSearcher.PageSize = 1000
            $objSearcher.Filter = $strFilter
            $objSearcher.SearchScope = "Subtree"
            $colProplist = "name","objectclass"
            foreach ($i in $colPropList){
               $objSearcher.PropertiesToLoad.Add($i) > $nul
               }
            $colResults = $objSearcher.FindAll()
            foreach ($objResult in $colResults)
                {
                  
                  $objItem = $objResult.Properties
                  
                  if ($objItem.objectclass -eq "user") {
                  $UserNames += [array]$objItem.name
                  }
                
                } 

        }
         #get unique names
         $UserNames=$UserNames | Sort-Object | Get-Unique
         
        
         function generateUserObject ($SAMName, $SID, $LastLogon, $LastPWChange, $isEnabled, $isSmartCard) # generate a standard user object for reporting results
            {
                $aUserObject = New-Object -TypeName PSObject 
                 $aUserObject |Add-Member -MemberType NoteProperty -Name SAMAccountName -Value $SAMName -PassThru | 
                                  Add-Member -MemberType NoteProperty -Name SID -Value $SID
                
                # check for last logon
                if ($LastLogon -ne $Null )
                {                
                                 $aUserObject | Add-Member -MemberType NoteProperty -Name LastLogon -Value ([DateTime]::fromFileTime($LastLogon))
                }
                else 
                {
                                 $aUserObject | Add-Member -MemberType NoteProperty -Name LastLogon -Value "Never"
                }
                
                # check last pw change
                if ($LastPWChange -ne $Null)
                {
                
                                  $aUserObject| Add-Member -MemberType NoteProperty -Name LastPassChange -Value ([DateTime]::fromFileTime($LastPWChange))
                }
                else 
                {
                                 $aUserObject | Add-Member -MemberType NoteProperty -Name LastPassChange -Value "Never"
                }
               
                # set InactiveAccount flag as needed
                if ($LastLogon -le ((get-date).AddDays(-90)).toFileTime()) # if account not logged in 90 days flag as inactive
                {                  
                        $aUserObject | Add-Member -MemberType NoteProperty -Name InactiveAcct -Value "Warning:Inactive account" 
                       
                }
                else 
                {                  
                        $aUserObject | Add-Member -MemberType NoteProperty -Name InactiveAcct -Value "OK" 
                       
                }


                if ($LastPWChange -le ((get-date).AddDays(-90)).toFileTime()) # if password was not chamged in 60 days flag as password not properly changed
                {                  
                        $aUserObject | Add-Member -MemberType NoteProperty -Name PassNotChanged -Value "Warning:Password was not changed in 90 days"
                }
                else 
                {
                        $aUserObject | Add-Member -MemberType NoteProperty -Name PassNotChanged -Value "OK"
                }
                # check if smart card is required
                if ($isSmartCard)
                {
                    $aUserObject | Add-Member -MemberType NoteProperty -Name SmartCardStatus -Value "Required"
                }
                else
                {
                    $aUserObject | Add-Member -MemberType NoteProperty -Name SmartCardStatus -Value "Not required"
                }
                # check if account is enabled
                if ($isEnabled)
                {
                    $aUserObject | Add-Member -MemberType NoteProperty -Name AcctStatus -Value "Enabled"
                }
                else
                {
                    $aUserObject | Add-Member -MemberType NoteProperty -Name AcctStatus -Value "Disabled"
                }
                


                #return object
                return [PSObject]$aUserObject

            }
        
             $PrivUsers =@()
             
             foreach ($User in $UserNames) 
             {          
                $TempUserObj=get-aduser -filter 'Name -eq $User' -Properties samaccountname, lastlogontimestamp, pwdLastSet, SmartcardLogonRequired 
                if ($TempUserObj -ne $Null) 
                {
                    $PrivUsers += [array] (generateUserObject $TempUserObj.samaccountname $TempUserObj.SID $TempUserObj.lastlogontimestamp $TempUserObj.pwdLastSet $TempUserObj.enabled $TempUserObj.SmartcardLogonRequired)
                }
         
            }
          
            # Write results to CSV and HTML files

            # CSV
            $PrivUsers |ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $OutFile"_ADPrivAccounts.csv"
            #HTML
            $domainName=(Get-ADDomain | Select-Object Name).Name.toString()
            $fileDate = Get-Date
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
         
             $PrivUsers | ConvertTo-Html -Title "ADAuditor AD Privileged Users Report for: $domainName" -Body "ADAuditor <b>AD AD Privileged Users Report for:</b> $domainName<br>Date: $fileDate" -Head $Head | 
                foreach {$PSItem -replace "<td>Warning:", "<td style='background-color:#FF0000'>Warning:"} | 
                foreach {$PSItem -replace "<td>OK", "<td style='background-color:#00FF00'>OK"} |
                foreach {$PSItem -replace "<td>Disabled", "<td style='background-color:#D3D3D3'>Disabled"} |
                foreach {$PSItem -replace "<td>Not required", "<td style='background-color:#FFFF00'>Not required"} |
                Out-File -FilePath $OutFile"_ADPrivAccounts.html"

        
        }
       
        function Check-AdmnistratorAcct 
        <# Check the status of buil-in Administrator account (RID 500) to validate if:
            * Account renamed
            * Account disabled
        #>
        {
             $ADaccts = get-aduser -Filter * -Properties samaccountname, sid | Select-Object samaccountname, sid, enabled
             foreach ($acct in $ADaccts)
             {
                   if (($acct.sid).toString() -like "*-500")
                   {
                        #Administrator account found
                        if ($acct.samaccountname -eq "Administrator")
                        {
                            Write-Host "[!!!] - Admnistrator account is not renamed" -ForegroundColor Red

                        }
                        if ($acct.enabled)
                        {
                            Write-Host "[!!!] - Admnistrator account is not disabled" -ForegroundColor Red

                        } 
                    }
             }   
        }
       
       
       
        # Menu loop
        do
			{
				Show-AD-User-ModuleMenu
				$input = Read-Host "Please make a selection"
				switch ($input)
				{
					'1'{ Check-AD-UserAccount-Policies }
					'2'{ Check-Priv-Users  }
					'3'{ Check-AdmnistratorAcct  }
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


    ###############################################
    ############# 3rd Party Functions #############
    ###############################################


    <#
	.Synopsis
	   This module will query Active Directory for the hostname, OS version, and service pack level  
	   for each computer account.  That information is then cross-referenced against a list of common
	   Metasploit exploits that can be used during penetration testing.

	.DESCRIPTION
	   This module will query Active Directory for the hostname, OS version, and service pack level  
	   for each computer account.  That information is then cross-referenced against a list of common
	   Metasploit exploits that can be used during penetration testing.  The script filters out disabled
	   domain computers and provides the computer's last logon time to help determine if it's been 
	   decommissioned.  Also, since the script uses data tables to output affected systems the results
	   can be easily piped to other commands such as test-connection or a Export-Csv.

	.EXAMPLE
	   The example below shows the standard command usage.  Disabled system are excluded by default, but
	   the "LastLgon" column can be used to determine which systems are live.  Usually, if a system hasn't 
	   logged on for two or more weeks it's been decommissioned.      

	   PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Format-Table -AutoSize
	   [*] Grabbing computer accounts from Active Directory...
	   [*] Loading exploit list for critical missing patches...
	   [*] Checking computers for vulnerable OS and SP levels...
	   [+] Found 5 potentially vulnerabile systems!

	   ComputerName          OperatingSystem         ServicePack    LastLogon            MsfModule                                      CVE                      
	   ------------          ---------------         -----------    ---------            ---------                                      ---                      
	   ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   ADS.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 5:46:52 PM  exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   LVA.demo.com          Windows Server 2003     Service Pack 2 4/8/2015 1:44:46 PM  exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   assess-xppro.demo.com Windows XP Professional Service Pack 3 4/1/2014 11:11:54 AM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   assess-xppro.demo.com Windows XP Professional Service Pack 3 4/1/2014 11:11:54 AM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   HVA.demo.com          Windows Server 2003     Service Pack 2 11/5/2013 9:16:31 PM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....
	   DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/dcerpc/ms07_029_msdns_zonename http://www.cvedetails....
	   DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/smb/ms08_067_netapi            http://www.cvedetails....
	   DB1.demo.com          Windows Server 2003     Service Pack 2 3/22/2012 5:05:34 PM exploit/windows/smb/ms10_061_spoolss           http://www.cvedetails....                     

	.EXAMPLE
	   The example below shows how to write the output to a csv file.

	   PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Export-Csv c:\temp\output.csv -NoTypeInformation

	.EXAMPLE
	   The example below shows how to pipe the resultant list of computer names into the test-connection to determine if they response to ping
	   requests.

	   PS C:\> Get-ExploitableSystems -DomainController 192.168.1.1 -Credential demo.com\user | Test-Connection

	 .LINK
	   http://www.netspi.com
	   
	 .NOTES
	   Author: Scott Sutherland - 2015, NetSPI
	   Version: Get-ExploitableSystems.psm1 v1.0
	   Comments: The technique used to query LDAP was based on the "Get-AuditDSComputerAccount" 
	   function found in Carols Perez's PoshSec-Mod project.  The general idea is based off of  
	   Will Schroeder's "Invoke-FindVulnSystems" function from the PowerView toolkit.

#>
function Get-ExploitableSystems
{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$false,
        HelpMessage="Credentials to use when connecting to a Domain Controller.")]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]$Credential = [System.Management.Automation.PSCredential]::Empty,
        
        [Parameter(Mandatory=$false,
        HelpMessage="Domain controller for Domain and Site that you want to query against.")]
        [string]$DomainController,

        [Parameter(Mandatory=$false,
        HelpMessage="Maximum number of Objects to pull from AD, limit is 1,000.")]
        [int]$Limit = 1000,

        [Parameter(Mandatory=$false,
        HelpMessage="scope of a search as either a base, one-level, or subtree search, default is subtree.")]
        [ValidateSet("Subtree","OneLevel","Base")]
        [string]$SearchScope = "Subtree",

        [Parameter(Mandatory=$false,
        HelpMessage="Distinguished Name Path to limit search to.")]

        [string]$SearchDN
    )
    Begin
    {
        if ($DomainController -and $Credential.GetNetworkCredential().Password)
        {
            $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
        else
        {
            $objDomain = [ADSI]""  
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        }
    }

    Process
    {

        # Status user
        Write-Host "[*] Grabbing computer accounts from Active Directory..."


        # ----------------------------------------------------------------
        # Setup data table for domain computer information
        # ----------------------------------------------------------------
    
        # Create data table for hostnames, os, and service packs from LDAP
        $TableAdsComputers = New-Object System.Data.DataTable 
        $TableAdsComputers.Columns.Add('Hostname') | Out-Null        
        $TableAdsComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableAdsComputers.Columns.Add('ServicePack') | Out-Null
        $TableAdsComputers.Columns.Add('LastLogon') | Out-Null


        # ----------------------------------------------------------------
        # Grab computer account information from Active Directory via LDAP
        # ----------------------------------------------------------------

        $CompFilter = "(&(objectCategory=Computer))"
        $ObjSearcher.PageSize = $Limit
        $ObjSearcher.Filter = $CompFilter
        $ObjSearcher.SearchScope = "Subtree"

        if ($SearchDN)
        {
            $objSearcher.SearchDN = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($SearchDN)")
        }

        $ObjSearcher.FindAll() | ForEach-Object {

            # Setup fields
            $CurrentHost = $($_.properties['dnshostname'])
            $CurrentOs = $($_.properties['operatingsystem'])
            $CurrentSp = $($_.properties['operatingsystemservicepack'])
            $CurrentLast = $($_.properties['lastlogon'])
            $CurrentUac = $($_.properties['useraccountcontrol'])

            # Convert useraccountcontrol to binary so flags can be checked
            # http://support.microsoft.com/en-us/kb/305144
            # http://blogs.technet.com/b/askpfeplat/archive/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory.aspx
            $CurrentUacBin = [convert]::ToString($CurrentUac,2)

            # Check the 2nd to last value to determine if its disabled
            $DisableOffset = $CurrentUacBin.Length - 2
            $CurrentDisabled = $CurrentUacBin.Substring($DisableOffset,1)

            # Add computer to list if it's enabled
            if ($CurrentDisabled  -eq 0){

                # Add domain computer to data table
                $TableAdsComputers.Rows.Add($CurrentHost,$CurrentOS,$CurrentSP,$CurrentLast) | Out-Null 
            }            
 
         }

        # Status user        
        Write-Host "[*] Loading exploit list for critical missing patches..."

        # ----------------------------------------------------------------
        # Setup data table for list of msf exploits
        # ----------------------------------------------------------------
    
        # Create data table for list of patches levels with a MSF exploit
        $TableExploits = New-Object System.Data.DataTable 
        $TableExploits.Columns.Add('OperatingSystem') | Out-Null 
        $TableExploits.Columns.Add('ServicePack') | Out-Null
        $TableExploits.Columns.Add('MsfModule') | Out-Null  
        $TableExploits.Columns.Add('CVE') | Out-Null
        
        # Add exploits to data table
        $TableExploits.Rows.Add("Windows 7","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 2","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 3","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","Service Pack 4","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/iis/ms03_007_ntdll_webdav","http://www.cvedetails.com/cve/2003-0109") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2000","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Server Pack 1","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/dcerpc/ms07_029_msdns_zonename","http://www.cvedetails.com/cve/2007-1748") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2003 R2","","exploit/windows/wins/ms04_045_wins","http://www.cvedetails.com/cve/2004-1080/") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Server 2008 R2","","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Server Pack 1","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows Vista","","exploit/windows/smb/ms09_050_smb2_negotiate_func_index","http://www.cvedetails.com/cve/2009-3103") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms04_011_lsass","http://www.cvedetails.com/cve/2003-0533/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms05_039_pnp","http://www.cvedetails.com/cve/2005-1983") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Server Pack 1","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_066_nwapi","http://www.cvedetails.com/cve/2006-4688") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms06_070_wkssvc","http://www.cvedetails.com/cve/2006-4691") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 2","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","Service Pack 3","exploit/windows/smb/ms10_061_spoolss","http://www.cvedetails.com/cve/2010-2729") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms03_026_dcom","http://www.cvedetails.com/cve/2003-0352/") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/dcerpc/ms05_017_msmq","http://www.cvedetails.com/cve/2005-0059") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms06_040_netapi","http://www.cvedetails.com/cve/2006-3439") | Out-Null  
        $TableExploits.Rows.Add("Windows XP","","exploit/windows/smb/ms08_067_netapi","http://www.cvedetails.com/cve/2008-4250") | Out-Null  

    

        # Status user        
        Write-Host "[*] Checking computers for vulnerable OS and SP levels..."

        # ----------------------------------------------------------------
        # Setup data table to store vulnerable systems
        # ----------------------------------------------------------------
        
        # Create data table to house vulnerable server list
        $TableVulnComputers = New-Object System.Data.DataTable 
        $TableVulnComputers.Columns.Add('ComputerName') | Out-Null
        $TableVulnComputers.Columns.Add('OperatingSystem') | Out-Null
        $TableVulnComputers.Columns.Add('ServicePack') | Out-Null
        $TableVulnComputers.Columns.Add('LastLogon') | Out-Null
        $TableVulnComputers.Columns.Add('MsfModule') | Out-Null  
        $TableVulnComputers.Columns.Add('CVE') | Out-Null   
        
        # Iterate through each exploit
        $TableExploits | 
        ForEach-Object {
                     
            $ExploitOS = $_.OperatingSystem
            $ExploitSP = $_.ServicePack
            $ExploitMsf = $_.MsfModule
            $ExploitCve = $_.CVE

            # Iterate through each ADS computer
            $TableAdsComputers | 
            ForEach-Object {
                
                $AdsHostname = $_.Hostname
                $AdsOS = $_.OperatingSystem
                $AdsSP = $_.ServicePack                                                        
                $AdsLast = $_.LastLogon
                
                # Add exploitable systems to vul computers data table
                if ($AdsOS -like "$ExploitOS*" -and $AdsSP -like "$ExploitSP" ){                    
                   
                    # Add domain computer to data table                    
                    $TableVulnComputers.Rows.Add($AdsHostname,$AdsOS,$AdsSP,[dateTime]::FromFileTime($AdsLast),$ExploitMsf,$ExploitCve) | Out-Null 
                }

            }

        }     
        

        # Display results
        $VulnComputer = $TableVulnComputers | select ComputerName -Unique | measure
        $vulnComputerCount = $VulnComputer.Count
        If ($VulnComputer.Count -gt 0){

            # Return vulnerable server list order with some hack date casting
            Write-Host "[+] Found $vulnComputerCount potentially vulnerabile systems!"
            $TableVulnComputers | Sort-Object { $_.lastlogon -as [datetime]} -Descending

        }else{

            Write-Host "[-] No vulnerable systems were found."

        }      

    }

    End
    {

    }
}

####################################
### end of 3rd party functions #####
####################################





### temporary for testing ###


invoke-ADAudit test_project.testfile