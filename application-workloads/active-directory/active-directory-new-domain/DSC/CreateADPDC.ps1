configuration CreateADPDC 
{ 
    param 
    ( 
        [Parameter(Mandatory)]
        [String]$DomainName,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$Admincreds,

        [Int]$RetryCount = 20,
        [Int]$RetryIntervalSec = 30
    ) 
    
    Import-DscResource -ModuleName xActiveDirectory, xStorage, xNetworking, PSDesiredStateConfiguration, xPendingReboot
    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($Admincreds.UserName)", $Admincreds.Password)
    $Interface = Get-NetAdapter | Where Name -Like "Ethernet*" | Select-Object -First 1
    $InterfaceAlias = $($Interface.Name)

    Node localhost
    {
        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            ActionAfterReboot = 'ContinueConfiguration'
        }

        PendingReboot {
            Ensure = "Present"
        }
        
        WindowsFeature DNS { 
            Ensure = "Present" 
            Name   = "DNS"		
        }

        Script GuestAgent {
            SetScript  = {
                Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WindowsAzureGuestAgent' -Name DependOnService -Type MultiString -Value DNS
                Write-Verbose -Verbose "GuestAgent depends on DNS"
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = "[WindowsFeature]DNS"
        }

        Script EnableDNSDiags {
            SetScript  = { 
                Set-DnsServerDiagnostics -All $true
                Write-Verbose -Verbose "Enabling DNS client diagnostics" 
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = "[WindowsFeature]DNS"
        }

        WindowsFeature DnsTools {
            Ensure    = "Present"
            Name      = "RSAT-DNS-Server"
            DependsOn = "[WindowsFeature]DNS"
        }

        xDnsServerAddress DnsServerAddress 
        { 
            Address        = '127.0.0.1' 
            InterfaceAlias = $InterfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn      = "[WindowsFeature]DNS"
        }

        xWaitforDisk Disk2
        {
            DiskNumber = 2
            RetryIntervalSec =$RetryIntervalSec
            RetryCount = $RetryCount
        }

        xDisk ADDataDisk {
            DiskNumber  = 2
            DriveLetter = "F"
            DependsOn   = "[xWaitForDisk]Disk2"
        }

        WindowsFeature ADDSInstall { 
            Ensure    = "Present" 
            Name      = "AD-Domain-Services"
            DependsOn = "[WindowsFeature]DNS" 
        } 

        WindowsFeature ADDSTools {
            Ensure    = "Present"
            Name      = "RSAT-ADDS-Tools"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }

        WindowsFeature ADAdminCenter {
            Ensure    = "Present"
            Name      = "RSAT-AD-AdminCenter"
            DependsOn = "[WindowsFeature]ADDSInstall"
        }
         
        xADDomain FirstDS 
        {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = "F:\NTDS"
            LogPath                       = "F:\NTDS"
            SysvolPath                    = "F:\SYSVOL"
            DependsOn                     = @("[xDisk]ADDataDisk", "[WindowsFeature]ADDSInstall")
        } 

        Configuration CheckReboot {
            Import-DscResource -ModuleName xPendingReboot
            Node localhost {
                xPendingReboot RebootCheck {
                    Name = "CheckReboot"
                }
            }
        }

        Script CreateOUs {
            SetScript  = {
                Import-Module ActiveDirectory
                New-ADOrganizationalUnit 'ToSync' -path 'DC=adatum,DC=com' -ProtectedFromAccidentalDeletion $false
                New-ADOrganizationalUnit 'AVDClients' -path 'DC=adatum,DC=com' -ProtectedFromAccidentalDeletion $false
                Write-Verbose -Verbose "Created OUs"
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = "[xADDomain]FirstDS"
        }

        Script CreateUsers {
            SetScript  = {
                $ouName = 'ToSync'
                $ouPath = "OU=$ouName,DC=adatum,DC=com"
                $adUserNamePrefix = 'aduser'
                $adUPNSuffix = 'adatum.com'
                $userCount = 1..9
                foreach ($counter in $userCount) {
                    New-AdUser -Name $adUserNamePrefix$counter -Path $ouPath -Enabled $True `
                        -ChangePasswordAtLogon $false -userPrincipalName $adUserNamePrefix$counter@$adUPNSuffix `
                        -AccountPassword (ConvertTo-SecureString 'Pa55w.rd1234!' -AsPlainText -Force) -passThru
                } 

                $adUserNamePrefix = 'avdadmin1'
                $adUPNSuffix = 'adatum.com'
                New-AdUser -Name $adUserNamePrefix -Path $ouPath -Enabled $True `
                    -ChangePasswordAtLogon $false -userPrincipalName $adUserNamePrefix@$adUPNSuffix `
                    -AccountPassword (ConvertTo-SecureString 'Pa55w.rd1234!' -AsPlainText -Force) -passThru

            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = '[Script]CreateOUs'
        }

        Script CreateGroups {
            SetScript  = {
                New-ADGroup -Name 'az140-avd-pooled' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
                New-ADGroup -Name 'az140-avd-remote-app' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
                New-ADGroup -Name 'az140-avd-personal' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
                New-ADGroup -Name 'az140-avd-users' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
                New-ADGroup -Name 'az140-avd-admins' -GroupScope 'Global' -GroupCategory Security -Path $ouPath
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = '[Script]CreateUsers'
        }

        Script AddGroupMembers {
            SetScript  = {
                Add-ADGroupMember -Identity 'az140-avd-pooled' -Members 'aduser1', 'aduser2', 'aduser3', 'aduser4'
                Add-ADGroupMember -Identity 'az140-avd-remote-app' -Members 'aduser1', 'aduser5', 'aduser6'
                Add-ADGroupMember -Identity 'az140-avd-personal' -Members 'aduser7', 'aduser8', 'aduser9'
                Add-ADGroupMember -Identity 'az140-avd-users' -Members 'aduser1', 'aduser2', 'aduser3', 'aduser4', 'aduser5', 'aduser6', 'aduser7', 'aduser8', 'aduser9'
                Add-ADGroupMember -Identity 'az140-avd-admins' -Members 'avdadmin1'
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = '[Script]CreateGroups'
        }

        Script InstallLibraries {
            SetScript  = {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-Module -Name PowerShellGet -Force -SkipPublisherCheck
                Install-Module -Name Az -AllowClobber -SkipPublisherCheck -Force
                Install-Module -Name AzureAD -Force -SkipPublisherCheck
            }
            GetScript  = { @{} }
            TestScript = { $false }
            DependsOn  = '[Script]AddGroupMembers'
        }

        

    }
} 
