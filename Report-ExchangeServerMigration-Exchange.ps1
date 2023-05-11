<#
.SYNOPSIS
    Generates a report with details collected from an on-prem Exchange Server for migration to Outlook Online.

.DESCRIPTION
    This PowerShell script collects various details from an on-prem Exchange server to assist with planning a migration to Outlook Online. 
    This script generates a text report with the following details:
    - Exchange Server network details, including domain NetBIOS name, domain FQDN, IP address, subnet mask, default gateway, and DNS servers.
    - Number of Exchange Servers
    - Number of Exchange, Databases, Paths, and Sizes
    - Number of Groups, Contacts, Shared Mailboxes, Public Folders, Mail Flow Rules
    - Enabled users, UPN and mailbox sizes
    - Mail Certificate Details
    - Certificate Subject Alternative Name
    - Send and Receive Connector details
    - Exchange Admin Center
    - Internal and External Entries for ECP, EAS, EWS, OAB, OWA, PowerShell
    - All Exchange Certificate Details
    - Application and System Event Logs Warnings, Errors, Critical (past 15 days) without duplicates

.EXAMPLE !!! Set-Execution Policy to Bypass !!!
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Report-ExchangeServerMigration-Exchange.ps1
    Runs the script and generates a report file on the desktop with details collected from the Exchange server.

.NOTES
    This script must be run as a local administrator with appropriate Exchange permissions on Exchange Server.

.NOTES
    Version: 1.0
    Author: Bentley
    Creation Date: 2023-05-09
    https://github.com/bentman/PoShDiscoveryTemplate/upload/main
#>

# Set report name
$ReportName = "Report-ExchangeServerMigration-Exchange"

# Set output file path
$OutputFile = "$env:USERPROFILE\Desktop\$ReportName.txt"

# Set transcript file path
$TranscriptPath = "$env:USERPROFILE\Desktop\$ReportName.log"
# Start transcript
Start-Transcript -Path $transcriptPath -Append

# Initialize report content as an empty string
$ReportContent = ""

# Function to add a section header to the report
function Add-SectionHeader {
    param (
        [string]$Title
    )
    $script:ReportContent += "`n`n`n$Title`n"
    $script:ReportContent += '-' * $Title.Length
}

# Function to add a line of text to the report
function Add-Line {
    param (
        [string]$Text
    )
    $script:ReportContent += "`n$Text"
}

# Function to add a warning to the report
function Add-Warning {
    param (
        [string]$Text
    )
    $script:ReportContent += "`n[WARNING] $Text"
}

# Function to add an error to the report
function Add-Error {
    param (
        [string]$Text
    )
    $script:ReportContent += "`n[ERROR] $Text"
}

# Function to get external IP address
function Get-ExternalIpAddress {
    try {
        $ExternalIp = (Invoke-WebRequest -Uri 'https://ipinfo.io/ip' -UseBasicParsing).Content.Trim()
    }
    catch {
        $ExternalIp = "Unable to retrieve external IP"
    }
    return $ExternalIp
}

# Function to detect Exchange version
function Get-ExchangeVersion {
    $ExchangeVersion = $null

    # Check for Exchange 2010
    if (Test-Path "C:\Program Files\Microsoft\Exchange Server\V14\bin\RemoteExchange.ps1") {
        $ExchangeVersion = "2010"
    }
    # Check for Exchange 2013, 2016, or 2019
    elseif (Test-Path "C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1") {
        $ExchangeVersion = "2013-2019"
    }
    return $ExchangeVersion
}

# Load Exchange module or connect to Exchange Management Shell
$ExchangeVersion = Get-ExchangeVersion
$LocalServerFQDN = [System.Net.Dns]::GetHostEntry([System.Net.Dns]::GetHostName()).HostName

switch ($ExchangeVersion) {
    "2010" {
        Import-Module -Name Microsoft.Exchange.Management.PowerShell.E2010
    }
    "2013-2019" {
        # Set the Exchange Management Shell URL for your server
        $ExchangeManagementShellUrl = "http://$LocalServerFQDN/PowerShell/"

        # Create a PSSession and import the Exchange cmdlets
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $ExchangeManagementShellUrl -Authentication Kerberos
        Import-PSSession $Session
    }
    default {
        Write-Error "Exchange version not detected or not supported"
        exit
    }
}

# Import required modules if available
$modules = @(
    "ActiveDirectory",
    "DnsServer",
    "NetTCPIP",
    "ServerManager",
    "GroupPolicy",
    "DFSR",
    "ADMT"
)

foreach ($module in $modules) {
    try {
        Import-Module -Name $module -ErrorAction SilentlyContinue
    }
    catch {
        Add-Error "Unable to import module $($module): $($_.Exception.Message)"
    }
}

# Add report header
Add-SectionHeader "Report - $ReportName"
Add-Line "Date: $(Get-Date -Format 'yyyy-MM-dd')"

# Add Exchange version and server FQDN to the report
Add-SectionHeader "Exchange Server Information"
Add-Line "Exchange Version: $ExchangeVersion"

# Get the server's FQDN addresses
Add-Line "Server FQDN: $LocalServerFQDN"

# Add Windows OS Information
Add-SectionHeader "Windows OS Information"
$osInfo = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
Add-Line "Windows OS: $($osInfo.ProductName)"
Add-Line "Version: $($osInfo.ReleaseId)"
Add-Line "Build: $($osInfo.BuildLabEx.Split('.')[0])"
Add-Line "UBR: $($osInfo.UBR)"
Add-Line "LCU Version: $($osInfo.LCUVer)"

# Add server network details section
Add-SectionHeader "ADDC Server Information"

# Get the server's FQDN addresses
$serverFQDNs = $ipAddresses | ForEach-Object { 
    [System.Net.Dns]::GetHostByAddress($_).HostName 
    }
Add-Line "Server FQDN(s): `n    $($serverFQDNs -join '`n    , ')"

# Add server network details section
Add-SectionHeader "Server Network Details"

# Get the server's IP addresses
$ipAddresses = [System.Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | 
    Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
    Select-Object -ExpandProperty IPAddressToString
Add-Line "Server IP Address(es): `n    $($ipAddresses -join '`n    , ')"

# Get the internal IP address of the server
$addcServerInternalIpAddress = (Get-NetIPAddress -AddressFamily IPv4 | 
    Where-Object { $_.InterfaceAlias `
        -ne 'Loopback Pseudo-Interface 1' `
        -and $_.Address -notmatch '^169\.254\.' `
        -and $_.Address -notmatch '^127\.'}).IPAddress

# Get the external IP address
$addcServerExternalIpAddress = Get-ExternalIpAddress

# Display IP addresses
Add-Line "Internal IP Address: `n    $addcServerInternalIpAddress"
Add-Line "External IP Address: `n    $addcServerExternalIpAddress"

# Iterate through each adapter and collect FQDN, DNS, and gateway information
$adapters = Get-NetAdapter -Physical
foreach ($adapter in $adapters) {
    $adapterName = $adapter.Name
    $dnsServers = (Get-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4).ServerAddresses -join ', '
    $gatewayAddress = (Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).NextHop

    # Get the adapter's FQDNs
    $adapterFQDNs = $ipAddresses | ForEach-Object { [System.Net.Dns]::GetHostByAddress($_).HostName }

    Add-Line "`nAdapter Name: `n    $adapterName"
    Add-Line "FQDN(s): `n    $($adapterFQDNs -join ', ')"
    Add-Line "Default Gateway: `n    $gatewayAddress"
    Add-Line "DNS Servers: `n    $dnsServers"

    # Check for potential DNS server contention and multiple gateways
    $dnsServerGroups = $dnsServers -split ',' | Group-Object | Where-Object { $_.Count -gt 1 }
    if ($dnsServerGroups) {
        Add-Warning "Potential DNS server contention on adapter $adapterName"
    }
    $gatewayCount = (Get-NetRoute -InterfaceIndex $adapter.InterfaceIndex -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' }).Count
    if ($gatewayCount -gt 1) {
        Add-Warning "Potential multiple gateways on adapter $adapterName"
    }
}

# *** Begin adding your code snippets here ***
# Use Add-SectionHeader to create a new section, 
# Use Add-Line to add details,
# Use Add-Warning to add warnings, 
# Use Add-Error to add errors

# Add number of Exchange Servers section
$exchangeServers = Get-ExchangeServer
$exchangeServerCount = $exchangeServers.Count
Add-Line "Exchange Servers: $exchangeServerCount"

# Add Exchange Server List
$exchangeServersList = $exchangeServers | Format-List
Add-Line "Exchange Server List: `n$exchangeServersList"

# Add Exchange databases section
$databases = Get-MailboxDatabase | Select-Object Name, EdbFilePath, DatabaseSize
Add-Line "Number Exchange of Databases: $($databases.Count)"

foreach ($database in $databases) {
    Add-Line "Name: $($database.Name) - Path: $($database.EdbFilePath) - Size: $($database.DatabaseSize)"
}

# Add number of Exchange groups, contacts, shared mailbox, and public folder section
$groupCount = (Get-Group -ResultSize Unlimited).Count
$contactCount = (Get-Contact -ResultSize Unlimited).Count
$sharedMailboxCount = (Get-Mailbox -ResultSize Unlimited -RecipientTypeDetails SharedMailbox).Count
$publicFolderCount = (Get-PublicFolder -Recurse -ResultSize Unlimited).Count
$mailFlowRuleCount = (Get-TransportRule).Count
$mailboxCount = (Get-Mailbox -ResultSize Unlimited).Count

Add-Line "Exchange Groups: $groupCount"
Add-Line "Exchange Contacts: $contactCount"
Add-Line "Exchange Shared Mailboxes: $sharedMailboxCount"
Add-Line "Exchange Public Folders: $publicFolderCount"
Add-Line "Exchange Mail Flow Rules: $mailFlowRuleCount"
Add-Line "Exchange Mailboxes: $mailboxCount"

# Add enabled users section
$enabledUsers = Get-Mailbox -ResultSize Unlimited | Where-Object {$_.UserAccountControl -eq 'Normal'} | Select-Object DisplayName, UserPrincipalName
foreach ($enabledUser in $enabledUsers) {
    Add-Line "$($enabledUser.DisplayName) - $($enabledUser.UserPrincipalName)"
}

# Add mailbox sizes section
$mailboxSizes = Get-Mailbox -ResultSize Unlimited | Get-MailboxStatistics | Select-Object DisplayName, TotalItemSize
foreach ($mailboxSize in $mailboxSizes) {
    Add-Line "$($mailboxSize.DisplayName) - $($mailboxSize.TotalItemSize)"
}

# Add send connector configurations section
$sendConnectors = Get-SendConnector | Select-Object Name, AddressSpaces, SourceTransportServers
foreach ($sendConnector in $sendConnectors) {
    Add-Line "Name: $($sendConnector.Name)"
    Add-Line "Address Spaces: $($sendConnector.AddressSpaces -join ', ')"
    Add-Line "Source Transport Servers: $($sendConnector.SourceTransportServers -join ', ')`n"
}

# Add receive connector section
$receiveConnectors = Get-ReceiveConnector | Select-Object Name, Bindings, RemoteIPRanges
foreach ($receiveConnector in $receiveConnectors) {
    Add-Line "Name: $($receiveConnector.Name)"
    Add-Line "Bindings: $($receiveConnector.Bindings -join ', ')"
    Add-Line "Remote IP Ranges: $($receiveConnector.RemoteIPRanges -join ', ')"
    Add-Line "`n"
}

# Add Exchange Admin Center section
Add-SectionHeader "Exchange Admin Center"
$exchangeAdminCenter = Get-EcpVirtualDirectory | Select-Object -First 1 | ForEach-Object { "https://$($_.InternalUrl.Host)/ecp" }
Add-Line "URL: $exchangeAdminCenter"

# Add virtual directories section
Add-SectionHeader "Virtual Directories"
$virtualDirectories = Get-VirtualDirectory | Select-Object Name, InternalUrl, ExternalUrl
foreach ($virtualDirectory in $virtualDirectories) {
    Add-Line "Name: $($virtualDirectory.Name) - Internal URL: $($virtualDirectory.InternalUrl) - External URL: $($virtualDirectory.ExternalUrl)"
}

# Add virtual directories section
Add-SectionHeader "Virtual Directories"

$virtualDirectories = Get-VirtualDirectory | Select-Object Name, InternalUrl, ExternalUrl

# Create a table header
Add-Line "Name" -f PadRight -w 30
Add-Line "Internal URL" -f PadRight -w 50
Add-Line "External URL`n" -f PadRight -w 50

# Add table content
foreach ($virtualDirectory in $virtualDirectories) {
    Add-Line $($virtualDirectory.Name) -f PadRight -w 30
    Add-Line $($virtualDirectory.InternalUrl) -f PadRight -w 50
    Add-Line "$($virtualDirectory.ExternalUrl)`n" -f PadRight -w 50
}
# Get all certificates
$certificates = Get-ExchangeCertificate | Select-Object Thumbprint, Subject, Issuer, NotAfter, CertificateDomains

# Filter out mail related and non-mail related certificates
$mailCertificates = $certificates | Where-Object { $_.CertificateDomains -like '*mail*' }
$nonMailCertificates = $certificates | Where-Object { $_.CertificateDomains -notlike '*mail*' }

# Mail-Related Certificate Details
Add-SectionHeader "Mail-Related Certificate Details"
if ($mailCertificates) {
    # Add table headers
    Add-Line "Subject                         Issuer                          Expiration          SAN                                                                      Thumbprint"
    Add-Line "------------------------------ ------------------------------ ------------------- -------------------------------------------------------------------- --------------------------------"
    
    foreach ($certificate in $mailCertificates) {
        $san = $certificate.CertificateDomains -join ', '
        Add-Line ("{0} {1} {2} {3} {4}" -f $certificate.Subject.PadRight(30), $certificate.Issuer.PadRight(30), $certificate.NotAfter.ToString("yyyy-MM-dd").PadRight(19), $san.PadRight(68), $certificate.Thumbprint)
    }
} else {
    Add-Line "No mail-related certificates found."
}

# Add non-mail related certificates section
Add-SectionHeader "Non-Mail Related Certificate Details"
$nonMailCertificates = $certificates | Where-Object { ($_.CertificateDomains -notmatch 'autodiscover|mail') -or ($_.CertificateDomains -match 'WMSvc|ADFS') }

# Add table headers
Add-Line "Subject                         Issuer                          Expiration          SAN                                                                      Thumbprint"
Add-Line "------------------------------ ------------------------------ ------------------- -------------------------------------------------------------------- --------------------------------"

foreach ($certificate in $nonMailCertificates) {
    $san = $certificate.CertificateDomains -join ', '
    Add-Line ("{0} {1} {2} {3} {4}" -f $certificate.Subject.PadRight(30), $certificate.Issuer.PadRight(30), $certificate.NotAfter.ToString("yyyy-MM-dd").PadRight(19), $san.PadRight(68), $certificate.Thumbprint)
}

# Add Application and System event logs section
Add-SectionHeader "Application and System Event Logs (past 15 days)"
$startTime = (Get-Date).AddDays(-15)
$eventLogTypes = 'Application', 'System'
$eventLevels = 'Warning', 'Error', 'Critical'

foreach ($logType in $eventLogTypes) {
    Add-SectionHeader "$logType Event Log"
    foreach ($level in $eventLevels) {
        Add-Line "$level Events:"
        $events = Get-WinEvent -FilterHashtable @{LogName=$logType; StartTime=$startTime; Level=$eventLevels}

        $uniqueEvents = @{}
        foreach ($event in $events) {
            $eventKey = "$($event.Id)-$($event.TimeCreated)-$($event.Message)"
            if (-not $uniqueEvents.ContainsKey($eventKey)) {
                $uniqueEvents.Add($eventKey, $event)
            }
        }

        foreach ($uniqueEvent in $uniqueEvents.Values) {
            Add-Line "Event ID: $($uniqueEvent.Id) - Time: $($uniqueEvent.TimeCreated) - Message: $($uniqueEvent.Message)"
        }
        Add-Line ""
    }
}

# End of code snippets section

# Save report content to output file
$ReportContent | Set-Content -Path $OutputFile

# Stop the transcript log
Stop-Transcript

# Display completion message
Write-Host "Report generated successfully and saved to $OutputFile"
