<#
.SYNOPSIS
    Collects details from an on-prem Active Directory domain controller server in preparation for a migration to Outlook Online.

.DESCRIPTION
    This PowerShell script collects various details from an on-prem Active Directory domain controller server to assist with planning a migration to Outlook Online. 
    - Server network details, including domain NetBIOS name, domain FQDN, IP address, subnet mask, default gateway, and DNS servers.
    - Windows Server version and CU details.
    - Domain and Forest functional level.
    - AAD Sync status, including the server it is running from (if applicable).
    - FSMO roles and servers.
    - Replication status, including repadmin /replsum and repadmin /syncall /Aed.
    - Net share details.
    - DFS vs DFSR replication status.
    - Domain DNS and Forest DNS zone infrastructure properties, including FSMORoleOwner.
    - DNS details, including root hints, forwarders, _msdcs, mx, spf, txt, and autodiscover records, and reverse lookup zones.
    - Sites and Services, including subnets.
    This script will also attempt to connect to the Exchange Management Console to retrieve Exchange details.
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
    If cannot connect to EMC, then run Report-ExchangeServerMigration-Exchange.ps1 from Exchange server itself

.PARAMETER None
    This script does not require any parameters to be passed.

.EXAMPLE !!! Set-Execution Policy to Bypass !!!
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Report-ExchangeServerMigration-ADDC.ps1
    Runs the script and generates a report file  on the desktop with details collected from the domain controller.

.NOTES
    This script must be run as a domain local administrator with appropriate Active Directory permissions on ADDC.

.NOTES
    Version: 1.0
    Creation Date: 2023-05-09
    Copyright (c) 2023 https://github.com/bentman
    https://github.com/bentman/PoShDiscoveryTemplate/upload/main
#>

# Set report name
$reportName = "Report-ExchangeServerMigration-ADDC"

# Set output file path
$outputFile = "$env:USERPROFILE\Desktop\$reportName.txt"

# Set transcript file path
$TranscriptPath = "$env:USERPROFILE\Desktop\$reportName.log"
# Start transcript
Start-Transcript -Path $transcriptPath -Append

# Initialize report content as an empty string
$ReportContent = ""

# Function to add a section header to the report
function Add-SectionHeader {
    param (
        [string]$Title
    )
    $script:ReportContent += "`n`n$Title`n"
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
        $externalIp = (Invoke-WebRequest -Uri 'https://ipinfo.io/ip' -UseBasicParsing).Content.Trim()
    }
    catch {
        $externalIp = "Unable to retrieve external IP"
    }
    return $externalIp
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
        Add-Error "Unable to import module $($module): `n    $($_.Exception.Message)"
    }
}

# Add report header
Add-SectionHeader "Report - $reportName"
Add-Line "Date: $(Get-Date -Format 'yyyy-MM-dd')"

# *** Begin adding your ADDC code snippets here ***
# Use Add-SectionHeader to create a new section, 
# Use Add-Line to add details,
# Use Add-Warning to add warnings, 
# Use Add-Error to add errors

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

# Add domain controller section
Add-SectionHeader "Domain Controller"
try {
    $domainController = Get-ADDomainController -Discover -Service PrimaryDC
    Add-Line "Domain Controller: `n    $($domainController.HostName)"
    Add-Line "Site: `n    $($domainController.Site)"
} catch {
    Add-Error "Error retrieving domain controller information: `n    $($_.Exception.Message)"
}

# Get the domain NetBIOS name
try {
    $domainNetBIOSName = (Get-ADDomain).NetBIOSName
    Add-Line "Domain NetBIOS Name: `n    $domainNetBIOSName"
} catch {
    Add-Error "Error retrieving domain NetBIOS name: `n    ($_.Exception.Message)"
}

# Add Domain and Forest Functional Level section
Add-SectionHeader "AD Functional Levels"
try {
    $domainFL = (Get-ADDomain).DomainMode
    $forestFL = (Get-ADForest).ForestMode
    Add-Line "Domain Functional Level: `n    $domainFL"
    Add-Line "Forest Functional Level: `n    $forestFL"
} catch {
    Add-Error "Error retrieving domain and forest functional levels: `n    $($_.Exception.Message)"
}

# Add AAD Sync section
Add-SectionHeader "AAD Sync Status"

# Check if ADSync module is available
$adSyncModule = Get-Module -ListAvailable -Name "ADSync"
if (-not $adSyncModule) {
    # Attempt to import the module
    try {
        Import-Module -Name "ADSync" -ErrorAction Stop
    } catch {
        Add-Warning "ADSync module not found or could not be imported: `n    $($_.Exception.Message)"
    }
}

# Check AAD Sync status
if (Get-Command Get-ADSyncConnector -ErrorAction SilentlyContinue) {
    if (Get-ADSyncConnector) {
        Add-Line "AAD Sync is enabled."
        try {
            $aadSyncServer = (Get-ADSyncScheduler).SynchronizationServer
            if ($aadSyncServer) {
                Add-Line "AAD Sync is running from: `n    $aadSyncServer"
            } else {
                Add-Error "AAD Sync is enabled, but the server it is running from is not specified."
            }
        } catch {
            Add-Error "Error retrieving AAD Sync server information: `n    $($_.Exception.Message)"
        }
    } else {
        Add-Line "AAD Sync is not enabled."
    }
} else {
    Add-Warning "Get-ADSyncConnector cmdlet not available. `n    AAD Sync status could not be checked."
}

# Add Sites and Subnets section
Add-SectionHeader "Active Directory Sites and Subnets"
$sites = Get-ADReplicationSite -Filter *
foreach ($site in $sites) {
    Add-Line "Site: `n    $($site.Name)"
    $subnets = Get-ADReplicationSubnet -Filter { Site -eq $site } | Select-Object -ExpandProperty Name
    if ($subnets) {
        Add-Line "Subnets:"
        foreach ($subnet in $subnets) {
            Add-Line "  $subnet`n"
        }
    } else {
        Add-Line "No subnets found."
    }
}

# Add FSMO Roles section
Add-SectionHeader "FSMO Roles and Servers"

# Get the FSMO roles and the servers that hold them
$domain = Get-ADDomain
$fsmoRoles = @{
    "Infrastructure Master" = $domain.InfrastructureMaster
    "Naming Master"         = (Get-ADForest).NamingMaster
    "PDC Emulator"          = $domain.PDCEmulator
    "RID Master"            = $domain.RIDMaster
    "Schema Master"         = (Get-ADForest).SchemaMaster
}

foreach ($role in $fsmoRoles.GetEnumerator()) {
    $roleName = $role.Name
    $roleServer = $role.Value

    if ($roleServer) {
        Add-Line "$roleName role is held by: `n    $roleServer"
    } else {
        Add-Warning "$roleName`n    No server is holding the $roleName role."
    }
}

# Add Replication Summary section
Add-SectionHeader "Replication Summary"
$repadminOutput = (repadmin /replsum /errorsonly) -split "`n" | ForEach-Object { "`t$_" }
Add-Line "repadmin /replsum output:"
foreach ($line in $repadminOutput) {
    Add-Line $line
}

# Add Sync All section
Add-SectionHeader "Replicate All Domain Controllers"
$repadminOutput = (repadmin /syncall /Aed) -split "`n" | ForEach-Object { "`t$_" }
Add-Line "repadmin /syncall /Aed output:"
foreach ($line in $repadminOutput) {
    Add-Line $line
}

# Add Net Share section
Add-SectionHeader "Shared Folders on the Server"
$shares = Get-SmbShare | Select-Object Name, Path, Description

# Format the shares as a table
$table = $shares | Format-Table -AutoSize | Out-String
$table = $table -replace "`n", "`n" # add extra line breaks for readability

# Add the table to the report
Add-Line $table

# Add DFS vs DFSR Replication section
Add-SectionHeader "DFS vs DFSR Replication"

$dfsNameSpaces = Get-DfsnRoot | Select-Object Name -ErrorAction SilentlyContinue
if ($dfsNameSpaces) {
    foreach ($dfsNameSpace in $dfsNameSpaces) {
        $dfsReplicationGroup = Get-DfsrGroup -GroupName $dfsNameSpace.Name -ErrorAction SilentlyContinue
        if ($dfsReplicationGroup) {
            Add-Line "DFS Namespace: `n    $($dfsNameSpace.Name) - Replication Type: DFSR"
        } else {
            Add-Line "DFS Namespace: `n    $($dfsNameSpace.Name) - Replication Type: DFS"
        }
    }
} else {
    Add-Line "No DFS namespaces found."
}

# Check DFS and DFSR services
Add-SectionHeader "DFS and DFSR Services"
$dfsServiceStatus = Get-Service -Name DFS* -ErrorAction SilentlyContinue
if ($dfsServiceStatus) {
    Add-Line "DFS service is running."
} else {
    Add-Warning "DFS service is not running."
}
$dfsrServiceStatus = Get-Service -Name DFSR* -ErrorAction SilentlyContinue
if ($dfsrServiceStatus) {
    Add-Line "DFSR service is running."
} else {
    Add-Warning "DFSR service is not running. Consider an AD upgrade."
}

# Add DNS Zones section
Add-SectionHeader "DNS Zones"

# Get the Domain and Forest DNS zones and their properties
$domainDnsZone = Get-DnsServerZone -Name $("_msdcs." + (Get-ADDomain).DNSRoot)
$forestDnsZone = Get-DnsServerZone -Name $("_msdcs." + (Get-ADForest).RootDomain)

# Add the Domain DNS zone and its FSMO role owner to the report
Add-Line "Domain DNS Zone: $($domainDnsZone.ZoneName)"

# Add the Forest DNS zone and its FSMO role owner to the report
Add-Line "Forest DNS Zone: $($forestDnsZone.ZoneName)"

# Add DNS Details section
Add-SectionHeader "DNS Details"

# Add DNS Root Hints section
$rootHints = Get-DnsServerRootHint | Format-Table | Out-String
Add-SectionHeader "Root Hints" 
Add-Line $rootHints

# Add DNS Forwarders section
Add-SectionHeader "Forwarders"
$forwarders = Get-DnsServerForwarder | Format-Table | Out-String
if ($forwarders) {
    Add-Line $forwarders
} else {
    Add-Line "No forwarders are configured."
}

# Add DNS Zones section
Add-SectionHeader "DNS Zones with Mail Records"
$recordTypes = @("MX","TXT")

# Get all DNS zones and filter out reverse lookup zones
$dnsZones = Get-DnsServerZone | Where-Object { $_.ZoneName -notlike "*in-addr.arpa" }

# Loop through each zone to find records of the specified types
foreach ($zone in $dnsZones) {
    $mailRecords = $null
    foreach ($recordType in $recordTypes) {
        $records = Get-DnsServerResourceRecord -ZoneName $zone.ZoneName -RRType $recordType -ErrorAction SilentlyContinue
        if ($records) {
            if (!$mailRecords) {
                Add-Line "Mail records found in the $($zone.ZoneName) zone:"
            }
            foreach ($record in $records) {
                Add-Line "  $($record.RecordData) - Type: $($record.RecordType) - Zone: $($zone.ZoneName)"
            }
            $mailRecords = $true
        }
    }
    if (!$mailRecords) {
        Add-Line "No mail records found in the $($zone.ZoneName) zone."
    }
}

# Add all DNS Forward Lookup Zones
Add-SectionHeader "Forward Lookup Zones"
$dnsZones = Get-DnsServerZone
if ($dnsZones) {
    $dnsZonesOutput = $dnsZones | 
        Where-Object -Property IsReverseLookupZone -eq $false  |
        Select-Object -Property ZoneName, ZoneType, IsAutoCreated, IsDsIntegrated, IsSigned, IsReverseLookupZone
    Add-Line ($dnsZonesOutput | Format-Table | Out-String)
} else {
    Add-Line "No forward lookup zones are configured."
}

# Add all DNS Reverse Lookup Zones
Add-SectionHeader "Reverse Lookup Zones"
$dnsZones = Get-DnsServerZone
if ($dnsZones) {
    $dnsZonesOutput = $dnsZones | 
        Where-Object -Property IsReverseLookupZone -EQ $true |
        Select-Object -Property ZoneName, ZoneType, IsAutoCreated, IsDsIntegrated, IsSigned, IsReverseLookupZone
    Add-Line ($dnsZonesOutput | Format-Table | Out-String)
} else {
    Add-Line "No reverse lookup zones are configured."
}

# **** End of ADDC code snippets section ****

# Add Exchange Server Information
Add-SectionHeader "Exchange Server Information"

# Find Exchange Server FQDN using SCP
$autodiscoverSCP = Get-ADObject -Filter {objectClass -eq 'serviceConnectionPoint' -and Name -eq 'Autodiscover'} -Properties keywords, ServiceBindingInformation
$exchangeFqdn = ($autodiscoverSCP | Where-Object {$_.keywords -contains '67661d7F-8FC4-4fa7-BFAC-E1D7794C1F68'}).ServiceBindingInformation -replace 'https?://','' -replace '/.*',''

# Connect to Exchange Server
$connected = $false
$session = $null
if ($exchangeFqdn) {
    $exchangeUri = "http://$exchangeFqdn/powershell"
    try {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $exchangeUri -Authentication Kerberos
        Import-PSSession $session -DisableNameChecking -AllowClobber -WarningAction SilentlyContinue
        $connected = $true
    } catch {
        Add-Warning "Unable to connect to Exchange Server at $exchangeUri"
        $connected = $false
    }
}

if (!$connected) {
    $emcPath2010 = "C:\Program Files\Microsoft\Exchange Server\V14\bin\RemoteExchange.ps1"
    $emcPath2013 = "C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1"

    if (Test-Path $emcPath2010) {
        . $emcPath2010
        Connect-ExchangeServer -auto -Fqdn $exchangeFqdn
        $connected = $true
    } elseif (Test-Path $emcPath2013) {
        . $emcPath2013
        Connect-ExchangeServer -auto -Fqdn $exchangeFqdn
        $connected = $true
    } else {
        Add-Warning "Unable to connect to Exchange Server. RemoteExchange.ps1 (EMC) path not found."
    }
}

# Run Exchange commands if connected
if ($connected) {
    Add-Line "Connected to Exchange Server: $exchangeFqdn"

    # Insert Exchange commands here
    # Example: Get-Mailbox | Select-Object Name, Alias, PrimarySmtpAddress

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

    # Add number of Exchange Servers section
    $exchangeServers = Get-ExchangeServer
    $exchangeServerCount = $exchangeServers.Count
    Add-Line "Exchange Servers: $exchangeServerCount"

    # Add Exchange Server List
    $exchangeServersList = $exchangeServers | Format-List
    Add-Line "Exchange Server List: `n$exchangeServersList"

    # Add Exchange databases section
    $databases = Get-MailboxDatabase | Select-Object Name, EdbFilePath, DatabaseSize
    Add-Line "Number of Exchange Databases: $($databases.Count)"

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

    # Disconnect Exchange session
    if ($session) {
        Remove-PSSession $session
        Add-Line "Disconnected from Exchange Server."
    }
} else {
    Add-Warning "Unable to connect to Exchange Server. Please run Report-ExchangeServerMigration-Exchange.ps1 from Exchange server."
}

# Save report content to output file
$reportContent | Set-Content -Path $outputFile

# Stop the transcript log
Stop-Transcript

# Display completion message
Write-Host "Report generated successfully and saved to $outputFile"
