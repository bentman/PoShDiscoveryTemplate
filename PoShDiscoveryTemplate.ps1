<#
.SYNOPSIS
PoShDiscoveryReport.ps1 - PowerShell Discovery Report Template

.DESCRIPTION
The PoSh Discovery Report template automates the process of gathering information by generating standardized text reports in various environments. Create snippets with ChatGPT by using this template to streamline information gathering and produce repeatable reports.

.KEY FEATURES
- Simplifies the generation of quick text reports on the logged-in user's desktop.
- Use ChatGPT to customize information gathering snippets with tailored conditions.
- Enhance error control and provide descriptive explanations in snippets.

.USAGE
1. Copy the provided template from the repository.

2. Utilize ChatGPT to interact with the template and store it for later use.
   Example: GPT-Prompt> Store the following as a template to produce snippets "<paste the content of the template between quotes>"

3. Create customized information reporting snippets using the stored template.
   Example: GPT-Prompt> Create a snippet with comments for use with the template that reports specific information.

4. Add requirements, error control, and further enhancements to the snippets.
   Example: GPT-Prompt> If the snippet requires a module, check if it is available and import it if not.

5. Enhance the snippets with appropriate error control.
   Example: GPT-Prompt> Use "SilentlyContinue" and only report errors in the catch block.

6. Get an example of the output for a better understanding.
   Example: GPT-Prompt> Show me an example of the report output.

.PARAMETER None
    This script does not require any parameters to be passed.

.EXAMPLE !!! Set-Execution Policy to Bypass !!!
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\PoShDiscoveryReport.ps1
    Runs the script and generates a txt report file on the desktop with details collected.

.NOTES
Make sure to customize the snippets based on your specific environment and requirements.

.NOTES
    Version: 1.0
    Creation Date: 2023-05-09
    Copyright (c) 2023 https://github.com/bentman
    https://github.com/bentman/PoShDiscoveryTemplate/upload/main
#>

# Set report name
$ReportName = "Discovery-Report"

# Set output file path
$OutputFile = "$env:USERPROFILE\Desktop\$ReportName.txt"

# Set transcript file path
$TranscriptPath = "$env:USERPROFILE\Desktop\$ReportName.log"

# Import required modules
$modules = @(
    "ActiveDirectory",
    "DnsServer"
)

# Import each module in the list
foreach ($module in $modules) {
    try {
        Import-Module -Name $module -ErrorAction Continue
    } catch {
        Write-Error "Unable to import module $($module): $($_.Exception.Message)"
    }
}

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

# Add report header
Add-SectionHeader "Report - $ReportName"
Add-Line "Date: $(Get-Date -Format 'yyyy-MM-dd')"

# *** Begin adding your code snippets here ***
# Use Add-SectionHeader to create a new section, 
# Use Add-Line to add details,
# Use Add-Warning to add warnings, 
# Use Add-Error to add errors

# *** End of code snippets section ***

# Save report content to output file
$ReportContent | Set-Content -Path $OutputFile

# Stop the transcript log
Stop-Transcript

# Display completion message
Write-Host "Report generated successfully and saved to $OutputFile"
