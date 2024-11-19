```powershell
### CONNECTING MICROSOFT GRAPH ### 
# Installs the Microsoft Graph PowerShell module.
Install-Module -Name Microsoft.Graph -Scope CurrentUser

# Authenticates to Microsoft Graph with specified permissions
Connect-MgGraph -Scopes "User.Read.All, Group.ReadWrite.All, DeviceManagement.ReadWrite.All"

# Displays the current connection context, including the authenticated user and scopes
Get-MgContext

---

### USERS ### 
# Retrieves all users in Azure Active Directory (Azure AD)
Get-MgUser -All | Select-Object DisplayName, UserPrincipalName, AccountEnabled

# Creates a new user in Azure AD.
New-MgUser -DisplayName "Test User" -UserPrincipalName "testuser@domain.com" -PasswordProfile @{Password="P@ssword1"} -AccountEnabled $true

# Deletes a specific user by UserId.
Remove-MgUser -UserId "<UserId>"

# Disables a user account.
Set-MgUser -UserId "<UserId>" -AccountEnabled $false

# Lists the licenses assigned to a user.
Get-MgUserLicenseDetail -UserId "<UserId>"

---

### DEVICES ### 
# List All Managed Devices
Get-MgDeviceManagementManagedDevice | Select-Object Id, ComplianceState, OperatingSystem, AzureAdDeviceId

# Filter Non-Compliant Devices
Get-MgDeviceManagementManagedDevice | Where-Object {$_.ComplianceState -ne "compliant"}

# Wipe a Device
Invoke-MgDeviceManagementManagedDeviceWipe -ManagedDeviceId "<DeviceId>"

# Automate Compliance Reports
$devices = Get-MgDeviceManagementManagedDevice
$nonCompliantDevices = $devices | Where-Object {$_.ComplianceState -ne "compliant"}
$nonCompliantDevices | Export-Csv -Path "NonCompliantDevices.csv" -NoTypeInformation

---

### GROUPS MANAGEMENT ###
# Create a New Security Group
New-MgGroup -DisplayName "IT Department" -MailEnabled $false -SecurityEnabled $true

# 
Get-MgGroup -All | Select-Object DisplayName, GroupTypes, SecurityEnabled

# Adds a user to a group.
Add-MgGroupMember -GroupId "<GroupId>" -MemberId "<UserId>"

# Removes a user from a group
Remove-MgGroupMember -GroupId "<GroupId>" -MemberId "<UserId>"

# Creates a dynamic group based on a rule (e.g., department = IT).
New-MgGroup -DisplayName "Dynamic Group" -MailEnabled $false -SecurityEnabled $true -GroupTypes "DynamicMembership" -MembershipRule "(user.department -eq 'IT')"

---

### DEVICES MANAGEMENT ###
# Lists all Intune-managed devices.
Get-MgDeviceManagementManagedDevice

#
Get-MgDeviceManagementManagedDevice | Where-Object {$_.ComplianceState -ne "compliant"}`

# Wipes a specific device.
Invoke-MgDeviceManagementManagedDeviceWipe -ManagedDeviceId "<DeviceId>"

# Exports all managed devices into a CSV file.
Export-MgDeviceManagementManagedDevice

---

### Compliance Policies ###
# Lists all compliance policies in Intune.
Get-MgDeviceManagementDeviceCompliancePolicy

# Updates the description of a compliance policy.
Set-MgDeviceManagementDeviceCompliancePolicy -PolicyId "<PolicyId>" -Description "Updated Policy"

### Conditional Access ###

# Lists all conditional access policies.
Get-MgConditionalAccessPolicy

# Creates a new conditional access policy requiring MFA for all users.
New-MgConditionalAccessPolicy -DisplayName "Require MFA" -Conditions @{Users=@{IncludeUsers=@("*")}} -GrantControls @{BuiltInControls=@("Mfa")}

---

### SharePoint Management ###
# Lists all SharePoint sites in the organization.
Get-SPOSite

# Restricts sharing capability to external users only.
Set-SPOSite -Identity "https://domain.sharepoint.com/sites/Example" -SharingCapability ExternalUserSharingOnly

# Get-SPOUser -Site "https://domain.sharepoint.com/sites/Example"
Lists all users of a specific SharePoint site.

---

### Security and Encryption ### 
# Retrieves BitLocker recovery keys for managed devices.
Get-MgDeviceManagementBitLockerRecoveryKey

# Enforces BitLocker encryption on devices.
Set-MgDeviceManagementBitLockerPolicy -PolicyId "<PolicyId>" -RequireDeviceEncryption $true

---

### Information Rights Management ###
# Enables an information protection policy (IRM).
Set-MgInformationProtectionPolicy -Id "<PolicyId>" -Name "Confidential" -IsEnabled $true

---

### Reporting and Automation ###
# Exports data from any PowerShell object to a CSV file.
Export-Csv -Path "<FilePath>" -NoTypeInformation

# Sends an email with an attachment (e.g., compliance report).
Send-MailMessage -To "admin@domain.com" -From "report@domain.com" -Subject "Report" -Body "Attached Report" -Attachments "<FilePath>" -SmtpServer "smtp.domain.com"

# Schedules a PowerShell script to run daily.
New-ScheduledTask -Action (New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File '<ScriptPath>'") -Trigger (New-ScheduledTaskTrigger -Daily -At "6:00AM") -TaskName "Daily Compliance"

---

### General PowerShell ###

# Installs a PowerShell module.
Install-Module -Name <ModuleName>

# Imports a PowerShell module into the current session.
Import-Module -Name <ModuleName>

# Updates an installed PowerShell module to the latest version.
Update-Module -Name <ModuleName>

# Tests network connectivity to a specific computer.
Test-Connection -ComputerName "<ComputerName>" -Count 4

# Display PowerShell version and environment details.
$PSVersionTable

# Lists all available commands.
Get-Command

# Displays help for a specific command.
Get-Help <Command>

# Updates the help content for PowerShell cmdlets.
Update-Help

# Clears the PowerShell console.
Clear-Host

### Files and Directories ###
# Lists files and directories in the specified path.
Get-ChildItem -Path <Path>

# Creates a new directory.
New-Item -Path <Path> -ItemType Directory

# Copies a file or directory.
Copy-Item -Path <SourcePath> -Destination <DestinationPath>

# Moves a file or directory.
Move-Item -Path <SourcePath> -Destination <DestinationPath>

# Deletes a file or directory.
Remove-Item -Path <Path>

# Reads the content of a file.
Get-Content -Path <FilePath>

# Overwrites content in a file.
Set-Content -Path <FilePath> -Value "Text"

# Appends content to a file.
Add-Content -Path <FilePath> -Value "Text"

### User Management ###
# Lists all local users on the system.
Get-LocalUser

# Creates a new local user.
New-LocalUser -Name <UserName> -Password (ConvertTo-SecureString "<Password>" -AsPlainText -Force)

# Changes a user's password.
Set-LocalUser -Name <UserName> -Password (ConvertTo-SecureString "<NewPassword>" -AsPlainText -Force)

# Deletes a local user.
Remove-LocalUser -Name <UserName>

# Lists all local groups on the system.
Get-LocalGroup

# Adds a user to a group.
Add-LocalGroupMember -Group <GroupName> -Member <UserName>

# Removes a user from a group.
Remove-LocalGroupMember -Group <GroupName> -Member <UserName>

### Process Management ###
# Lists running processes.
Get-Process

# Stops a specific process.
Stop-Process -Name <ProcessName>

# Starts a new process.
Start-Process -FilePath "<ProgramPath>"

#### Windows Services
# Lists all services on the system.
Get-Service

# Starts a service.
Start-Service -Name <ServiceName>

# Stops a service.
Stop-Service -Name <ServiceName>

# Restarts a service.
Restart-Service -Name <ServiceName>

---

### Networking ### 
# Tests connectivity to a host (ping equivalent).
Test-Connection -ComputerName <HostName>

# Lists IP configuration details.
Get-NetIPAddress

# Lists network adapters on the system.
Get-NetAdapter

# Enables a network adapter.
Enable-NetAdapter -Name <AdapterName>

# Disables a network adapter.
Disable-NetAdapter -Name <AdapterName>

# Lists DNS client configurations.
Get-DnsClient

# Configures DNS server addresses.
Set-DnsClientServerAddress -InterfaceAlias <AdapterName> -ServerAddresses <DNS_IP>

# Resolves a domain name to an IP address.
Resolve-DnsName <Domain>

---

### System Info and Logs ###
# Retrieves system event logs.
Get-EventLog -LogName System

# Clears the system event log.
Clear-EventLog -LogName System

# Retrieves OS information.
Get-WmiObject -Class Win32_OperatingSystem

# Retrieves system hardware information.
Get-WmiObject -Class Win32_ComputerSystem

---

### Storage Management ###
# Lists all storage volumes.
Get-Volume

# Lists all physical disks.
Get-Disk

# Lists partitions on a disk.
Get-Partition

# Creates a new partition.
New-Partition -DiskNumber <DiskNumber> -UseMaximumSize -AssignDriveLetter

# Formats a volume with the NTFS file system.
Format-Volume -DriveLetter <DriveLetter> -FileSystem NTFS

---

### PowerShell Remoting ###
# Enables PowerShell remoting on the system.
Enable-PSRemoting -Force

# Executes commands on a remote system.
Invoke-Command -ComputerName <ComputerName> -ScriptBlock { <Commands> }

# Starts an interactive remote session.
Enter-PSSession -ComputerName <ComputerName>

---

### PowerShell Modules ###
# Lists all available PowerShell modules.
Get-Module -ListAvailable

# Imports a module into the current session.
Import-Module <ModuleName>

# Installs a module from the PowerShell Gallery.
Install-Module -Name <ModuleName>

# Updates an installed module.
Update-Module -Name <ModuleName>

---

### Scripting and Automation ###
# Creates an action for a scheduled task.
New-ScheduledTaskAction -Execute "<ScriptPath>"

# Creates a trigger to run daily at a specific time.
New-ScheduledTaskTrigger -Daily -At "6:00AM"

# Registers a new scheduled task.
Register-ScheduledTask -TaskName "<TaskName>" -Trigger <Trigger> -Action <Action>

# Starts a background job.
Start-Job -ScriptBlock { <Commands> }

# Lists running background jobs.
Get-Job

# Retrieves the output of a completed job.
Receive-Job -Id <JobId>
