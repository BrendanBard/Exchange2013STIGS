Start-Transcript -Path "$env:UserProfile\Desktop\PS-Initial.Script.log" -Append -IncludeInvocationHeader -NoClobber
Set-StrictMode -Version 'Latest'
Get-History -Count '1000' | Out-File -FilePath "$env:UserProfile\Desktop\Prior-PS-History.log"
$ident=Get-ReceiveConnector

#Write-Host $ident

foreach($Identity in $ident)
{
#Setting receive connector permissions to exchange users only
Set-ReceiveConnector -Identity $Identity -PermissionGroups ExchangeUsers
Write-Host -ForegroundColor green "Set permissions for " $Identity " to exchange users only"
}

Set-ContentFilterConfig -Enabled $true
Set-SenderFilterConfig -Enabled $true
Set-SenderIDConfig -enabled $true
Set-SenderReputationConfig -Enabled $true

$startVal=Get-ItemProperty 'hklm:\system\currentcontrolset\services\MSExchangePOP3' | Select Start

if($startVAl.Start -eq '4'){
Write-Host -ForegroundColor yellow "POP3 Enabled ****Change in backend****"
}else{
Write-Host -ForegroundColor green "POP3 NOT ENABLED"
} 

$startVal=Get-ItemProperty 'hklm:\system\currentcontrolset\services\MSExchangeIMAP4' | Select Start
if($startVal.Start -eq '4'){
Write-Host -ForegroundColor yellow "IMAP4 Enabled ****CHANGE IN THE BACKEND****"
} else {
Write-Host -ForegroundColor green "IMAP4 NOT ENABLED"
}

$SendConnectorIdent=Get-SendConnector
Write-Host $SendConnectorIdent
foreach($Identity in $SendConnectorIdent)
{
Set-SendConnector -Identity $Identity -DomainSecureEnabled $true
Write-Host -ForegroundColor green "Set domain secure enabled on: " $Identity
}

#may have more than one remote domain need to check that, testing only had default and there was a type mismatch
#$RemoteDomainIdent=Get-RemoteDomain
#foreach($Identity in $RemoteDomainIdent){
Set-RemoteDomain -Identity Default -AutoForwardEnabled $false
Write-Host -ForegroundColor green "Set remote domain forwarding to false for: Default" 
#}

$OutlookIdent=Get-OutlookAnywhere
foreach($Identity in $OutlookIdent){
Set-OutlookAnywhere -ExternalClientAuthenticationMethod NTLM -Identity $Identity
Write-Host -ForegroundColor green "External client auth method set to NTLM on: " $Identity
Set-OutlookAnywhere -InternalClientAuthenticationMethod NTLM -Identity $Identity
Write-Host -ForegroundColor green "Internal client auth method set to NTLM on: " $Identity
}

Set-AdminAuditLogConfig -AdminAuditLogEnabled $true

$TransportServiceIdent=Get-TransportService
foreach($Identity in $TransportServiceIdent){
Set-TransportService -Identity $Identity -ConnectivityLogEnabled $true
Write-Host -ForegroundColor green "Set Connectivity log to enabled on: " $Identity
}

Set-OrganizationConfig -CustomerFeedbackEnabled $false 
Write-Host -ForegroundColor green "Set customer feedback to false"

#again just using default cause it breaks things
Set-RemoteDomain -Identity Default -DeliveryReportEnabled $false
Write-Host -ForegroundColor green "Set delivery reporting to false"
Set-RemoteDomain -Identity Default -AutoReplyEnabled $false
Write-Host -ForegroundColor green "Set auto reply to false"

foreach($Identity in $TransportServiceIdent){
Set-TransportService -Identity $Identity -MessageTrackingLogSubjectLoggingEnabled $True
Write-Host -ForegroundColor green "Set Subject Line Logging to false on: " $Identity
}

foreach($Identity in $SendConnectorIdent){
Set-SendConnector -Identity $Identity -TlsAuthLevel DomainValidation
Write-Host -ForegroundColor green "Set auth level to Domain validation on " $Identity
}

#set the banner 
foreach($Identity in $ident){
Set-ReceiveConnector -Identity $Identity -Banner '220 SMTP Server Ready'
Write-Host -ForegroundColor green "Set banner to SMTP Server Ready on: " $Identity
}
#disabling forwarding of emails
#Set-Mailbox | select Name, ForwardingSMTPAddress $null

#$IP=(Test-Connection -ComputerNAme $env:computername -count 1).ipv4address.IPAddressToString
#Set-TransportConfig -InternalSMTPServers @{Add=$IP}
#Write-Host -ForegroundColor green "Set SMTP server to " $IP

Write-Host -ForegroundColor green -Backgroundcolor blue "#######DONE############"

& $env:ExchangeInstallPath\Scripts\Install-AntispamAgents.ps1
Set-ExecutionPolicy RemoteSigned

Set-ExecutionPolicy -ExecutionPolicy 'Restricted' -Scope 'LocalMachine' -Force -ErrorAction 'SilentlyContinue'
Stop-Transcript