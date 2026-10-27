<#
.SYNOPSIS
  Engagement mailbox worker for the Project Management kickoff.

.DESCRIPTION
  Graph creates each engagement's Microsoft 365 group and so its mailbox address
  (ir-781@vendettacd.io). The Exchange settings Graph cannot make are done here:

    - accept mail from external senders (clients, counsel, carriers)
    - no copies to member inboxes: the mailbox is a CC address, mail stays in it
    - Send As for every engagement team member, so external mail can go out from
      the engagement address

  The worker claims pending jobs from the module API, applies them with Exchange
  Online app-only certificate auth, and reports each result back. Run it every
  minute from a systemd timer on the platform host (see the README), or by hand.

.PARAMETER Once
  Process the pending jobs one time and exit (the timer uses this).
#>
[CmdletBinding()]
param([switch]$Once)

$ErrorActionPreference = 'Stop'

$ApiBase     = $env:PM_API_URL            # http://localhost:8900 on the host
$ApiToken    = $env:PM_API_TOKEN          # the module's API_TOKEN
$Org         = $env:EXO_ORGANIZATION      # vendettacd.onmicrosoft.com
$AppId       = $env:EXO_APP_ID            # app registration with Exchange.ManageAsApp
$CertPath    = $env:EXO_CERT_PATH         # PFX on the host
$CertPass    = $env:EXO_CERT_PASSWORD

foreach ($v in 'PM_API_URL','PM_API_TOKEN','EXO_ORGANIZATION','EXO_APP_ID','EXO_CERT_PATH') {
    if (-not (Get-Item "env:$v" -ErrorAction SilentlyContinue)) { throw "Set $v" }
}

$headers = @{ Authorization = "Bearer $ApiToken" }

function Send-Report($id, $status, $detail) {
    $body = @{ status = $status; detail = $detail } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri "$ApiBase/api/kickoff-worker/mailbox/$id" -Headers $headers `
        -ContentType 'application/json' -Body $body | Out-Null
}

$claim = Invoke-RestMethod -Method Post -Uri "$ApiBase/api/kickoff-worker/mailbox/claim" -Headers $headers
if (-not $claim.jobs -or $claim.jobs.Count -eq 0) { return }

Import-Module ExchangeOnlineManagement
$secure = if ($CertPass) { ConvertTo-SecureString $CertPass -AsPlainText -Force } else { $null }
Connect-ExchangeOnline -AppId $AppId -Organization $Org -CertificateFilePath $CertPath `
    -CertificatePassword $secure -ShowBanner:$false

try {
    foreach ($job in $claim.jobs) {
        try {
            $group = $null
            for ($i = 0; $i -lt 20 -and -not $group; $i++) {
                $group = Get-UnifiedGroup -Identity $job.group_id -ErrorAction SilentlyContinue
                if (-not $group) { Start-Sleep -Seconds 30 }   # a new group takes a few minutes to reach Exchange
            }
            if (-not $group) { throw "Group $($job.group_id) is not in Exchange yet" }

            Set-UnifiedGroup -Identity $job.group_id -RequireSenderAuthenticationEnabled:$false `
                -AutoSubscribeNewMembers:$false -SubscriptionEnabled:$true

            $subs = Get-UnifiedGroupLinks -Identity $job.group_id -LinkType Subscribers -ResultSize Unlimited
            if ($subs) {
                Remove-UnifiedGroupLinks -Identity $job.group_id -LinkType Subscribers `
                    -Links ($subs.PrimarySmtpAddress) -Confirm:$false
            }

            $granted = @()
            foreach ($m in $job.members) {
                $have = Get-RecipientPermission -Identity $job.group_id -Trustee $m -ErrorAction SilentlyContinue |
                        Where-Object { $_.AccessRights -contains 'SendAs' }
                if (-not $have) {
                    Add-RecipientPermission -Identity $job.group_id -Trustee $m -AccessRights SendAs -Confirm:$false | Out-Null
                }
                $granted += $m
            }
            Send-Report $job.id 'done' ("$($job.address): external senders on, no inbox copies, Send As for " +
                                        ($granted -join ', '))
        }
        catch {
            Send-Report $job.id 'failed' ("$($job.address): " + $_.Exception.Message)
        }
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false
}
