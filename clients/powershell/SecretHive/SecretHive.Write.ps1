# The commands that change something on the server, and the ones that find and combine what is there. Loaded into
# the module by SecretHive.psm1, so everything here sees the module's own helpers (Invoke-Hive, Read-Value, ...).
#
# The rule of the read commands holds here too: a value is never taken as plain text on a command line, where it
# would stay in the history. It is given as a secure string, or asked for without showing it.

function Resolve-Secret([string]$Reference, [string]$Vault, [string]$Name, [switch]$AllowField) {
    if ($Reference) {
        $parsed = ConvertFrom-Reference $Reference
        if ($parsed.Version) { throw 'A version cannot be named here: a change always makes a new one.' }
        if ($parsed.Field -and -not $AllowField) { throw 'Name the secret, not one of its fields: vault/name.' }
        return $parsed
    }

    [pscustomobject]@{ Vault = $Vault; Name = $Name; Version = $null; Field = $null }
}

# What the server lists for one name, or nothing when it is not there. Never a value.
function Get-Listed([string]$Vault, [string]$Name) {
    Invoke-Hive "vaults/$([uri]::EscapeDataString($Vault))/secrets" | ConvertFrom-Json | ForEach-Object { $_ } |
        Where-Object { $_.name -eq $Name } | Select-Object -First 1
}

function ConvertTo-Text($Value) {
    if ($Value -is [securestring]) { return ConvertTo-PlainText $Value }
    if ($null -eq $Value) { return '' }
    [string]$Value
}

function Set-SecretHiveValue {
    <#
    .SYNOPSIS
    Makes a secret, or gives an existing one a new version.
    .DESCRIPTION
    The value is given as a secure string, or asked for without showing it; never as text on the command line.
    What is not mentioned stays as it is: the description, the ordinary fields and the sensitive fields of an
    existing secret are kept unless this command names them. Needs the role Secrets Officer in the vault, and a
    server of release 0.15.1 or later.
    .PARAMETER Reference
    vault/name.
    .PARAMETER Value
    The new value, as a secure string. Asked for when left out.
    .PARAMETER Description
    A new description. Left out: the description stays.
    .PARAMETER Field
    Ordinary fields to set, readable by everyone who may see the vault: @{ owner = 'operations' }. A field given
    as $null or '' is removed; fields not named stay.
    .PARAMETER SensitiveField
    Sensitive fields to set, each a secure string (or text): @{ pin = $pin }. One given as $null or '' is
    removed; sensitive fields not named are kept, without being read.
    .PARAMETER ReplaceDetails
    Make the new version exactly what this command names: no description, field or sensitive field is kept.
    .PARAMETER AllowEdgeWhitespace
    A value that starts or ends with whitespace is refused, because that is nearly always a pasted newline. This
    lets one through.
    .EXAMPLE
    Set-SecretHiveValue tools/api-token
    .EXAMPLE
    Set-SecretHiveValue tools/sql-admin -Value $password -Field @{ username = 'sa'; owner = 'operations' }
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Reference')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Reference')][string]$Reference,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Vault,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Name,
        [Parameter(Position = 1)][securestring]$Value,
        [string]$Description,
        [hashtable]$Field,
        [hashtable]$SensitiveField,
        [switch]$ReplaceDetails,
        [switch]$AllowEdgeWhitespace
    )

    $target = Resolve-Secret $Reference $Vault $Name

    # An earlier server makes a new version exactly what was sent, and would drop every field this command does
    # not name without a word. It does not answer this question, which is how it is told apart.
    if ($null -eq (Invoke-Hive 'server' -AllowNotFound)) {
        throw 'Setting a value from PowerShell needs a SecretHive server of release 0.15.1 or later: an earlier one would drop the fields that are not named. Change it on its page.'
    }

    if (-not $Value) { $Value = Read-Host -AsSecureString -Prompt "Value for $($target.Vault)/$($target.Name)" }
    $plain = ConvertTo-PlainText $Value
    if (-not $plain) { throw 'A secret cannot be empty.' }
    if (-not $AllowEdgeWhitespace -and $plain -ne $plain.Trim()) {
        throw 'The value starts or ends with whitespace, which is nearly always a pasted newline. Give it without, or pass -AllowEdgeWhitespace.'
    }

    # Only what is named is sent; the server keeps the rest. A field sent empty is taken away.
    $fields = @()
    if ($Field) {
        foreach ($key in $Field.Keys) {
            $text = ConvertTo-Text $Field[$key]
            $type = $(if ($key -eq 'url') { 'Url' } elseif ($text -match "[\r\n]") { 'Multiline' } else { 'Text' })
            $fields += @{ name = [string]$key; value = $text; type = $type; sensitive = $false }
        }
    }

    if ($SensitiveField) {
        foreach ($key in $SensitiveField.Keys) { $fields += @{ name = [string]$key; value = (ConvertTo-Text $SensitiveField[$key]); sensitive = $true } }
    }

    $body = @{ value = $plain; replaceDetails = [bool]$ReplaceDetails }
    if ($fields.Count -gt 0) { $body.fields = @($fields) }
    if ($PSBoundParameters.ContainsKey('Description')) { $body.description = $Description }

    if (-not $PSCmdlet.ShouldProcess("$($target.Vault)/$($target.Name)", 'Set the value')) { return }

    $path = "vaults/$([uri]::EscapeDataString($target.Vault))/secrets/$([uri]::EscapeDataString($target.Name))"
    $answer = Invoke-Hive $path -Method Put -Body ($body | ConvertTo-Json -Depth 5 -Compress) | ConvertFrom-Json
    [pscustomobject]@{ Vault = $target.Vault; Name = $target.Name; Version = $answer.version }
}

function Remove-SecretHiveSecret {
    <#
    .SYNOPSIS
    Moves a secret to the bin of its vault. Nothing is destroyed: it is restored from the vault's Bin page.
    .DESCRIPTION
    Asks first. Needs the role Secrets Officer in the vault.
    .EXAMPLE
    Remove-SecretHiveSecret tools/old-token
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Reference')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Reference')][string]$Reference,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Vault,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Name
    )

    $target = Resolve-Secret $Reference $Vault $Name
    if (-not $PSCmdlet.ShouldProcess("$($target.Vault)/$($target.Name)", 'Move to the bin')) { return }
    Invoke-Hive "vaults/$([uri]::EscapeDataString($target.Vault))/secrets/$([uri]::EscapeDataString($target.Name))" -Method Delete | Out-Null
}

function Rename-SecretHiveSecret {
    <#
    .SYNOPSIS
    Gives a secret another name in its vault. Its versions, fields, links and history stay with it.
    .DESCRIPTION
    Asks first. Needs the role Secrets Officer in the vault. Everything outside the server that names the secret
    (host manifests, vault/name references, job settings, scripts) stops finding it until it is changed to the new
    name. Needs a server of release 0.20.0 or later.
    .EXAMPLE
    Rename-SecretHiveSecret tools/old-token -NewName api-token
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Reference')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Reference')][string]$Reference,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Vault,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Name,
        [Parameter(Mandatory, Position = 1)][string]$NewName
    )

    $about = Invoke-Hive 'server' -AllowNotFound
    $version = if ($null -ne $about) { ($about | ConvertFrom-Json).version } else { '0.0.0' }
    $parsed = $null
    if ([version]::TryParse(($version -split '[-+]')[0], [ref]$parsed) -and $parsed -lt [version]'0.20.0') {
        throw "This server ($version) cannot rename a secret: that needs release 0.20.0 or later."
    }

    $target = Resolve-Secret $Reference $Vault $Name
    if (-not $PSCmdlet.ShouldProcess("$($target.Vault)/$($target.Name)", "Rename to '$NewName'")) { return }
    Invoke-Hive "vaults/$([uri]::EscapeDataString($target.Vault))/secrets/$([uri]::EscapeDataString($target.Name))/rename" -Method Post -Body (@{ name = $NewName } | ConvertTo-Json -Compress) | ConvertFrom-Json
}

function Rename-SecretHiveVault {
    <#
    .SYNOPSIS
    Gives a vault another name. Its secrets, roles, keys, networks and links stay with it.
    .DESCRIPTION
    Asks first. Only an administrator of the server may, and it is a security event on the server. Everything
    outside the server that names the vault (host manifests, vault/name references, job settings, scripts) stops
    finding it until it is changed to the new name. Needs a server of release 0.18.0 or later.
    .EXAMPLE
    Rename-SecretHiveVault -Vault app-logging -NewName app-observability
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Vault,
        [Parameter(Mandatory, Position = 1)][string]$NewName
    )

    $about = Invoke-Hive 'server' -AllowNotFound
    $version = if ($null -ne $about) { ($about | ConvertFrom-Json).version } else { '0.0.0' }
    $parsed = $null
    if ([version]::TryParse(($version -split '[-+]')[0], [ref]$parsed) -and $parsed -lt [version]'0.18.0') {
        throw "This server ($version) cannot rename a vault: that needs release 0.18.0 or later."
    }

    if (-not $PSCmdlet.ShouldProcess($Vault, "Rename to '$NewName'")) { return }
    Invoke-Hive "vaults/$([uri]::EscapeDataString($Vault))/rename" -Method Post -Body (@{ name = $NewName } | ConvertTo-Json -Compress) | ConvertFrom-Json
}

function Move-SecretHiveVault {
    <#
    .SYNOPSIS
    Puts a vault in a folder, or at the top without -Folder.
    .DESCRIPTION
    Asks first. Only an administrator of the server may. Every role given on the new folder, or on one above it,
    then counts in the vault, and those of the old folders no longer do: the server records who gained and who
    lost, as a security event when anyone gained. Needs a server of release 0.23.0 or later.
    .EXAMPLE
    Move-SecretHiveVault -Vault oci-apps -Folder oci
    .EXAMPLE
    Move-SecretHiveVault oci-apps            # back to the top
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Vault,
        [Parameter(Position = 1)][string]$Folder
    )

    $about = Invoke-Hive 'server' -AllowNotFound
    $version = if ($null -ne $about) { ($about | ConvertFrom-Json).version } else { '0.0.0' }
    $parsed = $null
    if ([version]::TryParse(($version -split '[-+]')[0], [ref]$parsed) -and $parsed -lt [version]'0.23.0') {
        throw "This server ($version) has no folders: that needs release 0.23.0 or later."
    }

    $where = if ($Folder) { "Move into folder '$Folder'" } else { 'Move to the top' }
    if (-not $PSCmdlet.ShouldProcess($Vault, $where)) { return }
    $target = if ($Folder) { $Folder } else { $null }
    Invoke-Hive "vaults/$([uri]::EscapeDataString($Vault))/folder" -Method Put -Body (@{ folder = $target } | ConvertTo-Json -Compress) | Out-Null
}

function Find-SecretHiveSecret {
    <#
    .SYNOPSIS
    Finds secrets in every vault you have a role in, by name, vault, description or an ordinary field.
    .DESCRIPTION
    Every word given has to be found. A search never looks at a value or a sensitive field, and is not a read.
    .EXAMPLE
    Find-SecretHiveSecret grafana token | Select-Object vault, name, description
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0, ValueFromRemainingArguments)][string[]]$Query)

    # In the body, not in the address: an address ends up in request logs.
    $found = Invoke-Hive 'search' -Method Post -Body (@{ query = ($Query -join ' ') } | ConvertTo-Json -Compress) -AllowNotFound
    if ($null -eq $found) { throw 'This server has no search for tools yet: it is older than 0.15.1.' }
    $found | ConvertFrom-Json | ForEach-Object { $_ }
}

function Get-SecretHiveCredential {
    <#
    .SYNOPSIS
    A credential from one secret: the user name from its field, the password from its value.
    .DESCRIPTION
    The user name is taken from the field 'username' (or the one named), whether it is an ordinary field or a
    sensitive one. Reading the value is a read the server writes down, like any other.
    .EXAMPLE
    Invoke-Command -ComputerName web-1 -Credential (Get-SecretHiveCredential tools/web-admin) { hostname }
    #>
    [CmdletBinding(DefaultParameterSetName = 'Reference')]
    [OutputType([pscredential])]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Reference')][string]$Reference,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Vault,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Name,
        [string]$UserNameField = 'username'
    )

    $target = Resolve-Secret $Reference $Vault $Name
    $listed = Get-Listed $target.Vault $target.Name
    if (-not $listed) { throw "SecretHive has no such thing, as far as this key can tell: $($target.Vault)/$($target.Name)" }

    $user = $listed.fields.PSObject.Properties | Where-Object { $_.Name -eq $UserNameField } | Select-Object -First 1
    if ($user) { $userName = [string]$user.Value }
    elseif ($listed.sensitiveFields -contains $UserNameField) { $userName = ConvertTo-PlainText (Read-Value $target.Vault $target.Name $UserNameField $null) }
    else { throw "$($target.Vault)/$($target.Name) has no field '$UserNameField' to take the user name from." }

    [pscredential]::new($userName, (Read-Value $target.Vault $target.Name $null $null))
}

# Tab completes vaults and names from what this key may see. Quiet when there is no connection: completion must
# never be the thing that asks for a key or prints an error.
$completeVault = {
    param($commandName, $parameterName, $wordToComplete)
    try { Invoke-Hive 'vaults' | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $_.name -like "$wordToComplete*" } | ForEach-Object { $_.name } } catch { }
}
$completeName = {
    param($commandName, $parameterName, $wordToComplete, $commandAst, $bound)
    if (-not $bound.Vault) { return }
    try { Invoke-Hive "vaults/$([uri]::EscapeDataString($bound.Vault))/secrets" | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $_.name -like "$wordToComplete*" } | ForEach-Object { $_.name } } catch { }
}
$completeReference = {
    param($commandName, $parameterName, $wordToComplete)
    try {
        if ($wordToComplete -match '^(?<vault>[^/]+)/(?<name>[^/#]*)$') {
            $vault = $Matches['vault']; $name = $Matches['name']
            Invoke-Hive "vaults/$([uri]::EscapeDataString($vault))/secrets" | ConvertFrom-Json | ForEach-Object { $_ } |
                Where-Object { $_.name -like "$name*" } | ForEach-Object { "$vault/$($_.name)" }
        }
        else {
            Invoke-Hive 'vaults' | ConvertFrom-Json | ForEach-Object { $_ } | Where-Object { $_.name -like "$wordToComplete*" } | ForEach-Object { "$($_.name)/" }
        }
    }
    catch { }
}

$withReference = 'Get-SecretHiveValue', 'Set-SecretHiveValue', 'Remove-SecretHiveSecret', 'Get-SecretHiveCredential'
Register-ArgumentCompleter -CommandName $withReference -ParameterName Reference -ScriptBlock $completeReference
Register-ArgumentCompleter -CommandName ($withReference + 'Get-SecretHiveSecret') -ParameterName Vault -ScriptBlock $completeVault
Register-ArgumentCompleter -CommandName ($withReference + 'Get-SecretHiveSecret') -ParameterName Name -ScriptBlock $completeName
