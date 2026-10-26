# SecretHive for PowerShell: reads secrets from a SecretHive server for the session that needs them, and sets them.
#
# The rule the commands keep: a value is never written to the pipeline as text unless that was asked for by
# name (-AsPlainText), never written to the host, and never stored by this module. What is stored, and only
# with -Save, is the connection: the server's address and the caller's key, the key protected for this
# Windows account on this machine.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Net.Http

# A certificate check written in C#, because a PowerShell script block cannot be the callback: it is called
# on a thread that has no runspace. Trusts exactly one certificate, by its SHA-256, and nothing else.
if (-not ('SecretHive.PowerShell.Pinned' -as [type])) {
    $source = @'
namespace SecretHive.PowerShell
{
    public static class Pinned
    {
        public static System.Net.Http.HttpClientHandler Handler(string sha256)
        {
            var handler = new System.Net.Http.HttpClientHandler();
            handler.AllowAutoRedirect = false;
            if (!string.IsNullOrEmpty(sha256))
            {
                handler.ServerCertificateCustomValidationCallback = (request, certificate, chain, errors) =>
                {
                    if (certificate == null) { return false; }
                    using (var hash = System.Security.Cryptography.SHA256.Create())
                    {
                        var presented = System.BitConverter.ToString(hash.ComputeHash(certificate.RawData)).Replace("-", "");
                        return string.Equals(presented, sha256, System.StringComparison.OrdinalIgnoreCase);
                    }
                };
            }

            return handler;
        }
    }
}
'@
    if ($PSVersionTable.PSEdition -eq 'Core') { Add-Type -TypeDefinition $source } else { Add-Type -TypeDefinition $source -ReferencedAssemblies 'System.Net.Http' }
}

$script:Connection = $null

function Get-SavedConnectionPath {
    if (-not $env:APPDATA) { return $null }
    Join-Path (Join-Path $env:APPDATA 'SecretHive') 'connection.clixml'
}

function ConvertTo-PlainText([securestring]$Secure) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}

function New-Connection([uri]$Server, [securestring]$Key, [string]$CertificateSha256) {
    $client = [System.Net.Http.HttpClient]::new([SecretHive.PowerShell.Pinned]::Handler($CertificateSha256))
    $client.Timeout = [timespan]::FromSeconds(20)
    [pscustomobject]@{ Server = $Server; Key = $Key; CertificateSha256 = $CertificateSha256; Client = $client }
}

# The connection of this session: the one made with Connect-SecretHive, else the saved one, else the one the
# environment names (SECRETHIVE_SERVER and SECRETHIVE_KEY_FILE, for a session that is not a person's).
function Get-Connection {
    if ($script:Connection) { return $script:Connection }

    $saved = Get-SavedConnectionPath
    if ($saved -and (Test-Path -LiteralPath $saved)) {
        try {
            $stored = Import-Clixml -LiteralPath $saved
            $script:Connection = New-Connection ([uri]$stored.Server) $stored.Key $stored.CertificateSha256
            return $script:Connection
        }
        catch {
            throw "The saved SecretHive connection in $saved cannot be read by this account on this machine. Run Connect-SecretHive -Save again."
        }
    }

    if ($env:SECRETHIVE_SERVER -and $env:SECRETHIVE_KEY_FILE) {
        $named = @{ Server = $env:SECRETHIVE_SERVER; KeyFile = $env:SECRETHIVE_KEY_FILE }
        if ($env:SECRETHIVE_SERVER_CERTIFICATE) { $named.CertificateFile = $env:SECRETHIVE_SERVER_CERTIFICATE }
        Connect-SecretHive @named | Out-Null
        return $script:Connection
    }

    if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
        throw 'Not connected to SecretHive. Run Connect-SecretHive -Server <https address> first (add -Save to keep it for this Windows account).'
    }
    throw 'Not connected to SecretHive. Run Connect-SecretHive -Server <https address> first, or set SECRETHIVE_SERVER and SECRETHIVE_KEY_FILE (and SECRETHIVE_SERVER_CERTIFICATE for a server with its own certificate).'
}

# One request. Returns the body as text on success; turns a refusal into words, using the server's own
# sentence when it gave one (it never holds a value).
function Invoke-Hive([string]$Path, [string]$Method = 'Get', [string]$Body, [switch]$AllowNotFound) {
    $connection = Get-Connection
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), [uri]::new($connection.Server, "api/v1/$Path"))
    $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', (ConvertTo-PlainText $connection.Key))
    if ($PSBoundParameters.ContainsKey('Body')) {
        $request.Content = [System.Net.Http.StringContent]::new($Body, [Text.Encoding]::UTF8, 'application/json')
    }

    try { $response = $connection.Client.SendAsync($request).GetAwaiter().GetResult() }
    catch {
        $inner = $_.Exception
        while ($inner.InnerException) { $inner = $inner.InnerException }
        throw "SecretHive at $($connection.Server.Host) does not answer ($($inner.GetType().Name)). If it uses a certificate it made for itself, connect with -CertificateFile."
    }
    finally { $request.Dispose() }

    try {
        $text = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        $status = [int]$response.StatusCode
        if ($response.IsSuccessStatusCode) { return $text }
        if ($status -eq 404 -and $AllowNotFound) { return $null }
        if ($status -eq 401) { throw 'SecretHive does not accept this key: unknown, expired, revoked, or not allowed from this address.' }
        $detail = $null
        try { $detail = ($text | ConvertFrom-Json).detail } catch { }
        if ($status -eq 404) { throw "SecretHive has no such thing, as far as this key can tell: $Path" }
        throw ("SecretHive refuses ($status)" + $(if ($detail) { ": $detail" } else { '' }))
    }
    finally { $response.Dispose() }
}

function ConvertFrom-Reference([string]$Reference) {
    if ($Reference -notmatch '^(?<vault>[A-Za-z0-9][A-Za-z0-9._-]*)/(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)(/(?<version>[0-9]+))?(#(?<field>[A-Za-z0-9][A-Za-z0-9._-]*))?$') {
        # The text is not repeated: the commonest way to get here is a value pasted where a reference belongs.
        throw 'That is not a reference. A reference is vault/name, vault/name/version, optionally followed by #field.'
    }

    [pscustomobject]@{
        Vault   = $Matches['vault']
        Name    = $Matches['name']
        Version = $(if ($Matches['version']) { [int]$Matches['version'] } else { $null })
        Field   = $Matches['field']
    }
}

function Read-Value([string]$Vault, [string]$Name, [string]$Field, $Version) {
    $path = "vaults/$([uri]::EscapeDataString($Vault))/secrets/$([uri]::EscapeDataString($Name))/"
    $path += $(if ($Field) { "fields/$([uri]::EscapeDataString($Field))" } else { 'value' })
    if ($Version) { $path += "?version=$Version" }
    $text = Invoke-Hive $path
    $value = ($text | ConvertFrom-Json).value
    if ($null -eq $value) { throw "SecretHive's answer for $Vault/$Name holds no value." }
    ConvertTo-SecureString -String $value -AsPlainText -Force
}

function Connect-SecretHive {
    <#
    .SYNOPSIS
    Connects this session to a SecretHive server.
    .DESCRIPTION
    The key is asked for without showing it, or read from a file. Nothing is stored unless -Save is given; then
    the address and the key are kept for this Windows account on this machine (the key under Windows data
    protection), and every later session of the same account is connected without asking.
    .PARAMETER Server
    The server's https address, such as https://secrethive.example.org.
    .PARAMETER Key
    Your key (shv_...), as a secure string. Asked for when neither this nor -KeyFile is given.
    .PARAMETER KeyFile
    A file that holds the key on one line.
    .PARAMETER CertificateFile
    The server's certificate as a PEM or DER file, for a server that made its own. Exactly that certificate is
    trusted then, and nothing else.
    .PARAMETER Save
    Keep the connection for this Windows account on this machine.
    .EXAMPLE
    Connect-SecretHive -Server https://secrethive.example.org -Save
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Server,
        [securestring]$Key,
        [string]$KeyFile,
        [string]$CertificateFile,
        [switch]$Save
    )

    $address = $null
    if (-not [uri]::TryCreate($Server.TrimEnd('/') + '/', [UriKind]::Absolute, [ref]$address) -or
        -not ($address.Scheme -eq 'https' -or ($address.Scheme -eq 'http' -and $address.IsLoopback))) {
        # Plain http only to this machine: a key sent in the clear to anything else is a key given away.
        throw "'Server' must be an https address."
    }

    if ($KeyFile) {
        $line = (Get-Content -LiteralPath $KeyFile -Raw).Trim()
        if (-not $line -or $line -match '\s') { throw "$KeyFile does not hold a key on one line." }
        $Key = ConvertTo-SecureString -String $line -AsPlainText -Force
    }
    elseif (-not $Key) {
        $Key = Read-Host -AsSecureString -Prompt "Key for $($address.Host)"
    }

    $sha256 = $null
    if ($CertificateFile) {
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path -LiteralPath $CertificateFile).Path)
        $hash = [System.Security.Cryptography.SHA256]::Create()
        try { $sha256 = [BitConverter]::ToString($hash.ComputeHash($certificate.RawData)).Replace('-', '') } finally { $hash.Dispose() }
    }

    $previous = $script:Connection
    $script:Connection = New-Connection $address $Key $sha256
    try { $vaults = @(Invoke-Hive 'vaults' | ConvertFrom-Json) }
    catch {
        $script:Connection = $previous
        throw
    }

    if ($Save) {
        $path = Get-SavedConnectionPath
        if (-not $path -or $PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) {
            throw 'Saving the connection relies on Windows data protection. On this system set SECRETHIVE_SERVER and SECRETHIVE_KEY_FILE instead.'
        }

        New-Item -ItemType Directory -Force -Path (Split-Path $path) | Out-Null
        [pscustomobject]@{ Server = $address.AbsoluteUri; Key = $Key; CertificateSha256 = $sha256 } | Export-Clixml -LiteralPath $path
    }

    [pscustomobject]@{ Server = $address.AbsoluteUri; Vaults = $vaults.Count; Saved = [bool]$Save }
}

function Disconnect-SecretHive {
    <#
    .SYNOPSIS
    Ends this session's connection. With -Forget, also removes the saved one.
    #>
    [CmdletBinding()]
    param([switch]$Forget)

    if ($script:Connection) { $script:Connection.Client.Dispose() }
    $script:Connection = $null
    $path = Get-SavedConnectionPath
    if ($Forget -and $path -and (Test-Path -LiteralPath $path)) { Remove-Item -LiteralPath $path -Force }
}

function Get-SecretHiveVault {
    <#
    .SYNOPSIS
    Lists the vaults this key's owner has a role in.
    #>
    [CmdletBinding()]
    param()

    Invoke-Hive 'vaults' | ConvertFrom-Json | ForEach-Object { $_ }
}

function Get-SecretHiveFolder {
    <#
    .SYNOPSIS
    Lists the folders of vaults: every one for an administrator, for anyone else those on the way to their vaults.
    .DESCRIPTION
    Each folder with its path from the top, and how many vaults and folders are directly in it. A role given on a
    folder counts in every vault beneath it. Needs a server of release 0.23.0 or later.
    .EXAMPLE
    Get-SecretHiveFolder | Select-Object @{ n = 'path'; e = { $_.path -join '/' } }, vaults
    #>
    [CmdletBinding()]
    param()

    Invoke-Hive 'folders' | ConvertFrom-Json | ForEach-Object { $_ }
}

function Get-SecretHiveSecret {
    <#
    .SYNOPSIS
    Lists what a vault holds: names, versions, descriptions, field names. Never a value.
    .EXAMPLE
    Get-SecretHiveSecret -Vault tools | Select-Object name, version, description
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][string]$Vault,
        [Parameter(Position = 1)][string]$Name
    )

    $secrets = Invoke-Hive "vaults/$([uri]::EscapeDataString($Vault))/secrets" | ConvertFrom-Json | ForEach-Object { $_ }
    if ($Name) { $secrets | Where-Object { $_.name -eq $Name } } else { $secrets }
}

function Get-SecretHiveValue {
    <#
    .SYNOPSIS
    Reads one value: a secret's value or one of its fields. Every call is a read the server writes down.
    .DESCRIPTION
    Returns a secure string, which most commands that take a credential accept as it is. -AsPlainText returns
    text instead: use it only where the text goes straight into something, never to look at it.
    .PARAMETER Reference
    vault/name, vault/name/version, optionally followed by #field.
    .EXAMPLE
    $password = Get-SecretHiveValue tools/sql-admin
    .EXAMPLE
    $credential = [pscredential]::new((Get-SecretHiveValue tools/sql-admin#user -AsPlainText), (Get-SecretHiveValue tools/sql-admin))
    #>
    [CmdletBinding(DefaultParameterSetName = 'Reference')]
    param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = 'Reference')][string]$Reference,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Vault,
        [Parameter(Mandatory, ParameterSetName = 'Parts')][string]$Name,
        [Parameter(ParameterSetName = 'Parts')][string]$Field,
        [Parameter(ParameterSetName = 'Parts')][int]$Version,
        [switch]$AsPlainText
    )

    if ($PSCmdlet.ParameterSetName -eq 'Reference') {
        $parsed = ConvertFrom-Reference $Reference
        $Vault = $parsed.Vault; $Name = $parsed.Name; $Field = $parsed.Field; $Version = $parsed.Version
    }

    $secure = Read-Value $Vault $Name $Field $Version
    if ($AsPlainText) { ConvertTo-PlainText $secure } else { $secure }
}

function Invoke-WithSecretHive {
    <#
    .SYNOPSIS
    Runs a script block with secrets in environment variables, and takes them away again afterwards.
    .DESCRIPTION
    Every reference is read before anything runs, so a missing secret or a refusal stops it before it starts.
    The variables exist for this process and what it starts, for as long as the block runs. What the variables
    held before is put back. Nothing is written to disk and nothing is shown.
    .PARAMETER Environment
    Variable names and the reference that fills each: @{ GH_TOKEN = 'tools/github-token' }.
    .EXAMPLE
    Invoke-WithSecretHive @{ GH_TOKEN = 'tools/github-token' } { gh release list }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][hashtable]$Environment,
        [Parameter(Mandatory, Position = 1)][scriptblock]$ScriptBlock
    )

    $values = @{}
    foreach ($variable in $Environment.Keys) {
        if ($variable -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "'$variable' is not an environment variable name." }
        $parsed = ConvertFrom-Reference ([string]$Environment[$variable])
        $values[$variable] = Read-Value $parsed.Vault $parsed.Name $parsed.Field $parsed.Version
    }

    $before = @{}
    try {
        foreach ($variable in $values.Keys) {
            $before[$variable] = [System.Environment]::GetEnvironmentVariable($variable, 'Process')
            [System.Environment]::SetEnvironmentVariable($variable, (ConvertTo-PlainText $values[$variable]), 'Process')
        }

        & $ScriptBlock
    }
    finally {
        # A variable that was not there is removed, not set to nothing: an empty value is still a value.
        foreach ($variable in $before.Keys) {
            if ($null -eq $before[$variable]) { Remove-Item -LiteralPath "Env:\$variable" -ErrorAction SilentlyContinue }
            else { [System.Environment]::SetEnvironmentVariable($variable, $before[$variable], 'Process') }
        }
    }
}

. (Join-Path $PSScriptRoot 'SecretHive.Write.ps1')

Export-ModuleMember -Function Connect-SecretHive, Disconnect-SecretHive, Get-SecretHiveVault, Get-SecretHiveSecret, Get-SecretHiveValue, Invoke-WithSecretHive,
    Set-SecretHiveValue, Remove-SecretHiveSecret, Rename-SecretHiveVault, Move-SecretHiveVault, Get-SecretHiveFolder, Rename-SecretHiveSecret, Find-SecretHiveSecret, Get-SecretHiveCredential
