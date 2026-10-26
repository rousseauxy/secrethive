# Starts the server from the build output with a throwaway master key, administrator token and database, waits
# until it answers, and writes the certificate it made for itself to a file. For the module's tests on a machine
# that has nothing but the SDK, such as the Windows runner. Prints the three things the test script needs.
#
#   $server = .\Start-TestServer.ps1 -Folder $env:RUNNER_TEMP\hive
#   .\Test-Module.ps1 -Server $server.Address -AdminTokenFile $server.AdminTokenFile -CertificateFile $server.CertificateFile
param(
    [Parameter(Mandatory)][string]$Folder,
    [int]$HttpPort = 5198,
    [int]$TlsPort = 5199,
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repository = Resolve-Path (Join-Path $PSScriptRoot '../../..')
New-Item -ItemType Directory -Force -Path (Join-Path $Folder 'data') | Out-Null

$key = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($key)
Set-Content -LiteralPath (Join-Path $Folder 'master.key') -Value ([Convert]::ToBase64String($key)) -NoNewline -Encoding ascii
$token = New-Object byte[] 24
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($token)
Set-Content -LiteralPath (Join-Path $Folder 'admin.token') -Value (-join ($token | ForEach-Object { $_.ToString('x2') })) -NoNewline -Encoding ascii

$env:SecretHive__MasterKeyFile = Join-Path $Folder 'master.key'
$env:SecretHive__Auth__BootstrapAdminTokenFile = Join-Path $Folder 'admin.token'
$env:SecretHive__DataDirectory = Join-Path $Folder 'data'
$env:SecretHive__Database__ConnectionString = "Data Source=$(Join-Path $Folder 'data/secrethive.db')"
$env:SecretHive__Http__Port = "$HttpPort"
$env:SecretHive__Tls__Port = "$TlsPort"
$env:SecretHive__Tls__HostNames = '127.0.0.1'
$env:ASPNETCORE_ENVIRONMENT = 'Development'

$log = Join-Path $Folder 'server.log'
$start = @{
    FilePath               = 'dotnet'
    PassThru               = $true
    ArgumentList           = @('run', '--project', (Join-Path $repository 'src/SecretHive.Web'), '--no-build', '-c', $Configuration)
    RedirectStandardOutput = $log
    RedirectStandardError  = Join-Path $Folder 'server.err'
}
# A window to hide exists only on Windows; elsewhere the parameter is refused.
if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) { $start.WindowStyle = 'Hidden' }
$process = Start-Process @start

$up = $false
foreach ($attempt in 1..60) {
    try {
        $client = New-Object Net.Sockets.TcpClient
        $client.Connect('127.0.0.1', $TlsPort)
        $client.Dispose()
        $up = $true
        break
    }
    catch { Start-Sleep -Seconds 1 }
    if ($process.HasExited) { break }
}

if (-not $up) {
    Get-Content -LiteralPath $log -Tail 30 -ErrorAction SilentlyContinue
    Get-Content -LiteralPath (Join-Path $Folder 'server.err') -Tail 30 -ErrorAction SilentlyContinue
    throw 'The test server did not start.'
}

# The certificate the server presents, as a file. It is accepted here unseen exactly once, to be able to write it
# down; the module under test then trusts that file and nothing else.
$client = New-Object Net.Sockets.TcpClient('127.0.0.1', $TlsPort)
$stream = New-Object Net.Security.SslStream($client.GetStream(), $false, ([Net.Security.RemoteCertificateValidationCallback] { $true }))
try {
    $stream.AuthenticateAsClient('127.0.0.1')
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2($stream.RemoteCertificate)
    $pem = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($certificate.RawData, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
    Set-Content -LiteralPath (Join-Path $Folder 'server.crt') -Value $pem -NoNewline -Encoding ascii
}
finally {
    $stream.Dispose()
    $client.Dispose()
}

[pscustomobject]@{
    Address         = "https://127.0.0.1:$TlsPort"
    AdminTokenFile  = Join-Path $Folder 'admin.token'
    CertificateFile = Join-Path $Folder 'server.crt'
    ProcessId       = $process.Id
}
