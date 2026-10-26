# Runs the module against a real server and checks what it promises. Works in Windows PowerShell 5.1 and in
# PowerShell 7, without a test framework, so it runs anywhere the module does.
#
#   Test-Module.ps1 -Server https://127.0.0.1:5199 -AdminTokenFile admin.token -CertificateFile server.crt
#
# Every value used is generated here. The saved connection is redirected to a temporary folder, so a real
# one on this machine is never touched.
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$AdminTokenFile,
    [string]$CertificateFile
)

$ErrorActionPreference = 'Stop'
$module = Join-Path $PSScriptRoot '../SecretHive/SecretHive.psd1'
Import-Module $module -Force

$script:Failed = 0
function Check([string]$What, [scriptblock]$Test) {
    try {
        if (& $Test) { Write-Output "ok    $What" } else { $script:Failed++; Write-Output "FAIL  $What" }
    }
    catch { $script:Failed++; Write-Output "FAIL  $What ($($_.Exception.Message))" }
}

# This PowerShell, to start a child of: the running executable, unless it is the dotnet host (PowerShell installed
# as a .NET tool), which takes no -Command; then the pwsh on the path.
function Get-PowerShell {
    $executable = (Get-Process -Id $PID).Path
    if ([IO.Path]::GetFileNameWithoutExtension($executable) -eq 'dotnet') { 'pwsh' } else { $executable }
}

function Refused([scriptblock]$Action, [string]$Pattern) {
    try { & $Action | Out-Null; return $false } catch { return $_.Exception.Message -match $Pattern }
}

$realAppData = $env:APPDATA
$scratch = Join-Path ([IO.Path]::GetTempPath()) ("secrethive-ps-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
$env:APPDATA = $scratch
$connect = @{ Server = $Server }
if ($CertificateFile) { $connect.CertificateFile = $CertificateFile }

try {
    $vault = 'ps-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    $secret = 'generated-' + [guid]::NewGuid().ToString('N')
    $user = 'generated-user-' + [guid]::NewGuid().ToString('N').Substring(0, 6)

    Check 'without a connection, a command says how to make one' { Refused { Get-SecretHiveVault } 'Connect-SecretHive' }
    Check 'a server that is not https is refused' { Refused { Connect-SecretHive -Server 'http://vault.example.org' -KeyFile $AdminTokenFile } 'https' }
    Check 'a key the server does not know is refused, and nothing stays connected' {
        $wrong = Join-Path $scratch 'wrong.key'
        Set-Content -LiteralPath $wrong -Value 'shv_generatednotakey0000000000000000000000000000000000' -NoNewline
        (Refused { Connect-SecretHive @connect -KeyFile $wrong } 'does not accept this key') -and (Refused { Get-SecretHiveVault } 'Connect-SecretHive')
    }
    if ($CertificateFile) {
        Check 'without its certificate named, a server with its own certificate is not talked to' {
            Refused { Connect-SecretHive -Server $Server -KeyFile $AdminTokenFile } 'does not answer'
        }
    }

    Check 'connects with a key from a file' { (Connect-SecretHive @connect -KeyFile $AdminTokenFile).Saved -eq $false }

    # What the tests read is put there with the module's own connection, as an administrator would.
    & (Get-Module SecretHive) {
        param($vault, $secret, $user)
        Invoke-Hive "vaults/$vault" -Method Put -Body '{}' | Out-Null
        Invoke-Hive "vaults/$vault/secrets/api-token" -Method Put -Body (@{ value = 'generated-first' } | ConvertTo-Json) | Out-Null
        Invoke-Hive "vaults/$vault/secrets/api-token" -Method Put -Body (@{ value = $secret; description = 'for the module test'; fields = @(@{ name = 'user'; value = $user; sensitive = $true }) } | ConvertTo-Json -Depth 4) | Out-Null
    } $vault $secret $user

    Check 'lists the vault' { @(Get-SecretHiveVault | Where-Object { $_.name -eq $vault }).Count -eq 1 }
    Check 'lists the secret with its version and no value' {
        $listed = Get-SecretHiveSecret $vault api-token
        $listed.version -eq 2 -and -not (($listed | ConvertTo-Json -Depth 6) -match [regex]::Escape($secret))
    }
    Check 'a value comes back as a secure string' { (Get-SecretHiveValue "$vault/api-token") -is [securestring] }
    Check 'as text only when asked, and it is the value' { (Get-SecretHiveValue "$vault/api-token" -AsPlainText) -ceq $secret }
    Check 'a field is read with #field' { (Get-SecretHiveValue "$vault/api-token#user" -AsPlainText) -ceq $user }
    Check 'an earlier version is read with /version' { (Get-SecretHiveValue "$vault/api-token/1" -AsPlainText) -ceq 'generated-first' }
    Check 'the same by parts' { (Get-SecretHiveValue -Vault $vault -Name api-token -Version 1 -AsPlainText) -ceq 'generated-first' }
    Check 'a name that is not there is said to be not there' { Refused { Get-SecretHiveValue "$vault/nothing-here" } 'no such thing' }
    Check 'something that is not a reference is refused without repeating it' {
        $pasted = 'generated pasted value = with; things'
        try { Get-SecretHiveValue $pasted | Out-Null; $false } catch { $_.Exception.Message -match 'not a reference' -and $_.Exception.Message -notmatch 'pasted' }
    }

    Check 'a block runs with the value in its environment, and a child process sees it' {
        $env:SECRETHIVE_TEST_TOKEN = 'what-was-there'
        $seen = Invoke-WithSecretHive @{ SECRETHIVE_TEST_TOKEN = "$vault/api-token"; SECRETHIVE_TEST_USER = "$vault/api-token#user" } {
            $executable = Get-PowerShell
            & $executable -NoProfile -Command '[Console]::Out.Write($env:SECRETHIVE_TEST_TOKEN + [char]124 + $env:SECRETHIVE_TEST_USER)'
        }
        $seen -ceq "$secret|$user"
    }
    Check 'afterwards the variables are as they were' { $env:SECRETHIVE_TEST_TOKEN -ceq 'what-was-there' -and $null -eq $env:SECRETHIVE_TEST_USER }
    Check 'they are taken away even when the block fails' {
        try { Invoke-WithSecretHive @{ SECRETHIVE_TEST_USER = "$vault/api-token#user" } { throw 'the block failed' } } catch { }
        $null -eq $env:SECRETHIVE_TEST_USER
    }
    Check 'a missing secret stops it before the block runs' {
        $ran = $false
        try { Invoke-WithSecretHive @{ A_TOKEN = "$vault/api-token"; B_TOKEN = "$vault/nothing-here" } { $script:ran = $true } } catch { }
        -not $ran -and $null -eq $env:A_TOKEN
    }
    Remove-Item Env:SECRETHIVE_TEST_TOKEN -ErrorAction SilentlyContinue

    # Writing: as a secure string, keeping what is not named.
    $secure = { param($text) ConvertTo-SecureString -String $text -AsPlainText -Force }
    Check 'a secret is made from a secure string, and says so' {
        $made = Set-SecretHiveValue "$vault/sql-admin" -Value (& $secure 'generated-sql-1') -Description 'the database' -Field @{ username = 'generated-sa'; owner = 'operations' } -SensitiveField @{ pin = (& $secure 'generated-pin') }
        $made.Version -eq 1 -and (Get-SecretHiveValue "$vault/sql-admin" -AsPlainText) -ceq 'generated-sql-1'
    }
    Check 'a new value keeps the description, the fields and the sensitive fields it does not name' {
        $next = Set-SecretHiveValue -Vault $vault -Name sql-admin -Value (& $secure 'generated-sql-2')
        $listed = Get-SecretHiveSecret $vault sql-admin
        $next.Version -eq 2 -and $listed.description -ceq 'the database' -and $listed.fields.username -ceq 'generated-sa' -and
            $listed.fields.owner -ceq 'operations' -and (Get-SecretHiveValue "$vault/sql-admin#pin" -AsPlainText) -ceq 'generated-pin' -and
            (Get-SecretHiveValue "$vault/sql-admin" -AsPlainText) -ceq 'generated-sql-2'
    }
    Check 'a field named is changed, one given empty is removed, the rest stays' {
        Set-SecretHiveValue "$vault/sql-admin" -Value (& $secure 'generated-sql-3') -Field @{ owner = ''; url = 'https://db.example.test' } -SensitiveField @{ pin = 'generated-pin-2' } | Out-Null
        $listed = Get-SecretHiveSecret $vault sql-admin
        $names = @($listed.fields.PSObject.Properties | ForEach-Object { $_.Name }) -join ','
        ($names -eq 'url,username' -or $names -eq 'username,url') -and $listed.description -ceq 'the database' -and (Get-SecretHiveValue "$vault/sql-admin#pin" -AsPlainText) -ceq 'generated-pin-2'
    }
    Check 'asked to replace, the new version is exactly what was named' {
        Set-SecretHiveValue "$vault/throwaway" -Value (& $secure 'generated-a') -Description 'kept until replaced' -SensitiveField @{ pin = 'generated-p' } | Out-Null
        Set-SecretHiveValue "$vault/throwaway" -Value (& $secure 'generated-b') -ReplaceDetails | Out-Null
        $listed = Get-SecretHiveSecret $vault throwaway
        -not $listed.description -and @($listed.sensitiveFields).Count -eq 0
    }
    Check '-WhatIf changes nothing' {
        Set-SecretHiveValue "$vault/sql-admin" -Value (& $secure 'generated-never') -WhatIf | Out-Null
        Remove-SecretHiveSecret "$vault/sql-admin" -WhatIf
        (Get-SecretHiveSecret $vault sql-admin).version -eq 3
    }
    Check 'a value with a newline at its end is refused unless that is asked for' {
        (Refused { Set-SecretHiveValue "$vault/sql-admin" -Value (& $secure "generated-pasted`n") } 'whitespace') -and (Get-SecretHiveSecret $vault sql-admin).version -eq 3
    }
    Check 'a version or a field is not a thing to set, and neither message repeats what was typed' {
        (Refused { Set-SecretHiveValue "$vault/sql-admin/2" -Value (& $secure 'generated-x') } 'version cannot be named') -and
        (Refused { Set-SecretHiveValue "$vault/sql-admin#pin" -Value (& $secure 'generated-x') } 'not one of its fields')
    }
    Check 'a credential comes from one secret: the user name from its field, the password from its value' {
        $credential = Get-SecretHiveCredential "$vault/sql-admin"
        $credential.UserName -ceq 'generated-sa' -and $credential.GetNetworkCredential().Password -ceq 'generated-sql-3'
    }
    Check 'and from a sensitive field when that is where the name is' {
        (Get-SecretHiveCredential "$vault/api-token" -UserNameField user).UserName -ceq $user
    }
    Check 'a search finds it across vaults by a word of its name or a field, and never by its value' {
        $byName = @(Find-SecretHiveSecret sql admin | Where-Object { $_.vault -eq $vault })
        $byField = @(Find-SecretHiveSecret generated-sa | Where-Object { $_.vault -eq $vault })
        $byName.Count -eq 1 -and $byField.Count -eq 1 -and @(Find-SecretHiveSecret generated-sql-3).Count -eq 0
    }
    Check 'tab completes a vault, then the names in it' {
        $line = "Get-SecretHiveValue $($vault.Substring(0, 6))"
        $vaults = @((TabExpansion2 $line $line.Length).CompletionMatches | ForEach-Object { $_.CompletionText })
        $line = "Get-SecretHiveValue $vault/sql"
        $names = @((TabExpansion2 $line $line.Length).CompletionMatches | ForEach-Object { $_.CompletionText })
        ($vaults -contains "$vault/") -and ($names -contains "$vault/sql-admin")
    }
    Check 'a key that may only read is refused, in the server''s words, and nothing changes' {
        $readerKey = Join-Path $scratch 'reader.key'
        & (Get-Module SecretHive) {
            param($vault, $file)
            Invoke-Hive 'service-identities/generated-reader' -Method Put -Body '{}' | Out-Null
            Invoke-Hive "vaults/$vault/access" -Method Put -Body (@{ user = 'generated-reader'; role = 'SecretsUser' } | ConvertTo-Json) | Out-Null
            $made = Invoke-Hive 'service-identities/generated-reader/keys' -Method Post -Body (@{ label = 'reads'; days = 1 } | ConvertTo-Json) | ConvertFrom-Json
            Set-Content -LiteralPath $file -Value $made.key -NoNewline
        } $vault $readerKey
        Connect-SecretHive @connect -KeyFile $readerKey | Out-Null
        try {
            (Refused { Set-SecretHiveValue "$vault/sql-admin" -Value (& $secure 'generated-denied') } 'Secrets Officer') -and
            (Refused { Remove-SecretHiveSecret "$vault/sql-admin" -Confirm:$false } 'Secrets Officer') -and
            (Get-SecretHiveValue "$vault/sql-admin" -AsPlainText) -ceq 'generated-sql-3'
        }
        finally { Connect-SecretHive @connect -KeyFile $AdminTokenFile | Out-Null }
    }
    Check 'a secret goes to the bin, and is gone from the vault' {
        Remove-SecretHiveSecret "$vault/sql-admin" -Confirm:$false
        Remove-SecretHiveSecret -Vault $vault -Name throwaway -Confirm:$false
        $null -eq (Get-SecretHiveSecret $vault sql-admin) -and (Refused { Get-SecretHiveValue "$vault/sql-admin" } 'no such thing')
    }

    Check 'every read is on record at the server' {
        $rows = & (Get-Module SecretHive) { param($vault) Invoke-Hive "vaults/$vault/audit?take=100" | ConvertFrom-Json | ForEach-Object { $_ } } $vault
        @($rows | Where-Object { $_.code -eq 'secret.value.read' }).Count -ge 8
    }

    Check 'a secret is renamed: its value and versions follow, the old name is gone, and it is on record' {
        Set-SecretHiveValue "$vault/to-rename" -Value (& $secure 'generated-renamed') -Confirm:$false | Out-Null
        Rename-SecretHiveSecret "$vault/to-rename" -NewName renamed -WhatIf
        $still = (Get-SecretHiveValue "$vault/to-rename" -AsPlainText) -ceq 'generated-renamed'
        Rename-SecretHiveSecret "$vault/to-rename" -NewName renamed -Confirm:$false | Out-Null
        $moved = (Get-SecretHiveValue "$vault/renamed" -AsPlainText) -ceq 'generated-renamed' -and (Refused { Get-SecretHiveValue "$vault/to-rename" } 'no such thing|no secret|not found')
        $same = Refused { Rename-SecretHiveSecret "$vault/renamed" -NewName RENAMED -Confirm:$false } 'already has that name'
        Remove-SecretHiveSecret "$vault/renamed" -Confirm:$false
        $still -and $moved -and $same
    }
    Check 'a vault is renamed: everything in it follows, the old name is gone, and it is on record' {
        $renamed = "$vault-renamed"
        Rename-SecretHiveVault $vault $renamed -WhatIf
        $before = @(Get-SecretHiveSecret $vault).Count
        Rename-SecretHiveVault $vault $renamed -Confirm:$false | Out-Null
        $moved = @(Get-SecretHiveSecret $renamed).Count -eq $before -and (Refused { Get-SecretHiveSecret $vault } 'no vault|no such')
        $taken = Refused { Rename-SecretHiveVault $renamed $renamed -Confirm:$false } 'already has that name'
        $rows = & (Get-Module SecretHive) { param($v) Invoke-Hive "vaults/$v/audit?take=200" | ConvertFrom-Json | ForEach-Object { $_ } } $renamed
        $history = @($rows | Where-Object { $_.code -eq 'secret.value.read' }).Count -ge 8 -and @($rows | Where-Object { $_.code -eq 'vault.renamed' -and $_.severity -eq 'Security' }).Count -eq 1
        Rename-SecretHiveVault $renamed $vault -Confirm:$false | Out-Null
        $before -ge 1 -and $moved -and $taken -and $history -and @(Get-SecretHiveSecret $vault).Count -eq $before
    }
    Check 'a vault goes into a folder and back, the folder is listed, and the moves are on record' {
        & (Get-Module SecretHive) { Invoke-Hive 'folders/module-folder' -Method Put -Body '{"description":"made by the module test"}' } | Out-Null
        Move-SecretHiveVault $vault -Folder module-folder -WhatIf
        $untouched = -not (@(Get-SecretHiveVault) | Where-Object { $_.name -eq $vault }).folder
        Move-SecretHiveVault $vault -Folder module-folder -Confirm:$false
        $inside = (@(Get-SecretHiveVault) | Where-Object { $_.name -eq $vault }).folder -eq 'module-folder'
        $listed = @(Get-SecretHiveFolder | Where-Object { $_.name -eq 'module-folder' -and $_.vaults -eq 1 }).Count -eq 1
        $again = Refused { Move-SecretHiveVault $vault -Folder module-folder -Confirm:$false } 'already'
        Move-SecretHiveVault $vault -Confirm:$false
        $back = -not (@(Get-SecretHiveVault) | Where-Object { $_.name -eq $vault }).folder
        $rows = & (Get-Module SecretHive) { param($v) Invoke-Hive "vaults/$v/audit?take=50" | ConvertFrom-Json | ForEach-Object { $_ } } $vault
        $recorded = @($rows | Where-Object { $_.code -eq 'vault.folder.changed' }).Count -eq 2
        & (Get-Module SecretHive) { Invoke-Hive 'folders/module-folder' -Method Delete } | Out-Null
        $untouched -and $inside -and $listed -and $again -and $back -and $recorded
    }
    if ($PSVersionTable.PSEdition -eq 'Desktop' -or $IsWindows) {
        Check 'a saved connection holds the key protected, not as text' {
            (Connect-SecretHive @connect -KeyFile $AdminTokenFile -Save).Saved | Out-Null
            $file = Join-Path $scratch 'SecretHive/connection.clixml'
            $token = (Get-Content -LiteralPath $AdminTokenFile -Raw).Trim()
            (Test-Path $file) -and -not ((Get-Content -LiteralPath $file -Raw) -match [regex]::Escape($token))
        }
        Check 'a new session of the same account is connected without asking' {
            $executable = Get-PowerShell
            $command = "Import-Module '$module'; [Console]::Out.Write(@(Get-SecretHiveSecret $vault).Count)"
            (& $executable -NoProfile -Command $command) -eq '1'
        }
        Check 'forgetting removes the saved connection' {
            Disconnect-SecretHive -Forget
            -not (Test-Path (Join-Path $scratch 'SecretHive/connection.clixml')) -and (Refused { Get-SecretHiveVault } 'Connect-SecretHive')
        }
    }
    else {
        # No Windows data protection here: a key "protected" in a file would only be encoded, readable by whoever
        # reads the file. So -Save refuses, after the connection was checked, and writes nothing at all.
        Check 'off Windows, -Save is refused, says what to use instead, and writes nothing' {
            $before = @(Get-ChildItem -LiteralPath $scratch -Recurse -Force | ForEach-Object FullName)
            $refused = Refused { Connect-SecretHive @connect -KeyFile $AdminTokenFile -Save } 'SECRETHIVE_SERVER and SECRETHIVE_KEY_FILE'
            $after = @(Get-ChildItem -LiteralPath $scratch -Recurse -Force | ForEach-Object FullName)
            Disconnect-SecretHive
            $refused -and -not (Compare-Object $before $after)
        }
    }
    Check 'a session that is not a person is connected from the environment' {
        $env:SECRETHIVE_SERVER = $Server; $env:SECRETHIVE_KEY_FILE = $AdminTokenFile; $env:SECRETHIVE_SERVER_CERTIFICATE = $CertificateFile
        try { @(Get-SecretHiveSecret $vault).Count -eq 1 }
        finally { Remove-Item Env:SECRETHIVE_SERVER, Env:SECRETHIVE_KEY_FILE, Env:SECRETHIVE_SERVER_CERTIFICATE -ErrorAction SilentlyContinue; Disconnect-SecretHive }
    }
}
finally {
    $env:APPDATA = $realAppData
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Output "$(if ($script:Failed) { "$script:Failed FAILED" } else { 'all passed' }) on PowerShell $($PSVersionTable.PSVersion)"
exit $script:Failed
