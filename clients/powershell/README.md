# SecretHive for PowerShell

Reads secrets from a SecretHive server for the session that needs them, so they do not have to be kept in a
profile script, an `.env` file or a second password store. Works in Windows PowerShell 5.1 and PowerShell 7, on
Windows and on Linux.
It reads values, sets them, finds secrets across vaults and makes credentials from them.

## Install

Copy the `SecretHive` folder into a module folder of your account:

```powershell
Copy-Item -Recurse .\SecretHive "$HOME\Documents\PowerShell\Modules\SecretHive"          # PowerShell 7
Copy-Item -Recurse .\SecretHive "$HOME\Documents\WindowsPowerShell\Modules\SecretHive"   # Windows PowerShell 5.1
```

## Connect

Make a key for your account on the server (your profile page), then, once:

```powershell
Connect-SecretHive -Server https://secrethive.example.org -Save
```

The key is asked for without showing it. With `-Save` the address and the key are kept for your Windows account on
this machine, the key under Windows data protection: another account or another machine cannot read it. Every
later session is connected without asking. `Disconnect-SecretHive -Forget` removes it.

A server with a certificate it made for itself is reached with `-CertificateFile <its certificate>`: exactly that
certificate is trusted and nothing else. There is no switch that turns verification off.

A session that is not a person (a scheduled task, a build agent) is connected from the environment instead:
`SECRETHIVE_SERVER`, `SECRETHIVE_KEY_FILE` and optionally `SECRETHIVE_SERVER_CERTIFICATE`.

On Linux and macOS `-Save` is refused: without Windows data protection the key in the file would only be encoded,
readable by whoever reads the file. Connect from the environment there, with the key in a file only your account
can read (`chmod 600`). On a host that renders secrets for its services, the host command does that job.

## Use

```powershell
Get-SecretHiveVault                                   # the vaults you have a role in
Get-SecretHiveSecret tools                            # names, versions, descriptions: never a value

$password = Get-SecretHiveValue tools/sql-admin       # a secure string
$user     = Get-SecretHiveValue tools/sql-admin#user -AsPlainText
$credential = [pscredential]::new($user, $password)

# A command that wants its secret in an environment variable gets it for as long as it runs, and no longer:
Invoke-WithSecretHive @{ GH_TOKEN = 'tools/github-token' } { gh release list }
```

A reference is `vault/name`, `vault/name/version` for an earlier version, and `#field` for one field.

## Set, find, and use as a credential

```powershell
Set-SecretHiveValue tools/api-token                       # asks for the value without showing it
Set-SecretHiveValue tools/sql-admin -Value $password -Field @{ username = 'sa'; owner = 'operations' }
Remove-SecretHiveSecret tools/old-token                   # to the bin, after asking; nothing is destroyed
Rename-SecretHiveVault tools tools-old                    # after asking; administrators only, server 0.18 or later
Move-SecretHiveVault tools -Folder ops                    # after asking; administrators only, server 0.23 or later
Get-SecretHiveFolder                                      # the folders, with their path
Rename-SecretHiveSecret tools/old-token -NewName api-token  # after asking; Secrets Officer, server 0.20 or later

Find-SecretHiveSecret grafana token                       # in every vault you have a role in
$credential = Get-SecretHiveCredential tools/sql-admin    # user name from the field, password from the value
```

- **A value is never text on the command line**, where it would stay in the history: it is a secure string, or it
  is asked for. One that starts or ends with whitespace is refused, because that is nearly always a pasted newline.
- **What you do not name stays.** A new value keeps the description, the fields and the sensitive fields; the
  sensitive ones are carried over without being read. A field given as `''` is removed. `-ReplaceDetails` makes the
  new version exactly what the command names.
- Setting needs the role **Secrets Writer** or **Secrets Officer** in the vault (Secrets Writer from server 0.17),
  removing needs **Secrets Officer**; with less, the server refuses and says which role it takes. `-WhatIf` and `-Confirm` work as everywhere.
- Setting needs a server of release 0.15.1 or later. Against an older one the command refuses, because that server
  would drop the fields it was not sent.
- A search looks at names, descriptions and ordinary fields, never at a value.
- Vaults and names complete with Tab: `Get-SecretHiveValue to<Tab>` gives `tools/`, then the names in it.

What the commands keep to:

- A value is a secure string unless `-AsPlainText` is given by name, and is never written to the host.
- `Invoke-WithSecretHive` reads every reference before the block starts, so a missing secret or a refusal stops
  it before anything runs. The variables are put back as they were afterwards, also when the block fails.
- Every read is a read the server writes down under the key's owner.
- You read what your role in a vault allows. Being an administrator of the server is not a role in a vault.

## Test

`tests\Test-Module.ps1 -Server <address> -AdminTokenFile <file> [-CertificateFile <file>]` runs the module against
a real server with generated values, in whichever PowerShell starts it.
