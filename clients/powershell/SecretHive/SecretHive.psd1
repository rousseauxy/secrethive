@{
    RootModule           = 'SecretHive.psm1'
    ModuleVersion        = '0.5.1'
    GUID                 = '6f0c1b0e-6d0b-4a39-9a55-4b6b0a2f7c11'
    Author               = 'SecretHive'
    Description          = 'Reads and sets secrets on a SecretHive server for the session that needs them, without storing them anywhere else.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FunctionsToExport    = @(
        'Connect-SecretHive',
        'Disconnect-SecretHive',
        'Get-SecretHiveVault',
        'Get-SecretHiveSecret',
        'Get-SecretHiveValue',
        'Invoke-WithSecretHive',
        'Set-SecretHiveValue',
        'Remove-SecretHiveSecret',
        'Rename-SecretHiveVault',
        'Move-SecretHiveVault',
        'Get-SecretHiveFolder',
        'Rename-SecretHiveSecret',
        'Find-SecretHiveSecret',
        'Get-SecretHiveCredential'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
}
