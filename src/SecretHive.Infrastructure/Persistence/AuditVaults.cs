namespace SecretHive.Infrastructure.Persistence;

/// <summary>
/// Audit rows written before 0.18 know their vault by name only. This gives each one about a vault that still exists
/// that vault's id: run by the migration that added the column, and after restoring a backup made before it.
/// </summary>
public static class AuditVaults
{
    /// <summary>The same statement on SQLite and SQL Server. Rows that already have an id are left alone.</summary>
    public const string Backfill =
        "UPDATE Audit SET VaultId = (SELECT v.Id FROM Vaults v WHERE v.NameKey = LOWER(Audit.Vault)) WHERE Audit.Vault IS NOT NULL AND Audit.VaultId IS NULL";
}

/// <summary>
/// Audit rows written before 0.20 know their secret by name only. This gives each one that names a version that
/// secret's id: the entry in the row's vault that holds the version's value (a value has one name per vault). Rows
/// without a version stay as they are and are found by their vault and name. Run by the migration that added the
/// column, and after restoring a backup made before it.
/// </summary>
public static class AuditEntries
{
    /// <summary>The same statement on SQLite and SQL Server. Rows that already have an id are left alone.</summary>
    public const string Backfill =
        "UPDATE Audit SET EntryId = (SELECT MIN(e.Id) FROM Entries e JOIN Versions v ON v.ValueId = e.ValueId WHERE v.Id = Audit.VersionId AND e.VaultId = Audit.VaultId) " +
        "WHERE Audit.EntryId IS NULL AND Audit.VersionId IS NOT NULL AND Audit.VaultId IS NOT NULL";
}
