using System.Data;
using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using SecretHive.Domain;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Infrastructure.Backup;

/// <summary>What a backup says about itself, once its seal has been checked.</summary>
public sealed record BackupFacts(DateTime CreatedUtc, string MasterKeyId, string Server, string Schema, IReadOnlyDictionary<string, int> Rows)
{
    public int Total => Rows.Values.Sum();
}

/// <summary>
/// The key that seals backups, derived from the master key, and the id of that master key. A backup carries a
/// keyed checksum over everything in it: a file that was changed, cut short, or made under another master key
/// fails the check before a single row is read into a database.
/// </summary>
public sealed class BackupSeal(byte[] key, string masterKeyId, IReadOnlyDictionary<string, byte[]>? earlier = null)
{
    private const string Purpose = "secrethive/backup-seal/v1";

    internal byte[] Key { get; } = key;

    public string MasterKeyId { get; } = masterKeyId;

    /// <summary>
    /// The key a backup made under the given master key was sealed with, or null when this server was not given
    /// that master key. A backup from before a rotation is read while the old key is still named as retired.
    /// </summary>
    internal byte[]? KeyFor(string id) => string.Equals(id, MasterKeyId, StringComparison.Ordinal) ? Key : earlier?.GetValueOrDefault(id);

    public static BackupSeal From(MasterKey master, IEnumerable<MasterKey>? retired = null)
    {
        ArgumentNullException.ThrowIfNull(master);
        return new BackupSeal(master.Derive(Purpose), master.Id, (retired ?? []).ToDictionary(old => old.Id, old => old.Derive(Purpose), StringComparer.Ordinal));
    }
}

/// <summary>
/// The whole database as one file, and back. Rows are written as they are stored: what is encrypted in the database
/// is the same ciphertext in the file, and the master key is in neither. The file does not belong to a database
/// product: one made on SQLite restores into SQL Server and the other way round.
///
/// The format is gzip around lines of JSON: a header, one line per row in an order a database accepts (what is
/// referred to comes before what refers to it), and a last line with the row count and the seal.
/// </summary>
public sealed class BackupArchive(SecretHiveDbContext db, BackupSeal seal, TimeProvider clock)
{
    private const string Format = "secrethive-backup";
    private const int Version = 1;
    private const int Batch = 500;

    public async Task<BackupFacts> WriteAsync(Stream output, string serverVersion, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(output);
        var created = clock.GetUtcNow().UtcDateTime;
        var schema = (await db.Database.GetAppliedMigrationsAsync(cancellationToken)).LastOrDefault() is { } last ? last[(last.IndexOf('_', StringComparison.Ordinal) + 1)..] : "";
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);

        using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, seal.Key);
        await using var gzip = new GZipStream(output, CompressionLevel.Optimal, leaveOpen: true);
        async Task Line(string json)
        {
            var bytes = Encoding.UTF8.GetBytes(json + "\n");
            mac.AppendData(bytes);
            await gzip.WriteAsync(bytes, cancellationToken);
        }

        // One view of the database for the whole file: a row written while the backup runs is in it with everything
        // it refers to, or not in it at all.
        await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, cancellationToken);
        await Line(JsonSerializer.Serialize(new Header(Format, Version, created, seal.MasterKeyId, serverVersion, schema)));
        var total = 0;
        foreach (var table in Tables())
        {
            var properties = table.GetProperties().ToList();
            var count = 0;
            await foreach (var entity in Rows(table).WithCancellation(cancellationToken))
            {
                var row = new Dictionary<string, JsonElement>(properties.Count, StringComparer.Ordinal);
                foreach (var property in properties)
                {
                    row[property.Name] = JsonSerializer.SerializeToElement(property.PropertyInfo!.GetValue(entity), property.ClrType);
                }

                await Line(JsonSerializer.Serialize(new Row(table.GetTableName()!, row)));
                count++;
            }

            counts[table.GetTableName()!] = count;
            total += count;
        }

        await transaction.CommitAsync(cancellationToken);
        await gzip.WriteAsync(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new Trailer(true, total, Convert.ToHexString(mac.GetHashAndReset()))) + "\n"), cancellationToken);
        return new BackupFacts(created, seal.MasterKeyId, serverVersion, schema, counts);
    }

    /// <summary>
    /// Reads a backup to its end and checks its seal, changing nothing. Throws a <see cref="DomainException"/> that
    /// says what is wrong: not a backup, made under another master key, or damaged.
    /// </summary>
    public async Task<BackupFacts> VerifyAsync(Stream input, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        Header? header = null;
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        await foreach (var (line, _) in Lines(input, cancellationToken))
        {
            if (header is null)
            {
                header = line.Deserialize<Header>()!;
                continue;
            }

            var table = line.GetProperty("t").GetString()!;
            counts[table] = counts.GetValueOrDefault(table) + 1;
        }

        return new BackupFacts(header!.CreatedUtc, header.MasterKeyId, header.Server, header.Schema, counts);
    }

    /// <summary>
    /// Fills an empty database from a backup. The seal is checked over the whole file first, and everything goes in
    /// as one transaction: a restore either happened or left the database as empty as it was. It never merges: a
    /// database that holds anything is refused.
    /// </summary>
    /// <param name="open">Opens the backup from its start; it is read twice.</param>
    public async Task<BackupFacts> RestoreAsync(Func<Stream> open, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(open);
        BackupFacts facts;
        await using (var first = open())
        {
            facts = await VerifyAsync(first, cancellationToken);
        }

        var tables = Tables().ToDictionary(table => table.GetTableName()!, StringComparer.Ordinal);
        foreach (var table in tables.Values)
        {
            await using var rows = Rows(table).GetAsyncEnumerator(cancellationToken);
            if (await rows.MoveNextAsync())
            {
                throw new DomainException("restore.not_empty", $"This database already holds data (table {table.GetTableName()}). A restore only fills an empty one; nothing was changed.");
            }
        }

        var sqlServer = db.Database.ProviderName?.Contains("SqlServer", StringComparison.Ordinal) == true;
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken);
        IEntityType? current = null;
        var pending = new List<object>(Batch);

        async Task Flush()
        {
            if (current is null || pending.Count == 0)
            {
                return;
            }

            // The rows keep the keys they had: everything else refers to them. SQL Server only takes a given value
            // for a generated key while told to, and for one table at a time.
            var identity = sqlServer && current.FindPrimaryKey()!.Properties is [{ ValueGenerated: ValueGenerated.OnAdd } key] && (key.ClrType == typeof(int) || key.ClrType == typeof(long));
            var name = "[" + current.GetTableName()!.Replace("]", "]]", StringComparison.Ordinal) + "]";
            if (identity)
            {
#pragma warning disable EF1002 // A table name from the model, bracket-quoted; a table name cannot be a parameter.
                await db.Database.ExecuteSqlRawAsync($"SET IDENTITY_INSERT {name} ON", cancellationToken);
#pragma warning restore EF1002
            }

            db.AddRange(pending);
            await db.SaveChangesAsync(cancellationToken);
            db.ChangeTracker.Clear();
            pending.Clear();
            if (identity)
            {
#pragma warning disable EF1002
                await db.Database.ExecuteSqlRawAsync($"SET IDENTITY_INSERT {name} OFF", cancellationToken);
#pragma warning restore EF1002
            }
        }

        await using (var second = open())
        {
            var header = true;
            await foreach (var (line, _) in Lines(second, cancellationToken))
            {
                if (header)
                {
                    header = false;
                    continue;
                }

                var tableName = line.GetProperty("t").GetString()!;
                if (!tables.TryGetValue(tableName, out var table))
                {
                    throw new DomainException("backup.unknown_schema", $"The backup holds a table this release does not know ({tableName}). Restore it with the release that made it ({facts.Server}), then upgrade.");
                }

                if (table != current || pending.Count >= Batch)
                {
                    await Flush();
                    current = table;
                }

                var entity = Activator.CreateInstance(table.ClrType)!;
                foreach (var column in line.GetProperty("r").EnumerateObject())
                {
                    var property = table.FindProperty(column.Name)
                        ?? throw new DomainException("backup.unknown_schema", $"The backup holds a column this release does not know ({tableName}.{column.Name}). Restore it with the release that made it ({facts.Server}), then upgrade.");
                    property.PropertyInfo!.SetValue(entity, column.Value.Deserialize(property.ClrType));
                }

                pending.Add(entity);
            }
        }

        await Flush();

        // A backup from before 0.18 has no vault id on its audit rows: give them one, as the migration did.
        await db.Database.ExecuteSqlRawAsync(SecretHive.Infrastructure.Persistence.AuditVaults.Backfill, cancellationToken);
        await db.Database.ExecuteSqlRawAsync(SecretHive.Infrastructure.Persistence.AuditEntries.Backfill, cancellationToken);
        await transaction.CommitAsync(cancellationToken);
        return facts;
    }

    /// <summary>
    /// The lines of a backup, each checked into the seal as it is read; the last one, which holds the seal, is
    /// compared and not returned. Nothing a caller does with a line counts until this has run to its end.
    /// </summary>
    private async IAsyncEnumerable<(JsonElement Line, int Number)> Lines(Stream input, [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        StreamReader reader;
        string? held;
        try
        {
            reader = new StreamReader(new GZipStream(input, CompressionMode.Decompress), Encoding.UTF8);
            held = await reader.ReadLineAsync(cancellationToken);
        }
        catch (InvalidDataException)
        {
            throw NotABackup();
        }

        using var _ = reader;
        if (held is null)
        {
            throw NotABackup();
        }

        Header header;
        try
        {
            header = JsonSerializer.Deserialize<Header>(held) ?? throw NotABackup();
        }
        catch (JsonException)
        {
            throw NotABackup();
        }

        if (header.Format != Format)
        {
            throw NotABackup();
        }

        if (header.Version != Version)
        {
            throw new DomainException("backup.unknown_schema", $"This backup has format version {header.Version.ToString(CultureInfo.InvariantCulture)}; this release reads version {Version.ToString(CultureInfo.InvariantCulture)}.");
        }

        // Said first, because it is the mistake that is easy to make and easy to fix: the right file, the wrong key.
        if (seal.KeyFor(header.MasterKeyId ?? "") is not { } sealKey)
        {
            throw new DomainException("backup.wrong_key", $"This backup was made under master key {header.MasterKeyId}; the server is running with {seal.MasterKeyId}. Nothing in it could be read with this key.");
        }

        using var mac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, sealKey);

        var number = 0;
        var rows = 0;
        while (true)
        {
            string? next;
            try
            {
                next = await reader.ReadLineAsync(cancellationToken);
            }
            catch (InvalidDataException)
            {
                throw Damaged();
            }

            if (next is null)
            {
                break;
            }

            mac.AppendData(Encoding.UTF8.GetBytes(held + "\n"));
            JsonElement line;
            try
            {
                line = JsonSerializer.Deserialize<JsonElement>(held);
            }
            catch (JsonException)
            {
                throw Damaged();
            }

            if (number > 0)
            {
                // Every line after the header is a row: a table name and its columns. Anything else is not ours.
                if (line.ValueKind != JsonValueKind.Object
                    || !line.TryGetProperty("t", out var table) || table.ValueKind != JsonValueKind.String
                    || !line.TryGetProperty("r", out var columns) || columns.ValueKind != JsonValueKind.Object)
                {
                    throw Damaged();
                }

                rows++;
            }

            yield return (line, number++);
            held = next;
        }

        Trailer? trailer;
        try
        {
            trailer = JsonSerializer.Deserialize<Trailer>(held);
        }
        catch (JsonException)
        {
            throw Damaged();
        }

        if (trailer is not { End: true, Mac: not null }
            || trailer.Rows != rows
            || !CryptographicOperations.FixedTimeEquals(mac.GetHashAndReset(), TryHex(trailer.Mac)))
        {
            throw Damaged();
        }
    }

    private static byte[] TryHex(string text)
    {
        try
        {
            return Convert.FromHexString(text);
        }
        catch (FormatException)
        {
            return [];
        }
    }

    private static DomainException NotABackup() => new("backup.not_a_backup", "This file is not a SecretHive backup.");

    private static DomainException Damaged() => new("backup.damaged", "This backup is damaged, incomplete or was changed after it was made: its seal does not match. Nothing was restored.");

    /// <summary>Every table, with what is referred to before what refers to it.</summary>
    private List<IEntityType> Tables()
    {
        var remaining = db.Model.GetEntityTypes().OrderBy(type => type.GetTableName(), StringComparer.Ordinal).ToList();
        var ordered = new List<IEntityType>(remaining.Count);
        while (remaining.Count > 0)
        {
            var ready = remaining.Where(type => type.GetForeignKeys().All(key => key.PrincipalEntityType == type || ordered.Contains(key.PrincipalEntityType))).ToList();
            if (ready.Count == 0)
            {
                throw new InvalidOperationException("The tables refer to each other in a circle; a backup cannot order them.");
            }

            ordered.AddRange(ready);
            remaining.RemoveAll(ready.Contains);
        }

        return ordered;
    }

    private IAsyncEnumerable<object> Rows(IEntityType table) =>
        (IAsyncEnumerable<object>)typeof(BackupArchive).GetMethod(nameof(RowsOf), System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance)!
            .MakeGenericMethod(table.ClrType)
            .Invoke(this, [])!;

    private IAsyncEnumerable<T> RowsOf<T>()
        where T : class => db.Set<T>().AsNoTracking().AsAsyncEnumerable();

    private sealed record Header(
        [property: System.Text.Json.Serialization.JsonPropertyName("format")] string Format,
        [property: System.Text.Json.Serialization.JsonPropertyName("version")] int Version,
        [property: System.Text.Json.Serialization.JsonPropertyName("createdUtc")] DateTime CreatedUtc,
        [property: System.Text.Json.Serialization.JsonPropertyName("masterKeyId")] string MasterKeyId,
        [property: System.Text.Json.Serialization.JsonPropertyName("server")] string Server,
        [property: System.Text.Json.Serialization.JsonPropertyName("schema")] string Schema);

    private sealed record Row(
        [property: System.Text.Json.Serialization.JsonPropertyName("t")] string Table,
        [property: System.Text.Json.Serialization.JsonPropertyName("r")] Dictionary<string, JsonElement> Values);

    private sealed record Trailer(
        [property: System.Text.Json.Serialization.JsonPropertyName("end")] bool End,
        [property: System.Text.Json.Serialization.JsonPropertyName("rows")] int Rows,
        [property: System.Text.Json.Serialization.JsonPropertyName("mac")] string? Mac);
}
