using System.Globalization;
using System.Text.RegularExpressions;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Infrastructure.Backup;

/// <summary>Where backups go and how many are kept.</summary>
public sealed record BackupOptions(string Directory, int Keep = 14, int IntervalHours = 24, bool Enabled = true, string ServerVersion = "unknown");

/// <summary>
/// What the health endpoint reports: when a backup was last made AND read back with its seal intact. A backup that
/// was written and never read is a hope, so only a verified one counts.
/// </summary>
public sealed class BackupStatus
{
    private readonly Lock gate = new();
    private DateTime? lastVerifiedUtc;
    private string? lastError;

    public DateTime? LastVerifiedUtc
    {
        get { lock (gate) { return lastVerifiedUtc; } }
    }

    public string? LastError
    {
        get { lock (gate) { return lastError; } }
    }

    public void Verified(DateTime createdUtc)
    {
        lock (gate)
        {
            lastVerifiedUtc = lastVerifiedUtc is { } known && known > createdUtc ? known : createdUtc;
            lastError = null;
        }
    }

    public void Failed(string error)
    {
        lock (gate)
        {
            lastError = error;
        }
    }
}

public sealed record BackupFile(string Name, long Bytes, DateTime CreatedUtc);

/// <summary>
/// Backups as files in one folder: make one, read it back, keep the newest few. For super admins and for the
/// server's own job. A backup holds every row, encrypted values as ciphertext and never the master key: it is
/// worthless without that key, and the key alone is worthless without a backup. They must not be kept together.
/// </summary>
public sealed partial class BackupService(BackupArchive archive, BackupOptions options, BackupStatus status, AuditWriter audit, TimeProvider clock)
{
    public const string Extension = ".shbak";

    public IReadOnlyList<BackupFile> List(Caller caller)
    {
        Require(caller);
        return Files();
    }

    /// <summary>
    /// Writes a backup beside the others, reads it back to check its seal, and only then gives it its name: a file
    /// with a backup's name is a whole, verified backup. Then drops the oldest beyond what is kept.
    /// </summary>
    public async Task<BackupFile> CreateAsync(Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        Directory.CreateDirectory(options.Directory);
        var name = $"secrethive-{clock.GetUtcNow().UtcDateTime.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture)}{Extension}";
        var path = Path.Combine(options.Directory, name);
        var partial = path + ".partial";
        try
        {
            BackupFacts written;
            await using (var output = new FileStream(partial, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                written = await archive.WriteAsync(output, options.ServerVersion, cancellationToken);
            }

            BackupFacts read;
            await using (var input = File.OpenRead(partial))
            {
                read = await archive.VerifyAsync(input, cancellationToken);
            }

            if (read.Total != written.Total)
            {
                throw new DomainException("backup.damaged", "The backup that was just written does not read back whole.");
            }

            File.Move(partial, path, overwrite: true);
            status.Verified(read.CreatedUtc);
            foreach (var old in Files().Skip(Math.Max(1, options.Keep)))
            {
                File.Delete(Path.Combine(options.Directory, old.Name));
            }

            await audit.RecordAsync("backup.created", caller, $"{name} rows={read.Total.ToString(CultureInfo.InvariantCulture)}", cancellationToken: cancellationToken);
            return new BackupFile(name, new FileInfo(path).Length, read.CreatedUtc);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            File.Delete(partial);
            status.Failed(e.Message);
            await audit.RecordAsync("backup.failed", caller, e.GetType().Name, AuditSeverity.Security, cancellationToken: CancellationToken.None);
            throw;
        }
    }

    /// <summary>Checks the newest backup on disk, so a server that just started knows how old its last good one is.</summary>
    public async Task<BackupFacts?> VerifyNewestAsync(CancellationToken cancellationToken = default)
    {
        if (Files().FirstOrDefault() is not { } newest)
        {
            return null;
        }

        try
        {
            await using var input = File.OpenRead(Path.Combine(options.Directory, newest.Name));
            var facts = await archive.VerifyAsync(input, cancellationToken);
            status.Verified(facts.CreatedUtc);
            return facts;
        }
        catch (DomainException e)
        {
            status.Failed(e.Message);
            return null;
        }
    }

    /// <summary>A backup to copy somewhere else. Leaving the server is an event of its own.</summary>
    public async Task<Stream> OpenAsync(string name, Caller caller, CancellationToken cancellationToken = default)
    {
        Require(caller);
        if (!NamePattern().IsMatch(name ?? "") || !File.Exists(Path.Combine(options.Directory, name!)))
        {
            throw new DomainException("backup.not_found", "That backup does not exist.");
        }

        await audit.RecordAsync("backup.downloaded", caller, name, AuditSeverity.Notice, cancellationToken: cancellationToken);
        return File.OpenRead(Path.Combine(options.Directory, name!));
    }

    private List<BackupFile> Files() =>
        !Directory.Exists(options.Directory)
            ? []
            : [.. new DirectoryInfo(options.Directory).EnumerateFiles("*" + Extension)
                .Where(file => NamePattern().IsMatch(file.Name))
                .OrderByDescending(file => file.Name, StringComparer.Ordinal)
                .Select(file => new BackupFile(file.Name, file.Length, DateTime.ParseExact(file.Name.AsSpan(11, 15), "yyyyMMdd-HHmmss", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal)))];

    private static void Require(Caller caller)
    {
        if (!(caller.Unrestricted || (caller.Role == UserRole.SuperAdmin && caller.KeyId is null)))
        {
            throw new DomainException("access.denied", "Only a super admin handles backups.");
        }
    }

    // The only names ever opened: what this service itself writes. Nothing from a request reaches the file system otherwise.
    [GeneratedRegex(@"^secrethive-\d{8}-\d{6}\.shbak$", RegexOptions.CultureInvariant)]
    private static partial Regex NamePattern();
}
