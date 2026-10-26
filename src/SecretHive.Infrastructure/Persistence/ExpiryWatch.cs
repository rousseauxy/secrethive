using System.Globalization;
using Microsoft.EntityFrameworkCore;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Backup;

namespace SecretHive.Infrastructure.Persistence;

/// <summary>
/// Says, in the audit trail, what is about to stop working: a certificate nearing its end, a key nearing its
/// expiry, a backup that has not been made. Each is said once per step (30, 14 and 3 days for a certificate, a week
/// for a key), by comparing where things stand now with where they stood at the last look; the first look reports
/// everything already inside a step. Nothing here reads a value.
/// </summary>
public sealed class ExpiryWatch(SecretHiveDbContext db, BackupStatus backups, BackupOptions backupOptions, TimeProvider clock)
{
    private const string LastLook = "expiry.lastLookUtc";
    private const string StaleSaid = "expiry.backupStaleSaidUtc";
    private const string Principal = "expiry-watch";
    private static readonly int[] CertificateSteps = [30, 14, 3];
    private const int KeyStep = 7;

    /// <summary>How many events were written.</summary>
    public async Task<int> LookAsync(CancellationToken cancellationToken = default)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var last = await ReadAsync(LastLook, cancellationToken);
        var written = 0;

        // The certificate each live name currently points at. A name in a bin, or an earlier version, renews nothing.
        var certificates = await (
            from entry in db.Entries.AsNoTracking()
            where entry.BinKey == ""
            join value in db.Values.AsNoTracking() on entry.ValueId equals value.Id
            join certificate in db.Certificates.AsNoTracking() on value.CurrentVersionId equals certificate.VersionId
            join vault in db.Vaults.AsNoTracking() on entry.VaultId equals vault.Id
            select new { Vault = vault.Name, VaultId = vault.Id, entry.Name, EntryId = entry.Id, certificate.NotAfterUtc, certificate.VersionId }).ToListAsync(cancellationToken);
        foreach (var certificate in certificates)
        {
            var step = Step(certificate.NotAfterUtc, now);
            if (step is null || (last is { } before && Step(certificate.NotAfterUtc, before) == step))
            {
                continue;
            }

            var until = certificate.NotAfterUtc.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            db.Audit.Add(new AuditEvent
            {
                AtUtc = now,
                Code = step == 0 ? "certificate.expired" : "certificate.expiring",
                Severity = step <= 3 ? AuditSeverity.Security : step <= 14 ? AuditSeverity.Notice : AuditSeverity.Info,
                Principal = Principal,
                Vault = certificate.Vault,
                VaultId = certificate.VaultId,
                Secret = certificate.Name,
                EntryId = certificate.EntryId,
                VersionId = certificate.VersionId,
                Via = "job",
                Detail = step == 0 ? $"notAfter={until}" : $"days={Math.Max(0, (int)Math.Round((certificate.NotAfterUtc - now).TotalDays, MidpointRounding.AwayFromZero)).ToString(CultureInfo.InvariantCulture)} notAfter={until}",
            });
            written++;
        }

        var soon = now.AddDays(KeyStep);
        var keys = await (
            from key in db.ApiKeys.AsNoTracking()
            where key.RevokedUtc == null && key.ExpiresUtc > now && key.ExpiresUtc <= soon
            join owner in db.Users.AsNoTracking() on key.UserKey equals owner.Key
            select new { key.Prefix, key.Label, key.ExpiresUtc, Owner = owner.UserName }).ToListAsync(cancellationToken);
        foreach (var key in keys.Where(key => last is not { } before || key.ExpiresUtc > before.AddDays(KeyStep)))
        {
            db.Audit.Add(new AuditEvent
            {
                AtUtc = now,
                Code = "key.expiring",
                Severity = AuditSeverity.Notice,
                Principal = Principal,
                Via = "job",
                Detail = $"shv_{key.Prefix} of {key.Owner} ({key.Label}) expires={key.ExpiresUtc!.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture)}",
            });
            written++;
        }

        // A backup twice as old as it should be, or none at all once the server has had a day to make one. Said once a day.
        var limit = TimeSpan.FromHours(Math.Max(1, backupOptions.IntervalHours) * 2);
        var stale = backupOptions.Enabled && (backups.LastVerifiedUtc is { } verified ? now - verified > limit : last is { } first && now - first > limit);
        if (stale && (await ReadAsync(StaleSaid, cancellationToken) is not { } said || now - said > TimeSpan.FromHours(23)))
        {
            db.Audit.Add(new AuditEvent
            {
                AtUtc = now,
                Code = "backup.verified.stale",
                Severity = AuditSeverity.Security,
                Principal = Principal,
                Via = "job",
                Detail = backups.LastVerifiedUtc is { } at ? $"last={at.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture)}" : "last=never",
            });
            await WriteAsync(StaleSaid, now, cancellationToken);
            written++;
        }

        await WriteAsync(LastLook, now, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        return written;
    }

    /// <summary>The tightest step a certificate is inside: 0 once past its end, null while further away than every step.</summary>
    private static int? Step(DateTime notAfterUtc, DateTime at)
    {
        if (notAfterUtc <= at)
        {
            return 0;
        }

        var left = (notAfterUtc - at).TotalDays;
        int? step = null;
        foreach (var candidate in CertificateSteps)
        {
            if (left <= candidate)
            {
                step = candidate;
            }
        }

        return step;
    }

    private async Task<DateTime?> ReadAsync(string key, CancellationToken cancellationToken) =>
        await db.Settings.AsNoTracking().FirstOrDefaultAsync(setting => setting.Key == key, cancellationToken) is { } setting
        && DateTime.TryParse(setting.Value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var value)
            ? value
            : null;

    private async Task WriteAsync(string key, DateTime value, CancellationToken cancellationToken)
    {
        var text = value.ToString("O", CultureInfo.InvariantCulture);
        if (await db.Settings.FirstOrDefaultAsync(setting => setting.Key == key, cancellationToken) is { } existing)
        {
            existing.Value = text;
        }
        else
        {
            db.Settings.Add(new AppSetting { Key = key, Value = text });
        }
    }
}
