using System.Runtime.CompilerServices;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Logging;
using SecretHive.Domain.Entities;

namespace SecretHive.Infrastructure.Persistence;

/// <summary>
/// Every audit row is also a log line, written once the row is safely in the database. The database is where the
/// trail lives; the log is how it leaves the host: a collector that ships the container's log gets every event as
/// structured fields, and an alert rule can match on the code and the severity. Like the rows, a line names things
/// and never holds a value.
/// </summary>
public sealed partial class AuditLogInterceptor(ILoggerFactory loggers, TimeProvider clock) : SaveChangesInterceptor
{
    private readonly ILogger logger = loggers.CreateLogger(Category);

    /// <summary>The log category every audit line is written under.</summary>
    public const string Category = "SecretHive.Audit";

    // An event from long ago being written now is history being moved (a restore), not news.
    private static readonly TimeSpan News = TimeSpan.FromMinutes(5);

    private readonly ConditionalWeakTable<DbContext, List<AuditEvent>> pending = [];

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
    {
        Collect(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    public override InterceptionResult<int> SavingChanges(DbContextEventData eventData, InterceptionResult<int> result)
    {
        Collect(eventData.Context);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
    {
        Write(eventData.Context);
        return base.SavedChangesAsync(eventData, result, cancellationToken);
    }

    public override int SavedChanges(SaveChangesCompletedEventData eventData, int result)
    {
        Write(eventData.Context);
        return base.SavedChanges(eventData, result);
    }

    public override Task SaveChangesFailedAsync(DbContextErrorEventData eventData, CancellationToken cancellationToken = default)
    {
        Forget(eventData.Context);
        return base.SaveChangesFailedAsync(eventData, cancellationToken);
    }

    public override void SaveChangesFailed(DbContextErrorEventData eventData)
    {
        Forget(eventData.Context);
        base.SaveChangesFailed(eventData);
    }

    private void Collect(DbContext? context)
    {
        if (context is null)
        {
            return;
        }

        var added = context.ChangeTracker.Entries<AuditEvent>().Where(entry => entry.State == EntityState.Added).Select(entry => entry.Entity).ToList();
        if (added.Count > 0)
        {
            pending.AddOrUpdate(context, added);
        }
    }

    private void Forget(DbContext? context)
    {
        if (context is not null)
        {
            pending.Remove(context);
        }
    }

    private void Write(DbContext? context)
    {
        if (context is null || !pending.TryGetValue(context, out var rows))
        {
            return;
        }

        pending.Remove(context);
        var now = clock.GetUtcNow().UtcDateTime;
        foreach (var row in rows.Where(row => now - row.AtUtc < News))
        {
            var level = row.Severity == AuditSeverity.Security ? LogLevel.Warning : LogLevel.Information;
            Audit(logger, level, row.Code, row.Severity.ToString().ToLowerInvariant(), row.Principal, row.Vault, row.Secret, row.Slot, row.Address, row.Via, row.Detail, row.Id);
        }
    }

    [LoggerMessage(EventId = 1000, EventName = "audit", Message = "audit {Code} {Severity} by {Principal} vault={Vault} secret={Secret} slot={Slot} from={Address} via={Via} detail={Detail} id={AuditId}")]
    private static partial void Audit(ILogger logger, LogLevel level, string code, string severity, string principal, string? vault, string? secret, string? slot, string? address, string? via, string? detail, long auditId);
}
