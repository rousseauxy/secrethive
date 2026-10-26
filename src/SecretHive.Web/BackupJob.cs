using SecretHive.Application.Secrets;
using SecretHive.Infrastructure.Backup;

namespace SecretHive.Web;

/// <summary>
/// Makes a backup when the newest verified one is older than the interval, and checks at start what is already on
/// disk. A failed run is on record as <c>backup.failed</c> and tried again an hour later; meanwhile the health
/// endpoint keeps showing the age of the last good one, which is what a monitor alerts on.
/// </summary>
public sealed class BackupJob(IServiceScopeFactory scopes, BackupOptions options, BackupStatus status, TimeProvider clock, ILogger<BackupJob> logger) : BackgroundService
{
    private static readonly TimeSpan Settle = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!options.Enabled)
        {
            return;
        }

        try
        {
            await using (var scope = scopes.CreateAsyncScope())
            {
                await scope.ServiceProvider.GetRequiredService<BackupService>().VerifyNewestAsync(stoppingToken);
            }

            // Not in the first moments of a start: a server that is restarting in a loop should not fill a disk.
            await Task.Delay(Settle, clock, stoppingToken);
            using var timer = new PeriodicTimer(Interval, clock);
            do
            {
                if (status.LastVerifiedUtc is { } last && clock.GetUtcNow().UtcDateTime - last < TimeSpan.FromHours(options.IntervalHours))
                {
                    continue;
                }

                try
                {
                    await using var scope = scopes.CreateAsyncScope();
                    var made = await scope.ServiceProvider.GetRequiredService<BackupService>().CreateAsync(Caller.System("backup-job"), stoppingToken);
                    logger.LogInformation("Backup {Name} written and verified ({Bytes} bytes).", made.Name, made.Bytes);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    logger.LogError(e, "The backup run failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
