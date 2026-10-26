using SecretHive.Application.Secrets;

namespace SecretHive.Web;

/// <summary>
/// Empties bins once the retention period an administrator switched on has passed. It does nothing while retention
/// is off, which is the default. One instance, one timer: when the server runs as several replicas this belongs on
/// the job queue under a leader lock, like the rest of the background work.
/// </summary>
public sealed class RetentionJob(IServiceScopeFactory scopes, ILogger<RetentionJob> logger) : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        do
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var purged = await scope.ServiceProvider.GetRequiredService<SecretService>().PurgeExpiredAsync(stoppingToken);
                if (purged > 0)
                {
                    logger.LogInformation("Retention purged {Count} secrets from the bins.", purged);
                }
            }
            catch (Exception e) when (e is not OperationCanceledException)
            {
                // The next run tries again; a failed purge leaves everything where it was.
                logger.LogError(e, "The retention run failed.");
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
