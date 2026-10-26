using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Web;

/// <summary>
/// Looks once an hour for what is about to stop working and says so in the audit trail: certificates, keys, and a
/// backup that is overdue. See <see cref="ExpiryWatch"/> for what counts and how often each is said.
/// </summary>
public sealed class ExpiryJob(IServiceScopeFactory scopes, TimeProvider clock, ILogger<ExpiryJob> logger) : BackgroundService
{
    private static readonly TimeSpan Settle = TimeSpan.FromMinutes(3);
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(Settle, clock, stoppingToken);
            using var timer = new PeriodicTimer(Interval, clock);
            do
            {
                try
                {
                    await using var scope = scopes.CreateAsyncScope();
                    await scope.ServiceProvider.GetRequiredService<ExpiryWatch>().LookAsync(stoppingToken);
                }
                catch (Exception e) when (e is not OperationCanceledException)
                {
                    logger.LogError(e, "The expiry look failed.");
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
        }
    }
}
