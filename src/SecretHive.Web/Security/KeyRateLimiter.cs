using System.Collections.Concurrent;

namespace SecretHive.Web.Security;

/// <summary>
/// How many requests one credential may make in a minute. A key is for a job, and a job has a pace: far beyond it
/// is a loop gone wrong or somebody reading everything the key can reach. The bootstrap token and a job's token
/// from its platform are held to the same pace, each on its own count. Counted in memory, in whole minutes; a
/// restart forgets the count, which costs nothing.
/// </summary>
public sealed class KeyRateLimiter(int perMinute, TimeProvider clock)
{
    private readonly ConcurrentDictionary<string, (long Minute, int Count)> counts = new(StringComparer.Ordinal);

    /// <summary>Zero switches the limit off.</summary>
    public int PerMinute { get; } = Math.Max(0, perMinute);

    /// <summary>
    /// Counts a request. <paramref name="first"/> is true for the first refusal of a minute, so the refusal is put
    /// on record once and not for every request of a runaway loop.
    /// </summary>
    public bool Allow(string subject, out bool first, out int retryAfterSeconds)
    {
        first = false;
        retryAfterSeconds = 0;
        if (PerMinute == 0)
        {
            return true;
        }

        var now = clock.GetUtcNow();
        var minute = now.ToUnixTimeSeconds() / 60;
        var (_, count) = counts.AddOrUpdate(subject, _ => (minute, 1), (_, held) => held.Minute == minute ? (minute, held.Count + 1) : (minute, 1));
        if (count <= PerMinute)
        {
            return true;
        }

        first = count == PerMinute + 1;
        retryAfterSeconds = 60 - (int)(now.ToUnixTimeSeconds() % 60);
        return false;
    }
}
