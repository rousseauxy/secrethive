using System.Globalization;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>What a rotation run found and did.</summary>
/// <param name="Moved">Versions whose key now sits under the current master key.</param>
/// <param name="From">The master keys they were under before.</param>
/// <param name="Unreadable">Master key ids that versions are still under and that this server has not been given.</param>
public sealed record RotationResult(int Moved, IReadOnlyList<string> From, IReadOnlyList<string> Unreadable);

/// <summary>
/// Moving to a new master key. Every version of every secret has a key of its own, and only that key is encrypted
/// under the master key: so a rotation rewrites one small record per version and never touches, or even reads, a
/// value. The server is started with the new key and with the old one named as retired; this moves everything
/// across, after which the old key is needed for nothing.
/// </summary>
public sealed class KeyRotation(ISecretStore store, IKeyRing ring, TimeProvider clock)
{
    private const int Batch = 500;

    public async Task<RotationResult> RunAsync(CancellationToken cancellationToken = default)
    {
        var moved = 0;
        var from = new HashSet<string>(StringComparer.Ordinal);
        var unreadable = new HashSet<string>(StringComparer.Ordinal);
        while (true)
        {
            var versions = await store.ListVersionsUnderOtherKeysAsync(ring.CurrentKeyId, unreadable, Batch, cancellationToken);
            if (versions.Count == 0)
            {
                break;
            }

            foreach (var version in versions)
            {
                try
                {
                    var rewrapped = ring.Rewrap(
                        new VersionAddress(version.ValueId, version.Id),
                        new SealedVersion(Blob.UnpackKey(version.DataKeyId, version.DataKey), new Dictionary<string, SealedItem>(StringComparer.Ordinal)));
                    from.Add(version.DataKeyId);
                    version.DataKeyId = rewrapped.Key.MasterKeyId;
                    version.DataKey = Blob.Pack(rewrapped.Key);
                    moved++;
                }
                catch (KeyRingException)
                {
                    // Under a master key this server was not given. Left as it is, and said.
                    unreadable.Add(version.DataKeyId);
                }
            }

            await store.SaveAsync(cancellationToken);
        }

        if (moved > 0)
        {
            store.Add(new AuditEvent
            {
                AtUtc = clock.GetUtcNow().UtcDateTime,
                Code = "keyring.rotated",
                Severity = AuditSeverity.Security,
                Principal = "key-rotation",
                Via = "job",
                Detail = $"from={string.Join(',', from.Order(StringComparer.Ordinal))} to={ring.CurrentKeyId} versions={moved.ToString(CultureInfo.InvariantCulture)}",
            });
            await store.SaveAsync(cancellationToken);
        }

        return new RotationResult(moved, [.. from.Order(StringComparer.Ordinal)], [.. unreadable.Order(StringComparer.Ordinal)]);
    }
}
