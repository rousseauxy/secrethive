using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Accounts;

/// <summary>
/// Writes audit rows for what is not about a secret: sign-ins and refusals, accounts, groups, roles, keys and
/// sign-in providers. The same table as the reads, so one trail answers "what happened".
/// </summary>
public sealed class AuditWriter(ISecretStore store, TimeProvider clock)
{
    public async Task RecordAsync(string code, Caller caller, string? detail = null, AuditSeverity severity = AuditSeverity.Info, string? vault = null, CancellationToken cancellationToken = default)
    {
        store.Add(new AuditEvent
        {
            AtUtc = clock.GetUtcNow().UtcDateTime,
            Code = code,
            Severity = severity,
            Principal = caller.Principal,
            Vault = vault,
            Address = caller.Address,
            Via = caller.Via,
            Detail = detail is { Length: > 2000 } ? detail[..2000] : detail,
        });
        await store.SaveAsync(cancellationToken);
    }
}
