using SecretHive.Domain.Entities;

namespace SecretHive.Application.Secrets;

/// <summary>
/// Finding a secret without knowing which vault it is in. A search looks at what a Reader may see and at nothing
/// else: names, descriptions and ordinary fields, in the vaults the caller has a role in. It never opens a value
/// or a sensitive field, so it is not a read and leaves no row.
/// </summary>
public sealed partial class SecretService
{
    public const int MinimumSearchLength = 2;

    /// <summary>
    /// The live secrets and certificates that hold every word of the query in their name, their vault's name, their
    /// description or an ordinary field. A vault that may not be used from the caller's address is passed over
    /// quietly: asking where something is must not read as an attempt on every limited vault.
    /// </summary>
    public async Task<IReadOnlyList<SecretSummary>> SearchAsync(string? query, Caller caller, int take = 50, CancellationToken cancellationToken = default)
    {
        var words = (query ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (words.Length == 0 || words.Sum(word => word.Length) < MinimumSearchLength)
        {
            return [];
        }

        var found = new List<SecretEntry>();
        foreach (var vault in await store.ListVaultsAsync(cancellationToken))
        {
            if (await EffectiveRoleAsync(vault, caller, cancellationToken) is null || !await NetworkAllowsAsync(vault, caller, cancellationToken))
            {
                continue;
            }

            found.AddRange((await store.ListEntriesAsync(vault.Id, inBin: false, cancellationToken)).Where(entry => words.All(word => Holds(vault, entry, word))));
        }

        var summaries = await SummariseAsync(found, caller, cancellationToken);

        // A name that starts with what was typed comes before one that merely mentions it.
        return [.. summaries
            .OrderByDescending(summary => summary.Name.StartsWith(words[0], StringComparison.OrdinalIgnoreCase))
            .ThenBy(summary => summary.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(summary => summary.Vault, StringComparer.OrdinalIgnoreCase)
            .Take(Math.Clamp(take, 1, 200))];
    }

    private static bool Holds(Vault vault, SecretEntry entry, string word) =>
        entry.Name.Contains(word, StringComparison.OrdinalIgnoreCase)
        || vault.Name.Contains(word, StringComparison.OrdinalIgnoreCase)
        || (entry.Description?.Contains(word, StringComparison.OrdinalIgnoreCase) ?? false)
        || entry.Fields.Any(field => field.Name.Contains(word, StringComparison.OrdinalIgnoreCase) || field.Value.Contains(word, StringComparison.OrdinalIgnoreCase));
}
