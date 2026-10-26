using System.Net;

namespace SecretHive.Domain;

/// <summary>
/// Address ranges: what a network group is made of, and what a vault or a key can be limited to. A range is written
/// the usual way, <c>192.168.10.0/24</c> or <c>fd7a::/48</c>; one address alone is a range of one.
/// </summary>
public static class Networks
{
    /// <summary>
    /// A range in its canonical form, or a <see cref="DomainException"/> saying what is wrong with it. A range
    /// with bits set after the prefix (<c>10.0.0.5/8</c>) is refused: it reads as one host and matches sixteen million.
    /// </summary>
    public static string Normalize(string? text)
    {
        var trimmed = (text ?? "").Trim();
        if (trimmed.Length == 0)
        {
            throw new DomainException("network.range.invalid", "Enter a range such as 192.168.10.0/24, or one address.");
        }

        if (!trimmed.Contains('/', StringComparison.Ordinal) && IPAddress.TryParse(trimmed, out var single))
        {
            single = Plain(single);
            return $"{single}/{(single.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 32 : 128)}";
        }

        // The runtime accepts 10.0.0.5/8 and quietly reads it as 10.0.0.0/8; said out loud here instead.
        if (!IPNetwork.TryParse(trimmed, out var network)
            || !IPAddress.TryParse(trimmed[..trimmed.IndexOf('/', StringComparison.Ordinal)], out var written)
            || !Plain(written).Equals(Plain(network.BaseAddress)))
        {
            throw new DomainException("network.range.invalid", $"'{trimmed}' is not a range. Write it as 192.168.10.0/24, with no bits set after the prefix.");
        }

        if (network.PrefixLength == 0)
        {
            throw new DomainException("network.range.invalid", "A range that covers every address limits nothing. Leave the list empty instead.");
        }

        return network.ToString();
    }

    /// <summary>The ranges of a text with one per line (or separated by spaces or commas), canonical, each once.</summary>
    public static IReadOnlyList<string> NormalizeAll(string? text) =>
        [.. (text ?? "").Split(['\n', '\r', ' ', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(Normalize).Distinct(StringComparer.Ordinal)];

    /// <summary>Whether an address is inside any of the ranges. An address that cannot be read is inside none.</summary>
    public static bool Contains(IEnumerable<string> ranges, string? address)
    {
        ArgumentNullException.ThrowIfNull(ranges);
        if (!IPAddress.TryParse(address, out var parsed))
        {
            return false;
        }

        parsed = Plain(parsed);
        foreach (var range in ranges)
        {
            if (IPNetwork.TryParse(range, out var network) && network.Contains(parsed))
            {
                return true;
            }
        }

        return false;
    }

    private static IPAddress Plain(IPAddress address) => address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
}
