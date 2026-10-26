using System.Text.RegularExpressions;

namespace SecretHive.Cli;

/// <summary>
/// Where a value comes from: <c>name</c>, <c>vault/name</c> or <c>vault/name/version</c>, optionally followed by
/// <c>#part</c> for one field of a secret or one part of a certificate.
/// </summary>
internal sealed partial record SecretReference(string Vault, string Name, string? Version, string? Part)
{
    /// <summary>The key of this reference in a bundle: everything but the version.</summary>
    public string BundleKey => Part is null ? $"{Vault}/{Name}" : $"{Vault}/{Name}#{Part}";

    public override string ToString() => Version is null ? BundleKey : $"{Vault}/{Name}/{Version}" + (Part is null ? "" : $"#{Part}");

    public static SecretReference Parse(string text, string? defaultVault)
    {
        var match = Shape().Match(text);
        if (!match.Success)
        {
            // The text is not repeated: the commonest way to get here is a value pasted where a reference belongs.
            throw new InputException("is not a reference (name, vault/name or vault/name/version, optionally #part)");
        }

        var segments = match.Groups["path"].Value.Split('/');
        var part = match.Groups["part"].Success ? match.Groups["part"].Value : null;
        return segments.Length switch
        {
            1 when defaultVault is null => throw new InputException("names no vault, and there is no default vault"),
            1 => new SecretReference(defaultVault!, segments[0], null, part),
            2 => new SecretReference(segments[0], segments[1], null, part),
            _ => new SecretReference(segments[0], segments[1], segments[2], part),
        };
    }

    // Vault, name and version share the server's rule for names. Because a value can never match this
    // shape by accident (no '=', ';', ':' or spaces), a value pasted into a manifest is refused as a reference.
    [GeneratedRegex(@"^(?<path>[0-9a-zA-Z-]{1,127}(/[0-9a-zA-Z-]{1,127}){0,2})(#(?<part>[0-9a-zA-Z-]{1,63}))?$", RegexOptions.CultureInvariant)]
    private static partial Regex Shape();
}
