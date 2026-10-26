namespace SecretHive.Domain.Entities;

/// <summary>
/// An OpenID Connect provider people sign in with - Authentik, Entra ID, Google, Keycloak - configured by a super admin
/// while the server runs. Any number are enabled side by side.
/// </summary>
public sealed class OidcProvider
{
    public int Key { get; set; }

    /// <summary>Lower-case, unique, in the callback path <c>/signin-oidc/{slug}</c>; changing it changes the redirect URI.</summary>
    public required string Slug { get; set; }

    /// <summary>What the sign-in button says: "Sign in with {DisplayName}".</summary>
    public required string DisplayName { get; set; }

    /// <summary>The issuer, whose <c>/.well-known/openid-configuration</c> describes the rest.</summary>
    public required string Authority { get; set; }

    public required string ClientId { get; set; }

    /// <summary>The client secret, encrypted with the instance's data-protection keys. Never shown again after saving.</summary>
    public string ProtectedClientSecret { get; set; } = "";

    /// <summary>Space-separated; <c>openid</c> is always asked for.</summary>
    public string Scopes { get; set; } = DefaultScopes;

    /// <summary>The claim a new account's user name is taken from.</summary>
    public string UserNameClaim { get; set; } = DefaultUserNameClaim;

    /// <summary>The claim listing the person's groups at the provider. Empty: group mapping is off for this provider.</summary>
    public string GroupsClaim { get; set; } = "";

    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Whether the first sign-in of an identity no account has makes an account. Off: an admin makes the account, and its
    /// owner connects the provider from the profile page. With a provider anyone can register at - Google, a multi-tenant
    /// Entra registration - on means anyone gets an account.
    /// </summary>
    public bool CreateAccounts { get; set; } = true;

    /// <summary>
    /// Email domains a new identity must have an address in, one per line; empty allows any. Checked before an account is
    /// made, never for an identity already connected to one. An address the provider marks unverified counts as none.
    /// </summary>
    public string AllowedEmailDomains { get; set; } = "";

    /// <summary>The domains of an allowed-domains text, lower case, without a leading @.</summary>
    public static IReadOnlyList<string> ParseEmailDomains(string? text) =>
        [.. (text ?? "").Split(['\n', '\r', ' ', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(d => d.TrimStart('@').ToLowerInvariant())
            .Where(d => d.Length > 0)
            .Distinct(StringComparer.Ordinal)];

    /// <summary>Whether an identity with this address may get an account: always without domains, else only a verified address in one of them.</summary>
    public bool AllowsEmail(string? email, bool? emailVerified)
    {
        var domains = ParseEmailDomains(AllowedEmailDomains);
        if (domains.Count == 0)
        {
            return true;
        }

        var at = email?.LastIndexOf('@') ?? -1;
        return emailVerified != false
            && at > 0
            && domains.Contains(email![(at + 1)..].Trim().ToLowerInvariant());
    }

    /// <summary>
    /// Whether the API accepts access tokens this issuer signs, next to the server's own keys: a pipeline or an application
    /// fetches a short-lived token instead of storing a key. Independent of <see cref="Enabled"/>, which is about people
    /// signing in, so an issuer nobody signs in with - a CI system's job tokens - is a provider with only this on.
    /// </summary>
    public bool AcceptApiTokens { get; set; }

    /// <summary>
    /// The audiences a token must be for, one per line; at least one when <see cref="AcceptApiTokens"/> is on. Without it
    /// any token the issuer signs for any application would do, which with a shared issuer means anyone's.
    /// </summary>
    public string ApiAudiences { get; set; } = "";

    /// <summary>
    /// Claims a token must carry, one <c>name=value</c> per line: every name listed must be present with one of the
    /// values listed for it. For a CI issuer that serves many projects, such as <c>ref=refs/heads/main</c>. A value
    /// that ends in <c>*</c> stands for every value that starts with what comes before it: <c>ref=refs/tags/docker-*</c>.
    /// </summary>
    public string ApiRequiredClaims { get; set; } = "";

    /// <summary>Whether a claim's value satisfies one required value: the same, or starting with it when it ends in a star.</summary>
    public static bool ClaimValueMatches(string required, string actual) =>
        required.EndsWith('*')
            ? actual.StartsWith(required[..^1], StringComparison.OrdinalIgnoreCase)
            : string.Equals(required, actual, StringComparison.OrdinalIgnoreCase);

    /// <summary>The audiences of an audiences text, trimmed and without duplicates.</summary>
    public static IReadOnlyList<string> ParseAudiences(string? text) =>
        [.. (text ?? "").Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.Ordinal)];

    /// <summary>
    /// The rules of a required-claims text: each claim name with the values that satisfy it. Null when a line is not
    /// <c>name=value</c>, so a typo is refused on the page rather than silently requiring nothing.
    /// </summary>
    public static IReadOnlyDictionary<string, IReadOnlyList<string>>? ParseRequiredClaims(string? text)
    {
        var rules = new Dictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var line in (text ?? "").Split(['\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var equals = line.IndexOf('=', StringComparison.Ordinal);
            if (equals <= 0 || equals == line.Length - 1)
            {
                return null;
            }

            var name = line[..equals].Trim();
            var value = line[(equals + 1)..].Trim();
            if (name.Length == 0 || value.Length == 0)
            {
                return null;
            }

            // A star only at the end, and never on its own: "*" would require nothing but the claim's presence, and a
            // star in the middle would read as a pattern it is not.
            if (value.IndexOf('*', StringComparison.Ordinal) is var star && star >= 0 && (star != value.Length - 1 || value.Length == 1))
            {
                return null;
            }

            if (!rules.TryGetValue(name, out var values))
            {
                rules[name] = values = [];
            }

            if (!values.Contains(value, StringComparer.OrdinalIgnoreCase))
            {
                values.Add(value);
            }
        }

        return rules.ToDictionary(r => r.Key, r => (IReadOnlyList<string>)r.Value, StringComparer.Ordinal);
    }

    /// <summary>Order of the buttons on the sign-in page.</summary>
    public int Ordinal { get; set; }

    public DateTime CreatedUtc { get; set; }

    /// <summary>
    /// Moved on every save. Each replica compares it with the options it built for this provider, so a change made on one
    /// applies on all of them at their next sign-in, with no restart.
    /// </summary>
    public DateTime UpdatedUtc { get; set; }

    public const string DefaultScopes = "openid profile email";

    public const string DefaultUserNameClaim = "preferred_username";
}

/// <summary>One provider identity joined to an account: signing in with it signs in as that account.</summary>
public sealed class ExternalLogin
{
    public int Key { get; set; }

    public int UserKey { get; set; }

    public int ProviderKey { get; set; }

    /// <summary>The provider's <c>sub</c>: stable and unique per provider, unlike a name or an email address.</summary>
    public required string Subject { get; set; }

    /// <summary>The email address as the provider gave it at the last sign-in, for recognising the link in lists.</summary>
    public string Email { get; set; } = "";

    public DateTime LinkedUtc { get; set; }

    public DateTime? LastUsedUtc { get; set; }
}

/// <summary>A group here whose members include everyone in a group at a provider, refreshed at each sign-in there.</summary>
public sealed class GroupProviderLink
{
    public int Key { get; set; }

    public int GroupKey { get; set; }

    public int ProviderKey { get; set; }

    /// <summary>The group's name as the provider sends it in its groups claim.</summary>
    public required string ProviderGroup { get; set; }
}
