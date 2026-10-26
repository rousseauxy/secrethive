namespace SecretHive.Application.Ports;

/// <summary>Who a valid access token from a trusted issuer speaks for, as far as SecretHive needs to know.</summary>
/// <param name="ProviderKey">The provider whose issuer signed it.</param>
/// <param name="ProviderSlug">That provider's slug, for logs and the audit trail.</param>
/// <param name="Caller">
/// The calling application or subject as the token names it (<c>azp</c>, <c>client_id</c>, <c>appid</c> or <c>sub</c>), for
/// logs only: it grants nothing.
/// </param>
/// <param name="Groups">The values of the provider's groups claim, which are matched against its group links.</param>
public sealed record ExternalTokenIdentity(int ProviderKey, string ProviderSlug, string Caller, IReadOnlyList<string> Groups);

/// <summary>The outcome of checking a token: an identity, or why there is none.</summary>
/// <param name="ProviderSlug">The provider whose issuer the token named, when one matched; null for an issuer nobody trusts.</param>
/// <param name="Reason">Why it was refused, in a few words and never with anything of the token itself.</param>
public sealed record ExternalTokenCheck(ExternalTokenIdentity? Identity, string? ProviderSlug, string Reason)
{
    public static ExternalTokenCheck Accepted(ExternalTokenIdentity identity) => new(identity, identity.ProviderSlug, "");

    public static ExternalTokenCheck Refused(string? providerSlug, string reason) => new(null, providerSlug, reason);
}

/// <summary>
/// Checks an access token signed by an identity provider or CI system that a super admin trusts for the API: signature,
/// issuer, audience, lifetime and required claims. What the token may then do is not this port's business.
/// </summary>
public interface IExternalTokenValidator
{
    Task<ExternalTokenCheck> ValidateAsync(string token, CancellationToken cancellationToken);

    /// <summary>
    /// Whether a credential has the shape of a signed JWT - three base64url parts, the first a JSON object - and so goes to
    /// the issuer check rather than the key lookup. The server's own keys never do: they start with <c>shv_</c>.
    /// </summary>
    static bool LooksLikeJwt(string? credential)
    {
        if (string.IsNullOrEmpty(credential) || credential.Length > 16 * 1024 || !credential.StartsWith("eyJ", StringComparison.Ordinal))
        {
            return false;
        }

        var parts = credential.Split('.');
        return parts.Length == 3
            && parts.All(p => p.Length > 0 && p.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_'));
    }
}
