using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SecretHive.Api;

public sealed class BootstrapAdminOptions : AuthenticationSchemeOptions
{
    /// <summary>SHA-256 of the token. The token itself is read from its file once and not kept.</summary>
#pragma warning disable CA1819 // a hash handed over once at start
    public byte[] TokenHash { get; set; } = [];
#pragma warning restore CA1819
}

/// <summary>
/// The bootstrap token as a bearer token for tools: all-powerful, and held in a file on the host. People sign in
/// with accounts; keys owned by an identity replace this for tools.
/// </summary>
public sealed class BootstrapAdminHandler(IOptionsMonitor<BootstrapAdminOptions> options, ILoggerFactory logger, UrlEncoder encoder)
    : AuthenticationHandler<BootstrapAdminOptions>(options, logger, encoder)
{
    public const string SchemeName = "BootstrapAdmin";
    public const string Principal = "bootstrap-token";
    public const int MinimumTokenLength = 32;

    /// <summary>Reads the token file. Refuses a missing, short or padded one: there is no mode without a sign-in.</summary>
    public static byte[] HashTokenFile(string path)
    {
        string token;
        try
        {
            token = File.ReadAllText(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new InvalidOperationException($"The bootstrap admin token file {path} cannot be read ({e.GetType().Name}).", e);
        }

        if (token.Length < MinimumTokenLength || token.Any(char.IsWhiteSpace))
        {
            throw new InvalidOperationException($"The bootstrap admin token in {path} must be at least {MinimumTokenLength} characters with no whitespace, not even a final newline.");
        }

        return SHA256.HashData(Encoding.UTF8.GetBytes(token));
    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        // A key that belongs to an identity is the other handler's business.
        if (!header.StartsWith("Bearer ", StringComparison.Ordinal)
            || SecretHive.Application.Accounts.KeyService.LooksLikeKey(header["Bearer ".Length..])
            || SecretHive.Application.Ports.IExternalTokenValidator.LooksLikeJwt(header["Bearer ".Length..].Trim()))
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // A server started without a token has an empty hash, and nothing presented is ever that token.
        var presented = SHA256.HashData(Encoding.UTF8.GetBytes(header["Bearer ".Length..]));
        if (Options.TokenHash.Length == 0 || !CryptographicOperations.FixedTimeEquals(presented, Options.TokenHash))
        {
            return Task.FromResult(AuthenticateResult.Fail("The token is not the bootstrap admin token."));
        }

        var identity = new ClaimsIdentity([new Claim(ClaimTypes.Name, Principal), new Claim(ClaimTypes.Role, "admin"), new Claim(ClaimTypes.Role, "superadmin")], SchemeName);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName)));
    }
}
