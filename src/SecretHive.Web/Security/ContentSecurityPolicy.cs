using SecretHive.Application.Ports;

namespace SecretHive.Web.Security;

/// <summary>
/// The Content-Security-Policy on every answer. Scripts, styles, images, fonts and connections come from this server
/// only, nothing may frame a page, and a form may post here or to a sign-in provider. A script that got onto a page
/// anyway could still read a value through the API with the session; this is what keeps it from running at all.
/// </summary>
/// <remarks>
/// The providers are in <c>form-action</c> because a provider button posts here and is answered with a redirect to
/// the provider, and a browser checks that redirect against the form's policy too. They are read again at most every
/// <see cref="Refresh"/>, so a provider added on the providers page works within that time.
/// </remarks>
public sealed class ContentSecurityPolicy(TimeProvider clock)
{
    public static readonly TimeSpan Refresh = TimeSpan.FromSeconds(30);

    // Styles allow inline: the pages set widths and colours in style attributes. Nothing inline runs as a script.
    private const string Fixed =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
        "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";

    private string? header;
    private DateTimeOffset readAt;

    public async Task<string> HeaderAsync(IOidcProviderStore providers, CancellationToken cancellationToken)
    {
        var now = clock.GetUtcNow();
        if (header is { } known && now - readAt < Refresh)
        {
            return known;
        }

        IReadOnlyList<SecretHive.Domain.Entities.OidcProvider> listed;
        try
        {
            listed = await providers.ListAsync(cancellationToken);
        }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            // The database is away: /health still has to say so, and a page still gets a policy. The last one read,
            // or one without providers; it is read again on the next answer.
            return header ?? $"{Fixed}; form-action 'self'";
        }

        var origins = listed
            .Where(provider => provider.Enabled)
            .Select(provider => Uri.TryCreate(provider.Authority, UriKind.Absolute, out var authority) && authority.Scheme is "https" or "http"
                ? authority.GetLeftPart(UriPartial.Authority)
                : null)
            .OfType<string>()
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Order(StringComparer.OrdinalIgnoreCase);

        header = $"{Fixed}; form-action {string.Join(' ', ["'self'", .. origins])}";
        readAt = now;
        return header;
    }
}
