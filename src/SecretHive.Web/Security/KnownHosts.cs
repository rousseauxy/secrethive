using System.Net;

namespace SecretHive.Web.Security;

/// <summary>
/// The names this server answers for: the names its certificate is for, the public address when a proxy is in
/// front, and localhost. A redirect to HTTPS is only ever made to one of these; the Host header of a plain HTTP
/// request is the client's word, and a redirect to whatever it says would send the next request wherever the
/// client chose.
/// </summary>
public sealed class KnownHosts
{
    private readonly HashSet<string> names = new(StringComparer.OrdinalIgnoreCase) { "localhost" };

    /// <param name="hostNames">The configured host names, as the certificate gets them; empty means the machine's own name.</param>
    /// <param name="publicBaseUrl">The public address behind a proxy, when one is configured.</param>
    /// <param name="machineName">What the certificate is for when no host name is configured.</param>
    public KnownHosts(IEnumerable<string> hostNames, string? publicBaseUrl, string machineName)
    {
        var any = false;
        foreach (var name in hostNames)
        {
            names.Add(name.Trim());
            any = true;
        }

        if (!any)
        {
            names.Add(machineName);
        }

        if (Uri.TryCreate(publicBaseUrl, UriKind.Absolute, out var uri))
        {
            names.Add(uri.Host);
        }
    }

    public bool Covers(string? host) => host is not null && (names.Contains(host) || (IPAddress.TryParse(host, out var address) && names.Contains(address.ToString())));
}
