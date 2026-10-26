namespace SecretHive.Web;

/// <summary>
/// Where a form or a sign-in may send the browser afterwards: a path on this site, never another site. One rule for
/// every place that redirects to an address it was given.
/// </summary>
public static class ReturnUrls
{
    /// <summary>
    /// A path starting with one slash. Not <c>//host</c> or <c>/\host</c>, which a browser reads as another site, and no
    /// control characters, which a browser drops before reading it (<c>/&#9;/host</c> is <c>//host</c>).
    /// </summary>
    public static bool IsLocal(string? url) =>
        !string.IsNullOrEmpty(url)
        && url[0] == '/'
        && (url.Length == 1 || (url[1] != '/' && url[1] != '\\'))
        && !url.Any(char.IsControl);

    public static string LocalOr(string? url, string fallback) => IsLocal(url) ? url! : fallback;
}
