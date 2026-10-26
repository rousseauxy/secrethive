namespace SecretHive.Cli.Hosting;

/// <summary>What is true of a whole host. Lives at the root of that host's compose repository.</summary>
internal sealed record HostProfile(
    string Host,
    string AppData,
    string BundleKeyPath,
    string BundleRecipientPath,
    IReadOnlyList<string> Docker,
    IReadOnlyList<string> Providers,
    Uri? Server = null,
    string? ServerKeyPath = null,
    string? ServerCertificatePath = null)
{
    /// <summary>Whether values are read from the server when it answers.</summary>
    public bool UsesServer => Providers.Contains("api");

    /// <summary>Whether the sealed bundle next to the manifest is read: alone, or when the server does not answer.</summary>
    public bool UsesBundle => Providers.Contains("bundle");

    public const string FileName = "secrethive.host.yml";

    public static HostProfile Load(string repositoryRoot, string expectedHost)
    {
        var path = Path.Combine(repositoryRoot, FileName);
        if (!File.Exists(path))
        {
            throw new InputException($"{path}: no host profile here. Run from the root of the compose repository or pass --repo.");
        }

        var map = YamlMap.Load(path);
        if (map.Text("version") != "1")
        {
            throw new InputException($"{FileName}: only version 1 is understood");
        }

        var host = map.Text("host");
        var appData = map.Text("appdata");
        var bundleKey = map.Text("bundle_key");
        var recipient = map.OptionalText("bundle_recipient") ?? "secrethive.host.pub";
        var docker = map.OptionalText("docker") ?? "docker";
        var providers = map.TextList("providers");
        var server = map.OptionalText("server");
        var serverKey = map.OptionalText("server_key");
        var serverCertificate = map.OptionalText("server_certificate");
        map.EnsureNothingElse();

        // The guard against rendering one host's manifest with another host in mind.
        if (!string.Equals(host, expectedHost, StringComparison.Ordinal))
        {
            throw new InputException($"this checkout is host '{host}', not '{expectedHost}'. Nothing was done.");
        }

        if (!Path.IsPathFullyQualified(appData) || !Path.IsPathFullyQualified(bundleKey))
        {
            throw new InputException($"{FileName}: 'appdata' and 'bundle_key' must be absolute paths");
        }

        // The order is fixed and says what happens: the server when it answers, the bundle when it does not.
        if (providers.Count == 0 || providers.Distinct(StringComparer.Ordinal).Count() != providers.Count || providers.Any(provider => provider is not ("api" or "bundle")) || (providers.Count == 2 && providers[0] != "api"))
        {
            throw new InputException($"{FileName}: 'providers' is [bundle], [api, bundle] or [api]");
        }

        if (providers.Contains("api") && (server is null || serverKey is null))
        {
            throw new InputException($"{FileName}: with 'api' in 'providers', 'server' (its https address) and 'server_key' (the file holding this host's key) are needed");
        }

        // Without 'api' the server may still be named: nothing reads from it, and 'bundle push' knows where to write.
        if (server is null && (serverKey is not null || serverCertificate is not null))
        {
            throw new InputException($"{FileName}: 'server_key' and 'server_certificate' mean something only next to 'server'");
        }

        Uri? address = null;
        if (server is not null)
        {
            // Plain http only to this machine: a key sent in the clear to anything else is a key given away.
            if (!Uri.TryCreate(server.TrimEnd('/') + "/", UriKind.Absolute, out address) || !(address.Scheme == Uri.UriSchemeHttps || (address.Scheme == Uri.UriSchemeHttp && address.IsLoopback)))
            {
                throw new InputException($"{FileName}: 'server' must be an https address");
            }

            if (serverKey is not null && !Path.IsPathFullyQualified(serverKey))
            {
                throw new InputException($"{FileName}: 'server_key' must be an absolute path, outside the repository");
            }
        }

        return new HostProfile(
            host,
            Path.TrimEndingDirectorySeparator(appData),
            bundleKey,
            Path.GetFullPath(recipient, repositoryRoot),
            docker.Split(' ', StringSplitOptions.RemoveEmptyEntries),
            providers,
            address,
            serverKey,
            serverCertificate is null ? null : Path.GetFullPath(serverCertificate, repositoryRoot));
    }
}
