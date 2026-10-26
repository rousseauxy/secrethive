using System.Security.Cryptography;
using System.Text;
using SecretHive.Cli;
using SecretHive.Cli.Commands;

namespace SecretHive.Unit.Tests;

/// <summary>
/// A compose checkout on disk (profile, manifest, bundle, host key) next to an in-memory host, and the command
/// line run against both. Every value used is generated here; no test holds a real one.
/// </summary>
internal sealed class Stack : IDisposable
{
    // One key pair for the whole run: generating RSA keys is the slow part and says nothing about the code under test.
    private static readonly Lazy<(string Private, string Public)> Keys = new(() =>
    {
        using var rsa = RSA.Create(3072);
        return (rsa.ExportPkcs8PrivateKeyPem(), rsa.ExportSubjectPublicKeyInfoPem());
    });

    private readonly Queue<string> _input = new();

    public Stack(string manifest, string host = "web-1")
    {
        Root = Directory.CreateTempSubdirectory("secrethive-test-").FullName;
        Repository = Path.Combine(Root, "compose");
        AppData = Path.Combine(Root, "appdata");
        Directory.CreateDirectory(Path.Combine(Repository, "shop"));
        File.WriteAllText(Path.Combine(Root, "host.key"), Keys.Value.Private);
        File.WriteAllText(Path.Combine(Repository, "secrethive.host.pub"), Keys.Value.Public);
        File.WriteAllText(Path.Combine(Repository, "secrethive.host.yml"), $"""
            version: 1
            host: {host}
            appdata: '{AppData}'
            bundle_key: '{Path.Combine(Root, "host.key")}'
            providers: [bundle]
            """);
        File.WriteAllText(Path.Combine(Repository, "shop", "secrethive.yml"), manifest);
        Files.SeedDirectory(AppData);
        Files.SeedDirectory(Path.Combine(AppData, "shop"), uid: 99, gid: 100, mode: 0x1FF);
    }

    public string Root { get; }

    public string Repository { get; }

    public string AppData { get; }

    public FakeHostFiles Files { get; } = new();

    public FakeContainers Containers { get; } = new();

    public string? HostAccessProblem { get; set; }

    /// <summary>The server the command line reaches, for the tests that give the host one: its address and key file.</summary>
    internal Func<Uri, string, SecretHive.Cli.Server.ISecretServer>? Server { get; set; }

    public StringBuilder Output { get; } = new();

    public string Target(string name = "secrets") => Path.Combine(AppData, "shop", name);

    public string BundlePath => Path.Combine(Repository, "shop", "secrethive.bundle");

    /// <summary>Seals a value the way an operator would: piped to <c>bundle set</c>.</summary>
    public void Set(string reference, string value)
    {
        _input.Enqueue(value);
        Assert.Equal(App.Ok, Run("bundle", "set", "shop", reference, "--host", "web-1"));
    }

    public void Pipe(string value) => _input.Enqueue(value);

    public int Run(params string[] args)
    {
        using var output = new StringWriter(Output);
        var services = new AppServices(
            output,
            output,
            Files,
            _ => Containers,
            () => new SecretValue(Encoding.UTF8.GetBytes(_input.Dequeue())),
            Repository,
            HostAccessProblem,
            TimeProvider.System,
            profile => Server?.Invoke(profile.Server!, profile.ServerKeyPath!) ?? throw new InvalidOperationException("this test has no server"));
        return new App(services).Run(args);
    }

    public void Dispose() => Directory.Delete(Root, recursive: true);
}

/// <summary>Where a redirect goes, whether the server gave it as a path or in full.</summary>
internal static class RedirectExtensions
{
    public static string Path(this Uri? location) => location is null ? "" : location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString;
}
