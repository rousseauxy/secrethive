using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Web.Security;

namespace SecretHive.Unit.Tests;

public sealed class ServerCertificateTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-tls-").FullName;

    private MasterKey Key(string name)
    {
        var path = Path.Combine(_directory, name);
        if (!File.Exists(path))
        {
            MasterKey.Create(path);
        }

        return MasterKey.Load(path);
    }

    private static IConfiguration Settings(params (string Key, string Value)[] values) =>
        new ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(item => item.Key, item => (string?)item.Value)).Build();

    private static string[] Names(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        return [.. extension.EnumerateDnsNames(), .. extension.EnumerateIPAddresses().Select(address => address.ToString())];
    }

    [Fact]
    public void With_nothing_given_the_server_makes_a_certificate_for_its_names_and_keeps_it()
    {
        var settings = Settings(("HostNames", "secrethive.example.test, 192.0.2.10"));

        var first = ServerCertificate.Resolve(settings, _directory, Key("a"));
        var second = ServerCertificate.Resolve(settings, _directory, Key("a"));

        Assert.True(first.SelfSigned);
        Assert.True(first.Certificate.HasPrivateKey);
        Assert.Equal(["secrethive.example.test", "localhost", "192.0.2.10"], Names(first.Certificate));
        Assert.InRange(first.Certificate.NotAfter.ToUniversalTime(), DateTime.UtcNow.AddDays(800), DateTime.UtcNow.AddDays(830));

        // The same certificate after a restart: an address must not change its certificate every time it starts.
        Assert.Equal(first.Certificate.Thumbprint, second.Certificate.Thumbprint);
    }

    [Fact]
    public void A_new_one_is_made_when_the_names_change_or_the_master_key_does()
    {
        var first = ServerCertificate.Resolve(Settings(("HostNames", "one.example.test")), _directory, Key("a"));

        var renamed = ServerCertificate.Resolve(Settings(("HostNames", "two.example.test")), _directory, Key("a"));
        var otherKey = ServerCertificate.Resolve(Settings(("HostNames", "two.example.test")), _directory, Key("b"));

        Assert.NotEqual(first.Certificate.Thumbprint, renamed.Certificate.Thumbprint);
        Assert.Contains("two.example.test", Names(renamed.Certificate));

        // Stored under a password derived from the master key: another key cannot open it and makes one of its own.
        Assert.NotEqual(renamed.Certificate.Thumbprint, otherKey.Certificate.Thumbprint);
        Assert.Throws<CryptographicException>(() => X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(_directory, "tls", $"self-signed.{Key("a").Id}.pfx"), null));

        // And it did not write over the first key's: a start with the wrong key costs the right key nothing.
        Assert.Equal(renamed.Certificate.Thumbprint, ServerCertificate.Resolve(Settings(("HostNames", "two.example.test")), _directory, Key("a")).Certificate.Thumbprint);
    }

    [Fact]
    public void A_rotation_keeps_the_certificate_even_after_a_start_with_the_new_key_alone()
    {
        var settings = Settings(("HostNames", "one.example.test"));
        var before = ServerCertificate.Resolve(settings, _directory, Key("old")).Certificate.Thumbprint;

        // Somebody starts with the new key and nothing else first. That makes a certificate of its own.
        var mistaken = ServerCertificate.Resolve(settings, _directory, Key("new")).Certificate.Thumbprint;
        Assert.NotEqual(before, mistaken);

        // The rotation proper: the old key named as retired. The old key's certificate becomes the new key's.
        Assert.Equal(before, ServerCertificate.Resolve(settings, _directory, Key("new"), [Key("old")]).Certificate.Thumbprint);

        // And stays, once the old key is no longer named.
        Assert.Equal(before, ServerCertificate.Resolve(settings, _directory, Key("new")).Certificate.Thumbprint);
    }

    [Fact]
    public void A_certificate_from_a_release_that_did_not_name_the_file_after_the_key_is_kept()
    {
        var settings = Settings(("HostNames", "one.example.test"));
        var before = ServerCertificate.Resolve(settings, _directory, Key("a")).Certificate.Thumbprint;
        var tls = Path.Combine(_directory, "tls");
        File.Move(Path.Combine(tls, $"self-signed.{Key("a").Id}.pfx"), Path.Combine(tls, "self-signed.pfx"));

        // Another key leaves it alone; its own key takes it over under the new name.
        Assert.NotEqual(before, ServerCertificate.Resolve(settings, _directory, Key("b")).Certificate.Thumbprint);
        Assert.True(File.Exists(Path.Combine(tls, "self-signed.pfx")));
        Assert.Equal(before, ServerCertificate.Resolve(settings, _directory, Key("a")).Certificate.Thumbprint);
        Assert.False(File.Exists(Path.Combine(tls, "self-signed.pfx")));
    }

    [Fact]
    public void A_certificate_of_your_own_is_used_as_given_and_half_a_pair_is_refused()
    {
        var site = new TestCertificate("secrethive.example.test");
        var certificateFile = Path.Combine(_directory, "site.pem");
        var keyFile = Path.Combine(_directory, "site.key");
        File.WriteAllBytes(certificateFile, site.Pem);
        File.WriteAllBytes(keyFile, site.Key);

        var own = ServerCertificate.Resolve(Settings(("CertificateFile", certificateFile), ("KeyFile", keyFile)), _directory, Key("a"));

        Assert.False(own.SelfSigned);
        Assert.True(own.Certificate.HasPrivateKey);
        Assert.Equal(site.Thumbprint, own.Certificate.GetCertHashString(HashAlgorithmName.SHA256));
        Assert.False(Directory.Exists(Path.Combine(_directory, "tls")));
        Assert.Throws<InvalidOperationException>(() => ServerCertificate.Resolve(Settings(("CertificateFile", certificateFile)), _directory, Key("a")));
        Assert.Throws<InvalidOperationException>(() => ServerCertificate.Resolve(Settings(("CertificateFile", certificateFile), ("KeyFile", Path.Combine(_directory, "absent.key"))), _directory, Key("a")));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
