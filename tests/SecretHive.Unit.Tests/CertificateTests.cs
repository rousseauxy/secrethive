using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using SecretHive.Domain;

namespace SecretHive.Unit.Tests;

/// <summary>A self-signed certificate made for one test, in every form it can be supplied in.</summary>
internal sealed class TestCertificate
{
    public const string Password = "generated-pfx-password";

    public TestCertificate(string host, int validDays = 90)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest($"CN={host}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(host);
        names.AddDnsName($"www.{host}");
        request.CertificateExtensions.Add(names.Build());
        NotAfterUtc = DateTimeOffset.UtcNow.AddDays(validDays);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), NotAfterUtc);
        Der = certificate.Export(X509ContentType.Cert);
        Pem = Encoding.ASCII.GetBytes(certificate.ExportCertificatePem());
        Key = Encoding.ASCII.GetBytes(rsa.ExportPkcs8PrivateKeyPem());
        Pfx = certificate.Export(X509ContentType.Pfx, Password);
        Thumbprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
    }

    public byte[] Der { get; }

    public byte[] Pem { get; }

    public byte[] Key { get; }

    public byte[] Pfx { get; }

    public string Thumbprint { get; }

    public DateTimeOffset NotAfterUtc { get; }

    public CertificatePart CertificatePart => new(CertificatePartKind.Certificate, "site.cer", Der);

    public CertificatePart ChainPart => new(CertificatePartKind.Chain, "site-chain.pem", Pem);

    public CertificatePart KeyPart => new(CertificatePartKind.Key, "site.key", Key);

    public CertificatePart PfxPart => new(CertificatePartKind.Pfx, "site.pfx", Pfx);

    public static CertificatePart PasswordPart(string password = Password) => new(CertificatePartKind.PfxPassword, "", Encoding.UTF8.GetBytes(password));
}

public sealed class CertificateTests
{
    private static readonly TestCertificate Site = new("shop.example.test");
    private static readonly TestCertificate Other = new("other.example.test");

    private static string Code(params CertificatePart[] parts) => Assert.Throws<DomainException>(() => CertificateParts.Inspect(parts)).Code;

    [Fact]
    public void Every_form_of_one_certificate_is_accepted_together_and_the_facts_come_from_the_certificate()
    {
        var facts = CertificateParts.Inspect([Site.CertificatePart, Site.ChainPart, Site.KeyPart, Site.PfxPart, TestCertificate.PasswordPart()]);

        Assert.Equal("CN=shop.example.test", facts.Subject);
        Assert.Equal(Site.Thumbprint, facts.Thumbprint);
        Assert.Equal(40, facts.Sha1Thumbprint.Length);
        Assert.Equal(["shop.example.test", "www.shop.example.test"], facts.AlternativeNames);
        Assert.Equal(DateTimeKind.Utc, facts.NotAfterUtc.Kind);
        Assert.InRange(facts.NotAfterUtc, Site.NotAfterUtc.UtcDateTime.AddMinutes(-1), Site.NotAfterUtc.UtcDateTime.AddMinutes(1));
    }

    [Fact]
    public void One_form_is_enough_as_long_as_it_holds_the_certificate()
    {
        Assert.Equal(Site.Thumbprint, CertificateParts.Inspect([Site.CertificatePart]).Thumbprint);
        Assert.Equal(Site.Thumbprint, CertificateParts.Inspect([Site.ChainPart, Site.KeyPart]).Thumbprint);
        Assert.Equal(Site.Thumbprint, CertificateParts.Inspect([Site.PfxPart, TestCertificate.PasswordPart()]).Thumbprint);
        Assert.Equal("certificate.parts.no_certificate", Code(Site.KeyPart));
    }

    [Fact]
    public void Parts_that_are_not_the_same_certificate_are_refused()
    {
        Assert.Equal("certificate.key.mismatch", Code(Site.CertificatePart, Other.KeyPart));
        Assert.Equal("certificate.parts.mismatch", Code(Site.CertificatePart, Other.PfxPart, TestCertificate.PasswordPart()));
        Assert.Equal("certificate.parts.mismatch", Code(Site.CertificatePart, Other.ChainPart));
    }

    [Fact]
    public void A_pkcs12_file_needs_the_password_that_opens_it()
    {
        Assert.Equal("certificate.pfx.password_missing", Code(Site.PfxPart));
        Assert.Equal("certificate.pfx.unreadable", Code(Site.PfxPart, TestCertificate.PasswordPart("generated-wrong")));
        Assert.Equal("certificate.pfx.missing", Code(Site.CertificatePart, TestCertificate.PasswordPart()));
    }

    [Fact]
    public void A_private_key_is_never_accepted_as_a_public_part()
    {
        var keyAsCertificate = new CertificatePart(CertificatePartKind.Certificate, "site.cer", Site.Key);
        var keyInChain = new CertificatePart(CertificatePartKind.Chain, "site.pem", Site.Pem.Concat(Site.Key).ToArray());

        Assert.Equal("certificate.part.private_in_public", Code(keyAsCertificate));
        Assert.Equal("certificate.part.private_in_public", Code(keyInChain));
    }

    [Fact]
    public void Malformed_duplicate_and_oversized_parts_are_refused_without_repeating_them()
    {
        var garbage = new CertificatePart(CertificatePartKind.Certificate, "site.cer", Encoding.ASCII.GetBytes("generated-not-a-certificate"));
        var huge = new CertificatePart(CertificatePartKind.Certificate, "site.cer", new byte[CertificateParts.MaxPartBytes + 1]);

        var invalid = Assert.Throws<DomainException>(() => CertificateParts.Inspect([garbage]));

        Assert.Equal("certificate.part.invalid", invalid.Code);
        Assert.DoesNotContain("generated", invalid.Message);
        Assert.Equal("certificate.part.duplicate", Code(Site.CertificatePart, Site.CertificatePart));
        Assert.Equal("certificate.part.too_large", Code(huge));
        Assert.Equal("certificate.part.empty", Code(new CertificatePart(CertificatePartKind.Key, "site.key", ReadOnlyMemory<byte>.Empty)));
    }

    [Fact]
    public void Only_the_certificate_and_its_chain_are_public()
    {
        Assert.Equal(
            [false, false, true, true, true],
            Enum.GetValues<CertificatePartKind>().Select(CertificateParts.IsPrivate));
        Assert.True(CertificateParts.IsPublicSlot("part:certificate"));
        Assert.True(CertificateParts.IsPublicSlot("part:chain"));
        Assert.False(CertificateParts.IsPublicSlot("part:pfx"));
        Assert.False(CertificateParts.IsPublicSlot("value"));
        Assert.Equal(CertificatePartKind.PfxPassword, CertificateParts.ParseKind("pfx-password"));
        Assert.Equal("certificate.part.not_found", Assert.Throws<DomainException>(() => CertificateParts.ParseKind("password")).Code);
    }
}
