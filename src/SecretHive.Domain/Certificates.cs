using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SecretHive.Domain;

public enum CertificatePartKind
{
    Certificate,
    Chain,
    Key,
    Pfx,
    PfxPassword,
}

/// <summary>One file of a certificate, as it was supplied. Nothing is converted.</summary>
public sealed record CertificatePart(CertificatePartKind Kind, string FileName, ReadOnlyMemory<byte> Content);

/// <summary>What a certificate says about itself. Read from it at import, never typed in.</summary>
public sealed record CertificateFacts(
    string Subject,
    string Issuer,
    string Serial,
    string Thumbprint,
    string Sha1Thumbprint,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc,
    IReadOnlyList<string> AlternativeNames);

/// <summary>
/// The rules for a certificate's parts: which exist, which are private, and that every part of one version is the
/// same certificate. Whether a part is private is decided from what it contains, not from what it was called.
/// </summary>
public static class CertificateParts
{
    public const int MaxPartBytes = 64 * 1024;

    private const string SlotPrefix = "part:";

    public static string Name(CertificatePartKind kind) => kind switch
    {
        CertificatePartKind.Certificate => "certificate",
        CertificatePartKind.Chain => "chain",
        CertificatePartKind.Key => "key",
        CertificatePartKind.Pfx => "pfx",
        _ => "pfx-password",
    };

    public static string Slot(CertificatePartKind kind) => SlotPrefix + Name(kind);

    public static bool IsPrivate(CertificatePartKind kind) => kind is CertificatePartKind.Key or CertificatePartKind.Pfx or CertificatePartKind.PfxPassword;

    public static CertificatePartKind ParseKind(string name) =>
        Enum.GetValues<CertificatePartKind>().Cast<CertificatePartKind?>().FirstOrDefault(kind => Name(kind!.Value) == name)
        ?? throw new DomainException("certificate.part.not_found", "A certificate has the parts certificate, chain, key, pfx and pfx-password.");

    /// <summary>Whether a slot of a version is a part anyone who may see the vault may read.</summary>
    public static bool IsPublicSlot(string slot) => slot == Slot(CertificatePartKind.Certificate) || slot == Slot(CertificatePartKind.Chain);

    /// <summary>
    /// Checks a set of parts and returns what the certificate says about itself. Refuses a private key offered as a
    /// public part, a key or a PKCS#12 file that is another certificate than the rest, and a PKCS#12 file without the
    /// password that opens it. No message repeats any content.
    /// </summary>
    public static CertificateFacts Inspect(IReadOnlyList<CertificatePart> parts)
    {
        if (parts.Select(part => part.Kind).Distinct().Count() != parts.Count)
        {
            throw new DomainException("certificate.part.duplicate", "A version holds at most one part of each kind.");
        }

        foreach (var part in parts)
        {
            if (part.Content.IsEmpty && part.Kind != CertificatePartKind.PfxPassword)
            {
                throw new DomainException("certificate.part.empty", $"The part '{Name(part.Kind)}' is empty.");
            }

            if (part.Content.Length > MaxPartBytes)
            {
                throw new DomainException("certificate.part.too_large", $"A part is at most {MaxPartBytes} bytes.");
            }
        }

        ReadOnlyMemory<byte>? Find(CertificatePartKind kind) => parts.FirstOrDefault(part => part.Kind == kind)?.Content;

        var leaves = new List<X509Certificate2>();
        try
        {
            if (Find(CertificatePartKind.Certificate) is { } certificate)
            {
                RefusePrivateKey(certificate, CertificatePartKind.Certificate);
                leaves.Add(Load(() => X509CertificateLoader.LoadCertificate(certificate.Span), "certificate.part.invalid", "The part 'certificate' is not a certificate."));
            }

            if (Find(CertificatePartKind.Chain) is { } chain)
            {
                RefusePrivateKey(chain, CertificatePartKind.Chain);
                var collection = new X509Certificate2Collection();
                Load(() => collection.ImportFromPem(Encoding.ASCII.GetString(chain.Span)), "certificate.part.invalid", "The part 'chain' is not a PEM chain.");
                if (collection.Count == 0)
                {
                    throw new DomainException("certificate.part.invalid", "The part 'chain' holds no certificate.");
                }

                leaves.Add(collection[0]);
                foreach (var other in collection.Skip(1))
                {
                    other.Dispose();
                }
            }

            var password = Find(CertificatePartKind.PfxPassword);
            if (Find(CertificatePartKind.Pfx) is { } pfx)
            {
                if (password is null)
                {
                    throw new DomainException("certificate.pfx.password_missing", "A PKCS#12 file needs its password as the part 'pfx-password', so it can be checked.");
                }

                var flags = OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet;
                var opened = Load(
                    () => X509CertificateLoader.LoadPkcs12(pfx.Span, Encoding.UTF8.GetString(password.Value.Span), flags),
                    "certificate.pfx.unreadable",
                    "The part 'pfx' does not open: it is not a PKCS#12 file, or the password is not its password.");
                leaves.Add(opened);
                if (!opened.HasPrivateKey)
                {
                    throw new DomainException("certificate.pfx.no_key", "The part 'pfx' holds no private key.");
                }
            }
            else if (password is not null)
            {
                throw new DomainException("certificate.pfx.missing", "There is a 'pfx-password' and no 'pfx'.");
            }

            if (leaves.Count == 0)
            {
                throw new DomainException("certificate.parts.no_certificate", "At least one of the parts 'certificate', 'chain' or 'pfx' is needed.");
            }

            var leaf = leaves[0];
            if (leaves.Any(other => !other.RawDataMemory.Span.SequenceEqual(leaf.RawDataMemory.Span)))
            {
                throw new DomainException("certificate.parts.mismatch", "The parts are not the same certificate.");
            }

            if (Find(CertificatePartKind.Key) is { } key)
            {
                var text = Encoding.ASCII.GetString(key.Span);
                if (text.Contains("ENCRYPTED", StringComparison.Ordinal))
                {
                    throw new DomainException("certificate.key.encrypted", "The part 'key' is encrypted; supply it unencrypted, it is encrypted here.");
                }

                // Pairing fails when the key is not this certificate's key.
                Load(() => X509Certificate2.CreateFromPem(leaf.ExportCertificatePem(), text), "certificate.key.mismatch", "The part 'key' is not the private key of this certificate.").Dispose();
            }

            return new CertificateFacts(
                leaf.Subject,
                leaf.Issuer,
                leaf.SerialNumber,
                leaf.GetCertHashString(HashAlgorithmName.SHA256),
                leaf.Thumbprint,
                leaf.NotBefore.ToUniversalTime(),
                leaf.NotAfter.ToUniversalTime(),
                AlternativeNames(leaf));
        }
        finally
        {
            foreach (var leaf in leaves)
            {
                leaf.Dispose();
            }
        }
    }

    private static void RefusePrivateKey(ReadOnlyMemory<byte> content, CertificatePartKind kind)
    {
        if (Encoding.Latin1.GetString(content.Span).Contains("PRIVATE KEY", StringComparison.Ordinal))
        {
            throw new DomainException("certificate.part.private_in_public", $"The part '{Name(kind)}' contains a private key. A private key goes in the part 'key'.");
        }
    }

    private static T Load<T>(Func<T> load, string code, string message)
    {
        try
        {
            return load();
        }
        catch (Exception e) when (e is CryptographicException or ArgumentException)
        {
            throw new DomainException(code, message);
        }
    }

    private static void Load(Action load, string code, string message) => Load(
        () =>
        {
            load();
            return 0;
        },
        code,
        message);

    private static List<string> AlternativeNames(X509Certificate2 certificate)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        return extension is null
            ? []
            : [.. extension.EnumerateDnsNames(), .. extension.EnumerateIPAddresses().Select(address => address.ToString())];
    }
}
