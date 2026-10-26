using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SecretHive.Infrastructure.Encryption;

namespace SecretHive.Web.Security;

/// <summary>The certificate the server answers with, and where it came from.</summary>
public sealed record ServerCertificate(X509Certificate2 Certificate, bool SelfSigned, string Source)
{
    private const int RenewDaysBefore = 30;
    private const int ValidDays = 825;

    /// <summary>
    /// The certificate to serve. Your own, when <c>SecretHive:Tls:CertificateFile</c> and <c>KeyFile</c> name PEM
    /// files; otherwise one the server makes for itself and keeps in the data folder, so the address is the same
    /// certificate after a restart. It is made again when it nears its end or when the host names change.
    /// </summary>
    /// <remarks>
    /// A self-made certificate is not trusted by a browser or a tool until someone trusts it by hand. What it gives
    /// without that is encryption on the wire, which is what matters behind a proxy that re-encrypts to this server.
    /// </remarks>
    public static ServerCertificate Resolve(IConfiguration tls, string dataDirectory, MasterKey masterKey, IReadOnlyList<MasterKey>? retired = null)
    {
        var certificateFile = tls["CertificateFile"];
        var keyFile = tls["KeyFile"];
        if (!string.IsNullOrEmpty(certificateFile) || !string.IsNullOrEmpty(keyFile))
        {
            if (string.IsNullOrEmpty(certificateFile) || string.IsNullOrEmpty(keyFile))
            {
                throw new InvalidOperationException("SecretHive:Tls:CertificateFile and SecretHive:Tls:KeyFile go together: set both, or neither.");
            }

            try
            {
                // Re-imported through PKCS#12 because a key that only exists as PEM in memory cannot be used for TLS on Windows.
                using var pem = X509Certificate2.CreateFromPemFile(certificateFile, keyFile);
                return new ServerCertificate(X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pfx), null), false, certificateFile);
            }
            catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException)
            {
                throw new InvalidOperationException($"The TLS certificate in {certificateFile} with its key in {keyFile} cannot be loaded ({e.GetType().Name}).", e);
            }
        }

        var names = (tls["HostNames"] ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).ToList();
        if (names.Count == 0)
        {
            names.Add(Dns.GetHostName());
        }

        names.Add("localhost");
        names = [.. names.Distinct(StringComparer.OrdinalIgnoreCase)];

        // Kept as PKCS#12 under a password derived from the master key: the data folder alone does not give the key away.
        // One file per master key, named after the key's id. A start with another key (a mistake, or the first step
        // of a rotation) then makes a file of its own and can never write over the certificate of the key in use.
        var directory = Path.Combine(dataDirectory, "tls");
        var path = Path.Combine(directory, $"self-signed.{masterKey.Id}.pfx");
        var unnamed = Path.Combine(directory, "self-signed.pfx"); // where releases before 0.8 kept it
        const string purpose = "secrethive/tls/self-signed/v1";
        var password = Convert.ToBase64String(masterKey.Derive(purpose));

        // A rotation: the certificate of the retired key becomes the current key's, replacing whatever a start
        // with the new key alone may have made. A proxy that trusts exactly this certificate is told nothing.
        var adopted = false;
        foreach (var old in retired ?? [])
        {
            foreach (var candidate in new[] { Path.Combine(directory, $"self-signed.{old.Id}.pfx"), unnamed }.Where(File.Exists))
            {
                try
                {
                    using var under = X509CertificateLoader.LoadPkcs12FromFile(candidate, Convert.ToBase64String(old.Derive(purpose)), X509KeyStorageFlags.Exportable);
                    File.WriteAllBytes(path, under.Export(X509ContentType.Pfx, password));
                    adopted = true;
                    break;
                }
                catch (CryptographicException)
                {
                }
            }

            if (adopted)
            {
                break;
            }
        }

        // From a release that did not name the file after the key: if it opens with this key, it is this key's.
        if (!File.Exists(path) && File.Exists(unnamed))
        {
            try
            {
                using var mine = X509CertificateLoader.LoadPkcs12FromFile(unnamed, password);
                File.Move(unnamed, path);
            }
            catch (CryptographicException)
            {
                // Another key's, or damaged. Left where it is.
            }
        }

        if (File.Exists(path))
        {
            try
            {
                var stored = X509CertificateLoader.LoadPkcs12FromFile(path, password);
                if (stored.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(RenewDaysBefore) && Covers(stored, names))
                {
                    return new ServerCertificate(stored, true, "made by this server");
                }

                stored.Dispose();
            }
            catch (CryptographicException)
            {
                // Damaged: make a new one.
            }
        }

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN={names[0]}", key, HashAlgorithmName.SHA256);
        var alternative = new SubjectAlternativeNameBuilder();
        foreach (var name in names)
        {
            if (IPAddress.TryParse(name, out var address))
            {
                alternative.AddIpAddress(address);
            }
            else
            {
                alternative.AddDnsName(name);
            }
        }

        request.CertificateExtensions.Add(alternative.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        using var made = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(ValidDays));
        var pfx = made.Export(X509ContentType.Pfx, password);
        Directory.CreateDirectory(directory);
        File.WriteAllBytes(path, pfx);
        return new ServerCertificate(X509CertificateLoader.LoadPkcs12(pfx, password), true, "made by this server");
    }

    private static bool Covers(X509Certificate2 certificate, List<string> names)
    {
        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (extension is null)
        {
            return false;
        }

        var present = extension.EnumerateDnsNames().Concat(extension.EnumerateIPAddresses().Select(address => address.ToString())).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return names.All(name => present.Contains(IPAddress.TryParse(name, out var address) ? address.ToString() : name));
    }
}

/// <summary>Facts about this server, for the system page.</summary>
public sealed record ServerInfo(
    string Version,
    DateTime StartedUtc,
    string DatabaseProvider,
    string MasterKeyId,
    IReadOnlyList<string> RetiredMasterKeyIds,
    string DataDirectory,
    ServerCertificate? Tls,
    int HttpPort,
    int? HttpsPort,
    IReadOnlyList<string> TrustedProxies,
    bool BootstrapToken = true);
