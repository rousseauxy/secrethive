using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;

namespace SecretHive.Web.Security;

/// <summary>The bootstrap administrator's token, as its hash. The pages and the API check against the same one.</summary>
public sealed class BootstrapAdminToken(byte[] hash)
{
#pragma warning disable CA1819 // a hash handed over once at start
    public byte[] Hash { get; } = hash;
#pragma warning restore CA1819

    /// <summary>Never, when the server was started without a token: an empty hash matches nothing.</summary>
    public bool Matches(string? token) =>
        token is not null && Hash.Length > 0 && CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(token)), Hash);
}

/// <summary>
/// The key the session key ring is encrypted with: derived from the master key, so there is one file to guard and
/// the data folder alone is not enough to forge a session.
/// </summary>
public sealed class SessionKey(byte[] key, string masterKeyId)
{
    internal byte[] Key { get; } = key;

    /// <summary>Names the master key without revealing it, so a ring made under another one is told apart from a damaged one.</summary>
    public string MasterKeyId { get; } = masterKeyId;
}

/// <summary>Encrypts each session key with AES-GCM under the session key.</summary>
public sealed class SessionKeyXmlEncryptor(SessionKey sessionKey) : IXmlEncryptor
{
    /// <summary>Bound into every ciphertext, so an element encrypted for something else does not decrypt as a key.</summary>
    internal static readonly byte[] Purpose = Encoding.UTF8.GetBytes("SecretHive session key ring, v1");

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        ArgumentNullException.ThrowIfNull(plaintextElement);
        var plaintext = Encoding.UTF8.GetBytes(plaintextElement.ToString(SaveOptions.DisableFormatting));
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var ciphertext = new byte[plaintext.Length];
        using (var aes = new AesGcm(sessionKey.Key, tag.Length))
        {
            aes.Encrypt(nonce, plaintext, ciphertext, tag, Purpose);
        }

        CryptographicOperations.ZeroMemory(plaintext);
        var element = new XElement(
            "encryptedKey",
            new XAttribute("masterKeyId", sessionKey.MasterKeyId),
            new XElement("nonce", Convert.ToBase64String(nonce)),
            new XElement("tag", Convert.ToBase64String(tag)),
            new XElement("value", Convert.ToBase64String(ciphertext)));
        return new EncryptedXmlInfo(element, typeof(SessionKeyXmlDecryptor));
    }
}

/// <summary>Created by the framework through its activator, which hands it the service provider.</summary>
public sealed class SessionKeyXmlDecryptor(IServiceProvider services) : IXmlDecryptor
{
    public XElement Decrypt(XElement encryptedElement)
    {
        ArgumentNullException.ThrowIfNull(encryptedElement);
        var id = (string?)encryptedElement.Attribute("masterKeyId");
        var sessionKey = services.GetServices<SessionKey>().FirstOrDefault(candidate => candidate.MasterKeyId == id)
            ?? throw new InvalidOperationException("The session key ring was encrypted under a different master key than the one this server was started with.");
        return Decrypt(encryptedElement, sessionKey);
    }

    /// <summary>
    /// A rotation: every session key in the folder that is stored under a retired master key is stored again under
    /// the current one, so the people who are signed in stay signed in once the old key is no longer named.
    /// Returns how many files were rewritten. A file that cannot be read is left exactly as it is.
    /// </summary>
    public static int MoveToCurrentKey(string directory, SessionKey current, IReadOnlyCollection<SessionKey> retired)
    {
        ArgumentNullException.ThrowIfNull(current);
        ArgumentNullException.ThrowIfNull(retired);
        if (retired.Count == 0 || !Directory.Exists(directory))
        {
            return 0;
        }

        var moved = 0;
        var encryptor = new SessionKeyXmlEncryptor(current);
        foreach (var file in Directory.EnumerateFiles(directory, "*.xml"))
        {
            try
            {
                var document = XDocument.Load(file);
                var changed = false;
                foreach (var element in document.Descendants("encryptedKey").ToList())
                {
                    if (retired.FirstOrDefault(old => old.MasterKeyId == (string?)element.Attribute("masterKeyId")) is { } old)
                    {
                        element.ReplaceWith(encryptor.Encrypt(Decrypt(element, old)).EncryptedElement);
                        changed = true;
                    }
                }

                if (changed)
                {
                    var partial = file + ".partial";
                    document.Save(partial);
                    File.Move(partial, file, overwrite: true);
                    moved++;
                }
            }
            catch (Exception e) when (e is System.Xml.XmlException or CryptographicException or FormatException or IOException or UnauthorizedAccessException)
            {
                // Not ours to repair. The framework will say what it thinks of the file when it reads the ring.
            }
        }

        return moved;
    }

    private static XElement Decrypt(XElement encryptedElement, SessionKey sessionKey)
    {
        var nonce = Convert.FromBase64String((string)encryptedElement.Element("nonce")!);
        var tag = Convert.FromBase64String((string)encryptedElement.Element("tag")!);
        var ciphertext = Convert.FromBase64String((string)encryptedElement.Element("value")!);
        var plaintext = new byte[ciphertext.Length];
        using (var aes = new AesGcm(sessionKey.Key, tag.Length))
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintext, SessionKeyXmlEncryptor.Purpose);
        }

        try
        {
            return XElement.Parse(Encoding.UTF8.GetString(plaintext));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plaintext);
        }
    }
}
