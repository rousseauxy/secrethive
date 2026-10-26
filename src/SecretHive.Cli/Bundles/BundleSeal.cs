using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace SecretHive.Cli.Bundles;

/// <summary>
/// Sealing and opening of bundle entries. Each value gets its own random AES-256-GCM key, and that key is wrapped
/// with the host's RSA public key (OAEP, SHA-256). Sealing therefore needs nothing secret; opening needs the
/// host's private key. Both primitives come from the base library.
/// </summary>
/// <remarks>
/// What this does not give: proof of who sealed an entry. Anyone who can commit to the compose repository can
/// replace an entry with one of their own making. They could change the compose file just as well, so the
/// repository's own access control is the boundary, not the bundle.
/// </remarks>
internal static class BundleSeal
{
    private const int KeyBytes = 32;
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const int MinimumRsaBits = 3072;

    /// <param name="version">
    /// The version the server gave the value, when it came from there; that is what a later pull compares. Without
    /// one, a random mark: a value entered on the host has no version anywhere else.
    /// </param>
    public static BundleEntry Seal(RSA recipient, Bundle bundle, string reference, SecretValue value, DateTimeOffset now, string? version = null)
    {
        RequireStrongKey(recipient);
        version ??= Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(8));
        var key = RandomNumberGenerator.GetBytes(KeyBytes);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(NonceBytes);
            var ciphertext = new byte[value.Length];
            var tag = new byte[TagBytes];
            using var aes = new AesGcm(key, TagBytes);
            aes.Encrypt(nonce, value.Reveal(), ciphertext, tag, AssociatedData(bundle, reference, version));
            return new BundleEntry(
                reference,
                version,
                now.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
                recipient.Encrypt(key, RSAEncryptionPadding.OaepSHA256),
                nonce,
                ciphertext,
                tag,
                value.Binary);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static SecretValue Open(RSA host, Bundle bundle, BundleEntry entry)
    {
        byte[]? key = null;
        try
        {
            key = host.Decrypt(entry.WrappedKey, RSAEncryptionPadding.OaepSHA256);
            var plaintext = new byte[entry.Ciphertext.Length];
            using var aes = new AesGcm(key, TagBytes);
            aes.Decrypt(entry.Nonce, entry.Ciphertext, entry.Tag, plaintext, AssociatedData(bundle, entry.Reference, entry.Version));
            return new SecretValue(plaintext) { Binary = entry.Binary };
        }
        catch (CryptographicException e)
        {
            // Covers the wrong host key and an entry that was moved to another reference, stack or host.
            throw new InputException($"{entry.Reference}: cannot be opened with this host's key, or the entry was altered", e);
        }
        finally
        {
            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    // Ties a ciphertext to the place it was sealed for, so an entry copied under another name does not open.
    private static byte[] AssociatedData(Bundle bundle, string reference, string version) =>
        Encoding.UTF8.GetBytes($"secrethive-bundle/1\n{bundle.Host}\n{bundle.Stack}\n{reference}\n{version}");

    private static void RequireStrongKey(RSA key)
    {
        if (key.KeySize < MinimumRsaBits)
        {
            throw new InputException($"the host key is {key.KeySize} bits; at least {MinimumRsaBits} is required");
        }
    }
}
