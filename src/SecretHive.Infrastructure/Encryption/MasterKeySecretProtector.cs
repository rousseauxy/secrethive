using System.Security.Cryptography;
using System.Text;
using SecretHive.Application.Ports;

namespace SecretHive.Infrastructure.Encryption;

/// <summary>
/// Encrypts the server's own small secrets (a sign-in provider's client secret) under a key derived from the master
/// key. So they are readable wherever the master key and the database are, which is exactly what a restore on a
/// clean host has: nothing else on the old host is needed to bring them back.
/// </summary>
public sealed class MasterKeySecretProtector(MasterKey master, IEnumerable<MasterKey>? retired = null) : ISecretProtector
{
    public const string Prefix = "mk1:";
    private const int NonceBytes = 12;
    private const int TagBytes = 16;
    private const string Purpose = "secrethive/server-secret/v1";
    private readonly byte[] key = (master ?? throw new ArgumentNullException(nameof(master))).Derive(Purpose);

    // Earlier master keys, tried when the current one does not open something: what they protected is read once
    // more, to be stored again under the current key.
    private readonly List<byte[]> earlier = [.. (retired ?? []).Select(old => old.Derive(Purpose))];

    public string Protect(string secret)
    {
        if (string.IsNullOrEmpty(secret))
        {
            return "";
        }

        var plain = Encoding.UTF8.GetBytes(secret);
        var sealedBytes = new byte[NonceBytes + TagBytes + plain.Length];
        RandomNumberGenerator.Fill(sealedBytes.AsSpan(0, NonceBytes));
        using var aes = new AesGcm(key, TagBytes);
        aes.Encrypt(sealedBytes.AsSpan(0, NonceBytes), plain, sealedBytes.AsSpan(NonceBytes + TagBytes), sealedBytes.AsSpan(NonceBytes, TagBytes));
        CryptographicOperations.ZeroMemory(plain);
        return Prefix + Convert.ToBase64String(sealedBytes);
    }

    public string? Unprotect(string protectedSecret) => Open(protectedSecret, key) ?? earlier.Select(old => Open(protectedSecret, old)).FirstOrDefault(opened => opened is not null);

    /// <summary>Whether the current master key opens it. False for what an earlier key protected and for what nothing opens.</summary>
    public bool IsUnderCurrentKey(string protectedSecret) => Open(protectedSecret, key) is not null;

    private static string? Open(string protectedSecret, byte[] with)
    {
        if (string.IsNullOrEmpty(protectedSecret) || !protectedSecret.StartsWith(Prefix, StringComparison.Ordinal))
        {
            return null;
        }

        try
        {
            var sealedBytes = Convert.FromBase64String(protectedSecret[Prefix.Length..]);
            if (sealedBytes.Length < NonceBytes + TagBytes)
            {
                return null;
            }

            var plain = new byte[sealedBytes.Length - NonceBytes - TagBytes];
            using var aes = new AesGcm(with, TagBytes);
            aes.Decrypt(sealedBytes.AsSpan(0, NonceBytes), sealedBytes.AsSpan(NonceBytes + TagBytes), sealedBytes.AsSpan(NonceBytes, TagBytes), plain);
            return Encoding.UTF8.GetString(plain);
        }
        catch (Exception e) when (e is FormatException or CryptographicException)
        {
            return null;
        }
    }
}
