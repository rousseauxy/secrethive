using System.Security.Cryptography;

namespace SecretHive.Domain;

/// <summary>
/// Decrypted bytes: a value, a sensitive field, a private part of a certificate. There is no way to turn it into a
/// string, so it cannot end up in a log line or an error message by accident; the only way out is
/// <see cref="Reveal"/>, and a test lists the places allowed to call it.
/// </summary>
public sealed class SecretBytes : IDisposable
{
    private readonly byte[] _bytes;

    public SecretBytes(byte[] bytes) => _bytes = bytes;

    public int Length => _bytes.Length;

    public ReadOnlySpan<byte> Reveal() => _bytes;

    public override string ToString() => "[secret]";

    public void Dispose() => CryptographicOperations.ZeroMemory(_bytes);
}
