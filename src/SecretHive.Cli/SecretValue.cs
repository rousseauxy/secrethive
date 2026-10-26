using System.Security.Cryptography;
using System.Text;

namespace SecretHive.Cli;

/// <summary>
/// The bytes of one secret. There is deliberately no way to turn it into a string: the only way out is
/// <see cref="Reveal"/>, and a test fails the build when that is called outside the few files allowed to.
/// </summary>
internal sealed class SecretValue : IDisposable
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private readonly byte[] _bytes;

    public SecretValue(byte[] bytes) => _bytes = bytes;

    public int Length => _bytes.Length;

    /// <summary>
    /// Bytes that are not text: a part of a certificate, as the server holds it. The rules that catch a mistyped
    /// password (a newline at the end, another encoding) do not apply to a file that is what it is.
    /// </summary>
    public bool Binary { get; init; }

    public ReadOnlySpan<byte> Reveal() => _bytes;

    public bool ContentEquals(ReadOnlySpan<byte> other) => CryptographicOperations.FixedTimeEquals(_bytes, other);

    /// <summary>
    /// Why this value may not be written, or null when it may. An empty file overrides a working setting with
    /// nothing, and a newline at the end presents as a wrong password, so both are refused before anything is written.
    /// </summary>
    public string? Problem()
    {
        if (_bytes.Length == 0)
        {
            return "is empty";
        }

        if (Binary)
        {
            return null;
        }

        string text;
        try
        {
            text = StrictUtf8.GetString(_bytes);
        }
        catch (DecoderFallbackException)
        {
            return "is not UTF-8 text";
        }

        if (char.IsWhiteSpace(text[0]))
        {
            return "starts with whitespace";
        }

        return char.IsWhiteSpace(text[^1]) ? "ends with whitespace" : null;
    }

    public override string ToString() => "[secret]";

    public void Dispose() => CryptographicOperations.ZeroMemory(_bytes);
}
