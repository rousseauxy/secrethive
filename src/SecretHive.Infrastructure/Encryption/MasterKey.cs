using System.Security.Cryptography;
using System.Text;
using SecretHive.Application.Ports;

namespace SecretHive.Infrastructure.Encryption;

/// <summary>
/// The key everything else hangs from: 32 random bytes in a file on the host, outside every repository. It is read
/// from a file and never from an environment variable, because a container's environment can be read by anyone
/// who can inspect the container.
/// </summary>
public sealed class MasterKey : IDisposable
{
    private const int Bytes = 32;

    private readonly byte[] _key;

    private MasterKey(byte[] key)
    {
        _key = key;

        // An id derived from the key says which master key wrapped something without revealing anything about it,
        // and needs no bookkeeping: the same file always has the same id.
        Id = Convert.ToHexStringLower(Derive("secrethive/master-key/id/v1", 8));
    }

    public string Id { get; }

    /// <summary>
    /// Reads a master key file: either the 32 bytes themselves, or their base64 text as <c>openssl rand -base64 32</c>
    /// writes it. Anything else is refused; a short or guessable key is worse than a missing one, because it looks fine.
    /// </summary>
    public static MasterKey Load(string path)
    {
        byte[] content;
        try
        {
            content = File.ReadAllBytes(path);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new KeyRingException($"The master key file {path} cannot be read ({e.GetType().Name}).", e);
        }

        if (content.Length == Bytes)
        {
            return new MasterKey(content);
        }

        var decoded = new byte[Bytes + 1];
        var text = Encoding.ASCII.GetString(content).Trim();
        var isBase64 = Convert.TryFromBase64String(text, decoded, out var written) && written == Bytes;
        CryptographicOperations.ZeroMemory(content);
        if (!isBase64)
        {
            CryptographicOperations.ZeroMemory(decoded);
            throw new KeyRingException($"The master key file {path} must hold 32 random bytes, raw or as base64.");
        }

        return new MasterKey(decoded[..Bytes]);
    }

    /// <summary>Creates a new key file. Refuses to replace one: an overwritten master key loses everything it protected.</summary>
    public static void Create(string path)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead;
        }

        var key = RandomNumberGenerator.GetBytes(Bytes);
        try
        {
            using var stream = new FileStream(path, options);
            stream.Write(Encoding.ASCII.GetBytes(Convert.ToBase64String(key) + "\n"));
        }
        catch (IOException e) when (File.Exists(path))
        {
            throw new KeyRingException($"A master key already exists at {path}. Nothing was done.", e);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>
    /// A key for one job, derived from the master key. Every use gets its own, so the bytes in the file are never
    /// themselves used to encrypt anything.
    /// </summary>
    public byte[] Derive(string purpose, int length = Bytes) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, _key, length, salt: null, info: Encoding.UTF8.GetBytes(purpose));

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);
}
