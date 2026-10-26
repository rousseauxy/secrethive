using System.Security.Cryptography;

namespace SecretHive.Cli.Bundles;

/// <summary>The host's key pair: the private half stays on the host outside every repository, the public half is committed.</summary>
internal static class HostKey
{
    private const int Bits = 4096;

    public static RSA LoadPrivate(string path) => Load(path, "the host's bundle key");

    public static RSA LoadPublic(string path) => Load(path, "the host's public key");

    /// <summary>Creates the pair. Refuses to replace either file: a lost private key makes every bundle unreadable.</summary>
    public static void Create(string privatePath, string publicPath)
    {
        if (File.Exists(privatePath) || File.Exists(publicPath))
        {
            throw new InputException($"a host key already exists ({privatePath} or {publicPath}). Nothing was done.");
        }

        using var rsa = RSA.Create(Bits);
        Directory.CreateDirectory(Path.GetDirectoryName(privatePath)!);
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead;
        }

        using (var stream = new FileStream(privatePath, options))
        using (var writer = new StreamWriter(stream))
        {
            writer.Write(rsa.ExportPkcs8PrivateKeyPem());
        }

        File.WriteAllText(publicPath, rsa.ExportSubjectPublicKeyInfoPem() + "\n");
    }

    private static RSA Load(string path, string what)
    {
        var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(File.ReadAllText(path));
            return rsa;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or CryptographicException)
        {
            rsa.Dispose();
            throw new InputException($"{path}: {what} cannot be read ({e.GetType().Name})", e);
        }
    }
}
