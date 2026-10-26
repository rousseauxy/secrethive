using SecretHive.Cli;
using SecretHive.Cli.Commands;
using SecretHive.Cli.Rendering;

string? hostAccessProblem = null;
IHostFiles files;
if (OperatingSystem.IsLinux())
{
    files = new UnixHostFiles();
    if (!Environment.IsPrivilegedProcess)
    {
        hostAccessProblem = "run as root: secret files belong to other users and are readable by them alone";
    }
}
else
{
    files = new UnavailableHostFiles();
    hostAccessProblem = "secret files are rendered on Linux hosts only; on this machine use the bundle commands";
}

var services = new AppServices(
    Console.Out,
    Console.Error,
    files,
    docker => new DockerCli(docker),
    ReadValue,
    Environment.CurrentDirectory,
    hostAccessProblem,
    TimeProvider.System,
    SecretHive.Cli.Server.HttpSecretServer.For);

return new App(services).Run(args);

// A value arrives on standard input when it is piped, and from a prompt without echo otherwise. Never from an
// argument: the command line of a process is readable by every user on the host.
static SecretValue ReadValue()
{
    if (Console.IsInputRedirected)
    {
        using var input = Console.OpenStandardInput();
        using var buffer = new MemoryStream();
        input.CopyTo(buffer);
        return new SecretValue(buffer.ToArray());
    }

    Console.Error.Write("value: ");
    var text = new System.Text.StringBuilder();
    while (Console.ReadKey(intercept: true) is { Key: not ConsoleKey.Enter } key)
    {
        if (key.Key == ConsoleKey.Backspace)
        {
            text.Length = Math.Max(0, text.Length - 1);
        }
        else if (!char.IsControl(key.KeyChar))
        {
            text.Append(key.KeyChar);
        }
    }

    Console.Error.WriteLine();
    return new SecretValue(System.Text.Encoding.UTF8.GetBytes(text.ToString()));
}

/// <summary>Stands in where there are no secret files to manage; every command that needs them is refused first.</summary>
internal sealed class UnavailableHostFiles : IHostFiles
{
    public EntryInfo? Stat(string path) => throw new PlatformNotSupportedException();

    public IReadOnlyList<EntryInfo> List(string directory) => throw new PlatformNotSupportedException();

    public byte[] Read(string path) => throw new PlatformNotSupportedException();

    public void CreateDirectory(string path, int mode) => throw new PlatformNotSupportedException();

    public void WriteNew(string path, ReadOnlySpan<byte> content, uint uid, uint gid, int mode) => throw new PlatformNotSupportedException();

    public void Rename(string from, string to) => throw new PlatformNotSupportedException();

    public void SetOwner(string path, uint uid, uint gid) => throw new PlatformNotSupportedException();

    public void SetMode(string path, int mode) => throw new PlatformNotSupportedException();

    public void DeleteFile(string path) => throw new PlatformNotSupportedException();

    public void DeleteDirectory(string path) => throw new PlatformNotSupportedException();
}
