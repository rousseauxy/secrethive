using System.Runtime.Versioning;
using System.Text;
using SecretHive.Cli.Commands;
using SecretHive.Cli.Rendering;

namespace SecretHive.Unit.Tests;

/// <summary>
/// The parts only a real Linux filesystem can prove: ownership, modes, exact bytes and the rename. They need root,
/// because giving a file to another user does; elsewhere they are skipped, and say so.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed class UnixHostFilesTests
{
    private static void RequireLinuxRoot() =>
        Assert.SkipUnless(OperatingSystem.IsLinux() && Environment.IsPrivilegedProcess, "needs Linux and root");

    [Fact]
    public void A_written_file_has_exactly_the_bytes_the_owner_and_the_mode()
    {
        RequireLinuxRoot();
        var directory = Directory.CreateTempSubdirectory("secrethive-unix-").FullName;
        var files = new UnixHostFiles();
        var path = Path.Combine(directory, "Api__Token");

        files.WriteNew(path, "generated-token"u8, 999, 1001, Renderer.FileMode);

        Assert.Equal("generated-token"u8.ToArray(), File.ReadAllBytes(path));
        var entry = files.Stat(path)!;
        Assert.Equal((EntryKind.File, 999u, 1001u, Renderer.FileMode), (entry.Kind, entry.Uid, entry.Gid, entry.Mode));
        Assert.InRange(entry.Modified, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Null(files.Stat(Path.Combine(directory, "absent")));
        Directory.Delete(directory, recursive: true);
    }

    [Fact]
    public void Rename_replaces_the_file_in_one_step_and_refuses_another_filesystem()
    {
        RequireLinuxRoot();
        var directory = Directory.CreateTempSubdirectory("secrethive-unix-").FullName;
        var files = new UnixHostFiles();
        var live = Path.Combine(directory, "live");
        var staged = Path.Combine(directory, "staged");
        files.WriteNew(live, "generated-old"u8, 999, 999, Renderer.FileMode);
        files.WriteNew(staged, "generated-new"u8, 999, 999, Renderer.FileMode);

        files.Rename(staged, live);

        Assert.Equal("generated-new", File.ReadAllText(live));
        Assert.False(File.Exists(staged));

        // /dev/shm is its own filesystem wherever it exists. File.Move would quietly copy; rename must not.
        if (files.Stat("/dev/shm") is { } shm && shm.Device != files.Stat(directory)!.Device)
        {
            var elsewhere = Path.Combine("/dev/shm", Path.GetRandomFileName());
            files.WriteNew(elsewhere, "generated-other"u8, 0, 0, Renderer.FileMode);
            Assert.Throws<IOException>(() => files.Rename(elsewhere, live));
            Assert.Equal("generated-new", File.ReadAllText(live));
            File.Delete(elsewhere);
        }

        Directory.Delete(directory, recursive: true);
    }

    [Fact]
    public void A_whole_render_on_a_real_filesystem_leaves_what_the_container_expects()
    {
        RequireLinuxRoot();
        using var stack = new RealStack();
        stack.Set("api-token", "generated-token");
        stack.Set("sql-connection", "Server=db;Password=generated");

        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));

        var files = new UnixHostFiles();
        var directory = files.Stat(stack.Target)!;
        Assert.Equal((999u, 999u, Renderer.DirectoryMode), (directory.Uid, directory.Gid, directory.Mode));
        Assert.Equal(["Api__Token", "ConnectionStrings__Default"], files.List(stack.Target).Select(entry => entry.Name));
        Assert.All(files.List(stack.Target), entry => Assert.Equal((999u, 999u, Renderer.FileMode), (entry.Uid, entry.Gid, entry.Mode)));
        Assert.Equal("Server=db;Password=generated"u8.ToArray(), File.ReadAllBytes(Path.Combine(stack.Target, "ConnectionStrings__Default")));
        Assert.False(Directory.Exists(stack.Target + ".secrethive-staging"));

        // Unchanged content keeps its modification time: that is how mtime stays meaningful.
        var before = files.Stat(Path.Combine(stack.Target, "Api__Token"))!.Modified;
        Assert.Equal(App.Ok, stack.Run("render", "shop", "--host", "web-1"));
        Assert.Equal(before, files.Stat(Path.Combine(stack.Target, "Api__Token"))!.Modified);
        Assert.Equal(App.Ok, stack.Run("status", "shop", "--host", "web-1"));

        // A stray file is pruned, a changed value replaces one file, and status sees a hand edit.
        File.WriteAllText(Path.Combine(stack.Target, "Old__Key"), "generated-old");
        stack.Set("api-token", "generated-token-2");
        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));
        Assert.Equal(["Api__Token", "ConnectionStrings__Default"], files.List(stack.Target).Select(entry => entry.Name));
        Assert.Equal("generated-token-2", File.ReadAllText(Path.Combine(stack.Target, "Api__Token")));
        File.SetUnixFileMode(Path.Combine(stack.Target, "Api__Token"), UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.WriteAllText(Path.Combine(stack.Target, "Api__Token"), "edited-by-hand\n");
        Assert.Equal(App.Drift, stack.Run("status", "shop", "--host", "web-1"));
        Assert.DoesNotContain("generated", stack.Output.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("edited-by-hand", stack.Output.ToString(), StringComparison.Ordinal);
    }

    /// <summary>The same checkout as <see cref="Stack"/>, against the real filesystem.</summary>
    private sealed class RealStack : IDisposable
    {
        private readonly Stack _checkout = new("""
            version: 1
            stack: shop
            vault: shop-prod
            targets:
              app:
                path: ${appdata}/shop/secrets
                owner: "999:999"
                restart: []
                keys:
                  ConnectionStrings__Default: sql-connection
                  Api__Token: api-token
            """);

        private readonly Queue<string> _input = new();

        public RealStack() => Directory.CreateDirectory(Path.Combine(_checkout.AppData, "shop"));

        public string Target => _checkout.Target();

        public StringBuilder Output => _checkout.Output;

        public void Set(string reference, string value)
        {
            _input.Enqueue(value);
            Assert.Equal(App.Ok, Run("bundle", "set", "shop", reference, "--host", "web-1"));
        }

        public int Run(params string[] args)
        {
            using var output = new StringWriter(Output);
            var services = new AppServices(
                output,
                output,
                new UnixHostFiles(),
                _ => new FakeContainers(),
                () => new SecretHive.Cli.SecretValue(Encoding.UTF8.GetBytes(_input.Dequeue())),
                _checkout.Repository,
                null,
                TimeProvider.System,
                _ => throw new InvalidOperationException("this test has no server"));
            return new App(services).Run(args);
        }

        public void Dispose() => _checkout.Dispose();
    }
}
