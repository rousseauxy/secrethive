using SecretHive.Cli.Rendering;

namespace SecretHive.Unit.Tests;

/// <summary>
/// An in-memory host. It records every path that ever existed, so a test can assert that nothing temporary was
/// created inside a target, and it counts writes, so a test can assert that an unchanged file was left alone.
/// </summary>
internal sealed class FakeHostFiles : IHostFiles
{
    private sealed class Node
    {
        public EntryKind Kind { get; init; }

        public byte[] Content { get; init; } = [];

        public uint Uid { get; set; }

        public uint Gid { get; set; }

        public int Mode { get; set; }

        public DateTimeOffset Modified { get; init; }

        public ulong Device { get; init; }
    }

    private readonly Dictionary<string, Node> _nodes = new(StringComparer.Ordinal);

    public DateTimeOffset Now { get; set; } = new(2026, 10, 9, 12, 0, 0, TimeSpan.Zero);

    public HashSet<string> EverCreated { get; } = new(StringComparer.Ordinal);

    public int Writes { get; private set; }

    public void SeedDirectory(string path, uint uid = 0, uint gid = 0, int mode = 0x1ED, ulong device = 1) =>
        Put(path, new Node { Kind = EntryKind.Directory, Uid = uid, Gid = gid, Mode = mode, Modified = Now, Device = device });

    public void SeedFile(string path, string content, uint uid, uint gid, int mode) =>
        Put(path, new Node { Kind = EntryKind.File, Content = System.Text.Encoding.UTF8.GetBytes(content), Uid = uid, Gid = gid, Mode = mode, Modified = Now, Device = 1 });

    public void SeedOther(string path) => Put(path, new Node { Kind = EntryKind.Other, Modified = Now, Device = 1 });

    public string Text(string path) => System.Text.Encoding.UTF8.GetString(_nodes[Normal(path)].Content);

    public bool Exists(string path) => _nodes.ContainsKey(Normal(path));

    public EntryInfo? Stat(string path) => _nodes.TryGetValue(Normal(path), out var node) ? Info(Normal(path), node) : null;

    public IReadOnlyList<EntryInfo> List(string directory)
    {
        var prefix = Normal(directory) + Path.DirectorySeparatorChar;
        return [.. _nodes
            .Where(pair => pair.Key.StartsWith(prefix, StringComparison.Ordinal) && !pair.Key[prefix.Length..].Contains(Path.DirectorySeparatorChar))
            .Select(pair => Info(pair.Key, pair.Value))
            .OrderBy(entry => entry.Name, StringComparer.Ordinal)];
    }

    // A copy, as a real read is: the caller wipes what it was given.
    public byte[] Read(string path) => [.. _nodes[Normal(path)].Content];

    public void CreateDirectory(string path, int mode) =>
        Put(path, new Node { Kind = EntryKind.Directory, Mode = mode, Modified = Now, Device = 1 });

    public void WriteNew(string path, ReadOnlySpan<byte> content, uint uid, uint gid, int mode)
    {
        if (Exists(path))
        {
            throw new IOException($"{path} exists");
        }

        Writes++;
        Put(path, new Node { Kind = EntryKind.File, Content = content.ToArray(), Uid = uid, Gid = gid, Mode = mode, Modified = Now, Device = 1 });
    }

    public void Rename(string from, string to)
    {
        var node = _nodes[Normal(from)];
        _nodes.Remove(Normal(from));
        _nodes[Normal(to)] = node;
        EverCreated.Add(Normal(to));
    }

    public void SetOwner(string path, uint uid, uint gid)
    {
        _nodes[Normal(path)].Uid = uid;
        _nodes[Normal(path)].Gid = gid;
    }

    public void SetMode(string path, int mode) => _nodes[Normal(path)].Mode = mode;

    public void DeleteFile(string path) => _nodes.Remove(Normal(path));

    public void DeleteDirectory(string path)
    {
        var prefix = Normal(path) + Path.DirectorySeparatorChar;
        foreach (var key in _nodes.Keys.Where(key => key == Normal(path) || key.StartsWith(prefix, StringComparison.Ordinal)).ToList())
        {
            _nodes.Remove(key);
        }
    }

    private void Put(string path, Node node)
    {
        _nodes[Normal(path)] = node;
        EverCreated.Add(Normal(path));
    }

    private static string Normal(string path) => Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));

    private static EntryInfo Info(string path, Node node) =>
        new(Path.GetFileName(path), node.Kind, node.Uid, node.Gid, node.Mode, node.Modified, node.Device);
}

internal sealed class FakeContainers : IContainerRuntime
{
    public Dictionary<string, ContainerState> States { get; } = new(StringComparer.Ordinal);

    public ContainerState? Running(string container) => States.GetValueOrDefault(container);
}
