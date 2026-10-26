namespace SecretHive.Cli.Rendering;

internal enum EntryKind
{
    File,
    Directory,
    Other,
}

/// <summary>What the renderer needs to know about one directory entry. Mode is the permission bits only.</summary>
internal sealed record EntryInfo(string Name, EntryKind Kind, uint Uid, uint Gid, int Mode, DateTimeOffset Modified, ulong Device);

/// <summary>
/// The file operations a render is made of. A port, so the rules (what changes, what is pruned, what is refused)
/// are tested without a Linux host, and the Linux behaviour (ownership, modes, atomic rename) is tested on its own.
/// </summary>
internal interface IHostFiles
{
    /// <summary>Null when nothing exists at the path. Never follows a symbolic link.</summary>
    EntryInfo? Stat(string path);

    IReadOnlyList<EntryInfo> List(string directory);

    byte[] Read(string path);

    void CreateDirectory(string path, int mode);

    /// <summary>Creates a new file with exactly these bytes, this owner and this mode, flushed to disk.</summary>
    void WriteNew(string path, ReadOnlySpan<byte> content, uint uid, uint gid, int mode);

    /// <summary>Atomic replace within one filesystem. Must fail, not copy, when the two paths are on different ones.</summary>
    void Rename(string from, string to);

    void SetOwner(string path, uint uid, uint gid);

    void SetMode(string path, int mode);

    void DeleteFile(string path);

    void DeleteDirectory(string path);
}
