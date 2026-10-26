using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace SecretHive.Cli.Rendering;

/// <summary>
/// The real thing, on Linux. Calls libc directly where .NET has no equivalent or a wrong one: ownership has no
/// managed API, and <c>File.Move</c> silently copies across filesystems, which is the opposite of atomic.
/// </summary>
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
internal sealed partial class UnixHostFiles : IHostFiles
{
    private const int AtFdCwd = -100;
    private const int AtSymlinkNoFollow = 0x100;
    private const uint StatxBasicStats = 0x7ff;
    private const int FileTypeMask = 0xF000;
    private const int RegularFile = 0x8000;
    private const int DirectoryFile = 0x4000;
    private const int NoSuchFile = 2;

    public EntryInfo? Stat(string path)
    {
        // struct statx has one layout on every architecture, which plain stat does not. Offsets from linux/stat.h.
        Span<byte> buffer = stackalloc byte[256];
        if (statx(AtFdCwd, path, AtSymlinkNoFollow, StatxBasicStats, ref MemoryMarshal.GetReference(buffer)) != 0)
        {
            var error = Marshal.GetLastPInvokeError();
            return error == NoSuchFile ? null : throw Failure("stat", path, error);
        }

        int mode = BinaryPrimitives.ReadUInt16LittleEndian(buffer[28..]);
        var kind = (mode & FileTypeMask) switch
        {
            RegularFile => EntryKind.File,
            DirectoryFile => EntryKind.Directory,
            _ => EntryKind.Other,
        };
        var modified = DateTimeOffset.FromUnixTimeSeconds(BinaryPrimitives.ReadInt64LittleEndian(buffer[112..]))
            .AddTicks(BinaryPrimitives.ReadUInt32LittleEndian(buffer[120..]) / 100);
        var device = ((ulong)BinaryPrimitives.ReadUInt32LittleEndian(buffer[136..]) << 32) | BinaryPrimitives.ReadUInt32LittleEndian(buffer[140..]);
        return new EntryInfo(
            Path.GetFileName(path),
            kind,
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[20..]),
            BinaryPrimitives.ReadUInt32LittleEndian(buffer[24..]),
            mode & 0xFFF,
            modified,
            device);
    }

    public IReadOnlyList<EntryInfo> List(string directory) =>
        [.. Directory.EnumerateFileSystemEntries(directory)
            .Select(Stat)
            .OfType<EntryInfo>()
            .OrderBy(entry => entry.Name, StringComparer.Ordinal)];

    public byte[] Read(string path) => File.ReadAllBytes(path);

    public void CreateDirectory(string path, int mode) => Directory.CreateDirectory(path, (UnixFileMode)mode);

    public void WriteNew(string path, ReadOnlySpan<byte> content, uint uid, uint gid, int mode)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
        };
        using (var stream = new FileStream(path, options))
        {
            stream.Write(content);
            stream.Flush(flushToDisk: true);
        }

        SetOwner(path, uid, gid);
        SetMode(path, mode);
    }

    public void Rename(string from, string to)
    {
        if (rename(from, to) != 0)
        {
            throw Failure("rename", to, Marshal.GetLastPInvokeError());
        }
    }

    public void SetOwner(string path, uint uid, uint gid)
    {
        if (lchown(path, uid, gid) != 0)
        {
            throw Failure("chown", path, Marshal.GetLastPInvokeError());
        }
    }

    public void SetMode(string path, int mode) => File.SetUnixFileMode(path, (UnixFileMode)mode);

    public void DeleteFile(string path) => File.Delete(path);

    public void DeleteDirectory(string path) => Directory.Delete(path, recursive: true);

    private static IOException Failure(string operation, string path, int error) =>
        new($"{operation} {path}: {Marshal.GetPInvokeErrorMessage(error)}");

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int statx(int directory, string path, int flags, uint mask, ref byte buffer);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int rename(string from, string to);

    [LibraryImport("libc", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]
    private static partial int lchown(string path, uint owner, uint group);
}
