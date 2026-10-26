using System.Globalization;
using SecretHive.Cli.Hosting;

namespace SecretHive.Cli.Rendering;

internal enum ChangeKind
{
    Created,
    Changed,
    Fixed,
    Pruned,
    Foreign,
}

/// <summary>One thing a render did, or would do. Names only.</summary>
internal sealed record Change(ChangeKind Kind, string Target, string Key, string? Detail = null)
{
    /// <summary>Whether the containers reading this target have to be restarted. A foreign entry is only reported.</summary>
    public bool NeedsRestart => Kind != ChangeKind.Foreign;
}

/// <summary>Every value a manifest asks for, resolved and checked, before anything is written.</summary>
internal sealed class ResolvedStack : IDisposable
{
    private readonly Dictionary<(string Target, string Key), SecretValue> _values = [];

    public void Add(string target, string key, SecretValue value) => _values[(target, key)] = value;

    public SecretValue Get(string target, string key) => _values[(target, key)];

    public void Dispose()
    {
        foreach (var value in _values.Values)
        {
            value.Dispose();
        }
    }
}

/// <summary>
/// The one file of an env target: a line per key, <c>KEY='value'</c>, sorted, for docker compose to read. Single
/// quotes because Compose takes what is between them as it is, with no substitution; a quote inside is written
/// as Compose reads it back. A value with a line break, a backslash at its end or a backslash before a quote
/// cannot be carried as Compose would read it and is refused.
/// </summary>
internal static class EnvFileContent
{
    public static SecretValue Compose(IEnumerable<KeyValuePair<string, SecretValue>> values, string target, List<string> problems)
    {
        using var buffer = new MemoryStream();
        foreach (var (key, value) in values.OrderBy(pair => pair.Key, StringComparer.Ordinal))
        {
            var bytes = value.Reveal();
            if (bytes.IndexOfAny((byte)'\n', (byte)'\r') >= 0)
            {
                problems.Add($"{target} {key}: the value holds a line break, which an env file cannot carry");
                continue;
            }

            // Compose reads \' inside single quotes as a quote. A value that ends in a backslash would therefore
            // escape the closing quote and swallow the lines after it, and a backslash before a quote comes back
            // without the backslash. Neither can be written as Compose would read it, so both are refused.
            if (bytes[^1] == (byte)'\\' || bytes.IndexOf("\\'"u8) >= 0)
            {
                problems.Add($"{target} {key}: the value has a backslash at its end or before a quote, which Compose reads as an escaped quote");
                continue;
            }

            buffer.Write(System.Text.Encoding.ASCII.GetBytes(key));
            buffer.Write("='"u8);
            foreach (var one in bytes)
            {
                if (one == (byte)'\'')
                {
                    buffer.WriteByte((byte)'\\');
                }

                buffer.WriteByte(one);
            }

            buffer.Write("'\n"u8);
        }

        var content = buffer.ToArray();
        System.Security.Cryptography.CryptographicOperations.ZeroMemory(buffer.GetBuffer());
        return new SecretValue(content) { Binary = true };
    }
}

/// <summary>
/// Makes target directories hold exactly what the manifest declares: one file per key, the bytes of the value and
/// nothing else, owned by the process that reads it, 0400 in a 0500 directory.
/// </summary>
internal sealed class Renderer(IHostFiles files)
{
    public const int DirectoryMode = 0x140; // 0500
    public const int FileMode = 0x100; // 0400

    private const int StagingMode = 0x1C0; // 0700
    private const string StagingSuffix = ".secrethive-staging";

    /// <summary>
    /// Renders the given targets. With <paramref name="dryRun"/> nothing is written and the result says what would be.
    /// Everything that can be refused is refused for all targets before the first write.
    /// </summary>
    public IReadOnlyList<Change> Render(IReadOnlyList<Target> targets, ResolvedStack values, bool dryRun)
    {
        var plans = targets.Select(target => Plan(target, values)).ToList();
        if (!dryRun)
        {
            foreach (var plan in plans)
            {
                Apply(plan, values);
            }
        }

        return [.. plans.SelectMany(plan => plan.Changes)];
    }

    private TargetPlan Plan(Target target, ResolvedStack values)
    {
        var plan = new TargetPlan(target);
        var directory = files.Stat(target.Path);
        if (directory is null)
        {
            // Only the target itself is created. Creating its parents would give them the wrong owner and
            // lock the application out of its own data folder.
            if (files.Stat(Path.GetDirectoryName(target.Path)!) is not { Kind: EntryKind.Directory })
            {
                throw new InputException($"{target.Name}: the folder that should hold {target.Path} does not exist");
            }

            plan.CreateDirectory = true;
            plan.Changes.AddRange(target.Files.Select(key => new Change(ChangeKind.Created, target.Name, key.Key)));
            return plan;
        }

        if (directory.Kind != EntryKind.Directory)
        {
            throw new InputException($"{target.Name}: {target.Path} exists and is not a directory");
        }

        // Staging sits beside the target. If the target is its own mount, beside it is another filesystem and the
        // rename would not be atomic, so that is refused here instead of discovered halfway.
        var parent = files.Stat(Path.GetDirectoryName(target.Path)!);
        if (parent is null || parent.Device != directory.Device)
        {
            throw new InputException($"{target.Name}: {target.Path} is a mount point; files cannot be replaced atomically from beside it");
        }

        var existing = files.List(target.Path).ToDictionary(entry => entry.Name, StringComparer.Ordinal);
        foreach (var (key, _) in target.Files)
        {
            if (!existing.Remove(key, out var entry))
            {
                plan.Write.Add(key);
                plan.Changes.Add(new Change(ChangeKind.Created, target.Name, key));
            }
            else if (entry.Kind != EntryKind.File)
            {
                throw new InputException($"{target.Name}: {key} exists and is not a regular file");
            }
            else if (!values.Get(target.Name, key).ContentEquals(files.Read(Path.Combine(target.Path, key))))
            {
                plan.Write.Add(key);
                plan.Changes.Add(new Change(ChangeKind.Changed, target.Name, key));
            }
            else if (Drift(entry, target, FileMode) is { } drift)
            {
                // Same content: left alone so its modification time keeps meaning "last real change".
                plan.Repair.Add(key);
                plan.Changes.Add(new Change(ChangeKind.Fixed, target.Name, key, drift));
            }
        }

        foreach (var leftover in existing.Values.OrderBy(entry => entry.Name, StringComparer.Ordinal))
        {
            if (leftover.Kind == EntryKind.File)
            {
                plan.Prune.Add(leftover.Name);
                plan.Changes.Add(new Change(ChangeKind.Pruned, target.Name, leftover.Name));
            }
            else
            {
                plan.Changes.Add(new Change(ChangeKind.Foreign, target.Name, leftover.Name, "not a regular file, left alone"));
            }
        }

        if (Drift(directory, target, DirectoryMode) is { } directoryDrift)
        {
            plan.RepairDirectory = true;
            plan.Changes.Add(new Change(ChangeKind.Fixed, target.Name, ".", directoryDrift));
        }

        return plan;
    }

    private void Apply(TargetPlan plan, ResolvedStack values)
    {
        var target = plan.Target;
        if (plan.CreateDirectory)
        {
            files.CreateDirectory(target.Path, StagingMode);
            plan.Write.AddRange(target.Files.Select(key => key.Key));
            plan.RepairDirectory = true;
        }

        if (plan.Write.Count > 0)
        {
            // A container that starts during the render must never see a half-written or an extra file, and one
            // of the applications refuses to start on any empty file in the directory. So nothing temporary is
            // ever created inside the target: files are completed beside it and renamed in.
            var staging = target.Path + StagingSuffix;
            if (files.Stat(staging) is not null)
            {
                files.DeleteDirectory(staging);
            }

            files.CreateDirectory(staging, StagingMode);
            try
            {
                foreach (var key in plan.Write)
                {
                    var staged = Path.Combine(staging, key);
                    files.WriteNew(staged, values.Get(target.Name, key).Reveal(), target.OwnerUid, target.OwnerGid, FileMode);
                    files.Rename(staged, Path.Combine(target.Path, key));
                }
            }
            finally
            {
                files.DeleteDirectory(staging);
            }
        }

        foreach (var key in plan.Repair)
        {
            var path = Path.Combine(target.Path, key);
            files.SetOwner(path, target.OwnerUid, target.OwnerGid);
            files.SetMode(path, FileMode);
        }

        foreach (var name in plan.Prune)
        {
            files.DeleteFile(Path.Combine(target.Path, name));
        }

        if (plan.RepairDirectory)
        {
            files.SetOwner(target.Path, target.OwnerUid, target.OwnerGid);
            files.SetMode(target.Path, DirectoryMode);
        }
    }

    /// <summary>Describes how an entry's owner or mode differs from what the target wants, or null when it does not.</summary>
    public static string? Drift(EntryInfo entry, Target target, int wantedMode)
    {
        var parts = new List<string>(2);
        if (entry.Uid != target.OwnerUid || entry.Gid != target.OwnerGid)
        {
            parts.Add(string.Create(CultureInfo.InvariantCulture, $"owner {entry.Uid}:{entry.Gid} -> {target.Owner}"));
        }

        if (entry.Mode != wantedMode)
        {
            parts.Add($"mode {Octal(entry.Mode)} -> {Octal(wantedMode)}");
        }

        return parts.Count == 0 ? null : string.Join(", ", parts);
    }

    public static string Octal(int mode) => Convert.ToString(mode, 8).PadLeft(4, '0');

    private sealed class TargetPlan(Target target)
    {
        public Target Target { get; } = target;

        public bool CreateDirectory { get; set; }

        public bool RepairDirectory { get; set; }

        public List<string> Write { get; } = [];

        public List<string> Repair { get; } = [];

        public List<string> Prune { get; } = [];

        public List<Change> Changes { get; } = [];
    }
}
