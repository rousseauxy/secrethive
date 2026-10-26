using System.Globalization;
using System.Text.RegularExpressions;

namespace SecretHive.Cli.Hosting;

/// <summary>One directory that is mounted whole into containers, and what belongs in it.</summary>
internal sealed record Target(
    string Name,
    string Path,
    uint OwnerUid,
    uint OwnerGid,
    IReadOnlyList<string> Restart,
    IReadOnlyList<KeyValuePair<string, SecretReference>> Keys,
    bool EnvFile = false)
{
    /// <summary>The one file an env target holds: every key as a line, for docker compose to read.</summary>
    public const string EnvFileName = "secrets.env";

    public string Owner => string.Create(CultureInfo.InvariantCulture, $"{OwnerUid}:{OwnerGid}");

    /// <summary>
    /// What is on disk in this target: one file per key, or for an env target the single file that holds them all.
    /// </summary>
    public IReadOnlyList<KeyValuePair<string, SecretReference>> Files => EnvFile ? [new(EnvFileName, Keys[0].Value)] : Keys;
}

/// <summary>A stack's manifest: which files exist where, and which secret fills each. It holds no values.</summary>
internal sealed partial record Manifest(
    string Stack,
    string? DefaultVault,
    IReadOnlyList<Target> Targets,
    IReadOnlyList<KeyValuePair<string, SecretReference>> Environment)
{
    public const string FileName = "secrethive.yml";
    public const string BundleFileName = "secrethive.bundle";

    private const string AppDataVariable = "${appdata}";

    public IEnumerable<SecretReference> References => Targets.SelectMany(target => target.Keys).Concat(Environment).Select(pair => pair.Value);

    public static Manifest Load(string repositoryRoot, string stack, HostProfile profile)
    {
        if (!NameShape().IsMatch(stack))
        {
            throw new InputException($"'{stack}' is not a stack name");
        }

        var path = System.IO.Path.Combine(repositoryRoot, stack, FileName);
        if (!File.Exists(path))
        {
            throw new InputException($"{path}: this stack has no manifest");
        }

        var map = YamlMap.Load(path);
        if (map.Text("version") != "1")
        {
            throw new InputException($"{stack}/{FileName}: only version 1 is understood");
        }

        if (map.Text("stack") != stack)
        {
            throw new InputException($"{stack}/{FileName}: 'stack' must equal the folder name");
        }

        var defaultVault = map.OptionalText("vault");
        var targetsMap = map.Map("targets");
        var environment = ReadReferences(map.Map("env"), defaultVault, EnvironmentNameShape(), "an environment variable name");
        map.EnsureNothingElse();

        var targets = new List<Target>();
        foreach (var name in targetsMap?.Keys ?? [])
        {
            if (!NameShape().IsMatch(name))
            {
                throw new InputException($"{stack}/{FileName}: '{name}' is not a target name");
            }

            var target = targetsMap!.Map(name)!;
            var directory = ExpandPath(target.Text("path"), profile, $"{stack}/{FileName}: targets.{name}.path");
            var (uid, gid) = ParseOwner(target.Text("owner"), $"{stack}/{FileName}: targets.{name}.owner");
            var restart = target.TextList("restart");

            // "files" is one file per key, for an application that reads /run/secrets. "env" is one file of
            // KEY='value' lines, for docker compose to read beside the stack's .env: for the many containers that
            // only take their secrets as variables.
            var format = target.OptionalText("format") ?? "files";
            if (format is not ("files" or "env"))
            {
                throw new InputException($"{stack}/{FileName}: targets.{name}.format is 'files' or 'env'");
            }

            var envFile = format == "env";
            var keys = envFile
                ? ReadReferences(target.Map("keys"), defaultVault, EnvironmentNameShape(), "a variable name")
                : ReadReferences(target.Map("keys"), defaultVault, FileNameShape(), "a file name");
            target.EnsureNothingElse();
            if (envFile && keys.Count == 0)
            {
                throw new InputException($"{stack}/{FileName}: targets.{name} is an env file with no keys");
            }

            if (targets.Any(other => string.Equals(other.Path, directory, StringComparison.Ordinal)))
            {
                throw new InputException($"{stack}/{FileName}: two targets fill {directory}");
            }

            targets.Add(new Target(name, directory, uid, gid, restart, keys, envFile));
        }

        return new Manifest(stack, defaultVault, targets, environment);
    }

    private static List<KeyValuePair<string, SecretReference>> ReadReferences(YamlMap? map, string? defaultVault, Regex shape, string what)
    {
        var result = new List<KeyValuePair<string, SecretReference>>();
        foreach (var key in map?.Keys ?? [])
        {
            if (!shape.IsMatch(key) || key is "." or "..")
            {
                throw new InputException($"'{key}' is not {what}");
            }

            try
            {
                result.Add(new(key, SecretReference.Parse(map!.Text(key), defaultVault)));
            }
            catch (InputException e)
            {
                throw new InputException($"{key}: what it points to {e.Message}", e);
            }
        }

        return result;
    }

    private static string ExpandPath(string raw, HostProfile profile, string where)
    {
        var expanded = raw.Replace(AppDataVariable, profile.AppData, StringComparison.Ordinal);
        if (expanded.Contains('$', StringComparison.Ordinal))
        {
            throw new InputException($"{where}: {AppDataVariable} is the only variable");
        }

        // GetFullPath also folds '..', so a path cannot climb out of appdata unnoticed.
        var full = System.IO.Path.TrimEndingDirectorySeparator(System.IO.Path.GetFullPath(expanded));
        if (!full.StartsWith(profile.AppData + System.IO.Path.DirectorySeparatorChar, StringComparison.Ordinal))
        {
            throw new InputException($"{where}: must be a directory under {profile.AppData}");
        }

        return full;
    }

    private static (uint Uid, uint Gid) ParseOwner(string raw, string where)
    {
        var parts = raw.Split(':');
        if (parts.Length == 2
            && uint.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out var uid)
            && uint.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out var gid))
        {
            return (uid, gid);
        }

        // Names are refused: 'appuser' is one number in the image and another, or nobody, on the host.
        throw new InputException($"{where}: must be numeric uid:gid");
    }

    [GeneratedRegex("^[0-9a-zA-Z][0-9a-zA-Z_-]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex NameShape();

    // No leading dot (hidden files) and no path separator. '__' is the section delimiter and is kept as is.
    [GeneratedRegex("^[0-9a-zA-Z_][0-9a-zA-Z_.-]{0,254}$", RegexOptions.CultureInvariant)]
    private static partial Regex FileNameShape();

    [GeneratedRegex("^[A-Za-z_][A-Za-z0-9_]{0,254}$", RegexOptions.CultureInvariant)]
    private static partial Regex EnvironmentNameShape();
}
