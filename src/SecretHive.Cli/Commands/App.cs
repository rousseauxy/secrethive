using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using SecretHive.Cli.Bundles;
using SecretHive.Cli.Hosting;
using SecretHive.Cli.Rendering;
using SecretHive.Cli.Server;

namespace SecretHive.Cli.Commands;

/// <summary>Everything a command touches outside its own logic, so the commands run unchanged under test.</summary>
internal sealed record AppServices(
    TextWriter Out,
    TextWriter Error,
    IHostFiles Files,
    Func<IReadOnlyList<string>, IContainerRuntime> Containers,
    Func<SecretValue> ReadValue,
    string WorkingDirectory,
    string? HostAccessProblem,
    TimeProvider Clock,
    Func<HostProfile, ISecretServer> Server);

/// <summary>
/// The commands. Every line written here is made of names: stacks, targets, keys, references, containers. No
/// command prints, logs or passes on a value, and none takes one as an argument.
/// </summary>
internal sealed class App(AppServices services)
{
    public const int Ok = 0;
    public const int Refused = 1;
    public const int Changed = 10;
    public const int Drift = 20;

    private const string Usage = """
        secrethive render <stack> --host <profile> [--dry-run] [--target <name>]
        secrethive check  <stack> --host <profile>
        secrethive status <stack> --host <profile>
        secrethive run    <stack> --host <profile> -- <command>

        secrethive bundle pull   <stack> --host <profile>      from the server, sealed for this host
        secrethive bundle push   <stack> --host <profile> [--dry-run] [--server-key <file>]
                                                               onto the server: what it lacks, never over what it has
        secrethive bundle import <stack> --host <profile>      from the files on disk
        secrethive bundle set    <stack> <reference> --host <profile>
        secrethive bundle prune  <stack> --host <profile>
        secrethive host keygen --host <profile>

        Run from the root of the compose repository, or pass --repo <dir>.
        Exit: 0 nothing to do, 10 changed (restart what is named), 20 out of step, 1 refused.
        """;

    public int Run(IReadOnlyList<string> args)
    {
        try
        {
            var arguments = new Arguments(args);
            return arguments.NextWord() switch
            {
                "render" => Render(arguments),
                "check" => Check(arguments),
                "status" => Status(arguments),
                "run" => RunCommand(arguments),
                "bundle" => arguments.NextWord() switch
                {
                    "import" => BundleImport(arguments),
                    "set" => BundleSet(arguments),
                    "prune" => BundlePrune(arguments),
                    "pull" => BundlePull(arguments),
                    "push" => BundlePush(arguments),
                    _ => PrintUsage(),
                },
                "host" when arguments.NextWord() == "keygen" => HostKeygen(arguments),
                _ => PrintUsage(),
            };
        }
        catch (InputException e)
        {
            services.Error.WriteLine($"refused: {e.Message}");
            return Refused;
        }
    }

    private int PrintUsage()
    {
        services.Error.WriteLine(Usage);
        return Refused;
    }

    private int Render(Arguments arguments)
    {
        var context = Load(arguments);
        var dryRun = arguments.Has("--dry-run");
        RequireHostAccess();

        var targets = context.Manifest.Targets;
        if (arguments.Option("--target") is { } only)
        {
            targets = [.. targets.Where(target => target.Name == only)];
            if (targets.Count == 0)
            {
                throw new InputException($"{context.Manifest.Stack} has no target '{only}'");
            }
        }

        using var values = Resolve(context, targets, out var problems);
        if (Report(problems))
        {
            return Refused;
        }

        var changes = new Renderer(services.Files).Render(targets, values, dryRun);
        if (dryRun)
        {
            services.Error.WriteLine("dry run: nothing was written");
        }

        foreach (var change in changes)
        {
            var target = targets.First(candidate => candidate.Name == change.Target);
            var detail = change.Detail ?? (dryRun && change.Kind is ChangeKind.Created or ChangeKind.Changed
                ? $"{target.Owner} {Renderer.Octal(Renderer.FileMode)}"
                : "");
            services.Out.WriteLine($"{Verb(change.Kind),-8} {change.Target}  {change.Key}  {detail}".TrimEnd());
        }

        var restart = targets
            .Where(target => changes.Any(change => change.Target == target.Name && change.NeedsRestart))
            .SelectMany(target => target.Restart)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        foreach (var container in restart)
        {
            services.Out.WriteLine($"restart  {container}");
        }

        return changes.Any(change => change.NeedsRestart) ? Changed : Ok;
    }

    private int Check(Arguments arguments)
    {
        var context = Load(arguments);
        using var values = Resolve(context, context.Manifest.Targets, out var problems);

        var containers = services.Containers(context.Profile.Docker);
        foreach (var target in context.Manifest.Targets)
        {
            foreach (var container in target.Restart)
            {
                // An unreadable secret file is a crash at startup, not a fallback, so a wrong owner fails here.
                if (containers.Running(container) is { } state && state.Uid != target.OwnerUid)
                {
                    problems.Add($"{target.Name}: {container} runs as uid {state.Uid}, the target is owned by {target.OwnerUid}");
                }
            }
        }

        if (Report(problems))
        {
            return Refused;
        }

        services.Out.WriteLine($"ok       {context.Manifest.Stack}  {context.Manifest.Targets.Sum(target => target.Keys.Count)} keys in {context.Manifest.Targets.Count} targets");
        return Ok;
    }

    private int Status(Arguments arguments)
    {
        var context = Load(arguments);
        RequireHostAccess();
        using var values = Resolve(context, context.Manifest.Targets, out var problems);
        if (Report(problems))
        {
            return Refused;
        }

        var containers = services.Containers(context.Profile.Docker);
        var findings = new List<string>();
        foreach (var target in context.Manifest.Targets)
        {
            var directory = services.Files.Stat(target.Path);
            if (directory is not { Kind: EntryKind.Directory })
            {
                findings.Add($"missing  {target.Name}  .");
                continue;
            }

            if (Renderer.Drift(directory, target, Renderer.DirectoryMode) is { } directoryDrift)
            {
                findings.Add($"drift    {target.Name}  .  {directoryDrift}");
            }

            var existing = services.Files.List(target.Path).ToDictionary(entry => entry.Name, StringComparer.Ordinal);
            DateTimeOffset? newest = null;
            foreach (var (key, _) in target.Files)
            {
                if (!existing.Remove(key, out var entry) || entry.Kind != EntryKind.File)
                {
                    findings.Add($"missing  {target.Name}  {key}");
                    continue;
                }

                newest = newest is null || entry.Modified > newest ? entry.Modified : newest;
                if (!values.Get(target.Name, key).ContentEquals(services.Files.Read(Path.Combine(target.Path, key))))
                {
                    findings.Add($"differs  {target.Name}  {key}");
                }

                if (Renderer.Drift(entry, target, Renderer.FileMode) is { } drift)
                {
                    findings.Add($"drift    {target.Name}  {key}  {drift}");
                }
            }

            findings.AddRange(existing.Keys.Order(StringComparer.Ordinal).Select(name => $"orphan   {target.Name}  {name}"));

            // There is no reload: a file newer than the container means the container still runs on the old value.
            foreach (var container in target.Restart)
            {
                if (newest is not null && containers.Running(container) is { } state && state.StartedAt < newest)
                {
                    findings.Add($"restart-pending  {target.Name}  {container}");
                }
            }
        }

        findings.AddRange(BundleBehindServer(context));
        if (findings.Count == 0)
        {
            services.Out.WriteLine($"in-step  {context.Manifest.Stack}");
            return Ok;
        }

        foreach (var finding in findings)
        {
            services.Out.WriteLine(finding);
        }

        return Drift;
    }

    private int RunCommand(Arguments arguments)
    {
        var context = Load(arguments);
        if (arguments.Rest.Count == 0)
        {
            throw new InputException("run needs a command after --");
        }

        var start = new ProcessStartInfo(arguments.Rest[0]) { UseShellExecute = false };
        foreach (var argument in arguments.Rest.Skip(1))
        {
            start.ArgumentList.Add(argument);
        }

        var problems = new List<string>();
        using var source = OpenSource(context, [.. context.Manifest.Environment.Select(pair => pair.Value)]);
        foreach (var (variable, reference) in context.Manifest.Environment)
        {
            if (Checked(source, reference, variable, problems) is { } value)
            {
                using (value)
                {
                    start.Environment[variable] = Encoding.UTF8.GetString(value.Reveal());
                }
            }
        }

        if (Report(problems))
        {
            return Refused;
        }

        using var process = Process.Start(start) ?? throw new InputException($"{arguments.Rest[0]} could not be started");
        process.WaitForExit();
        return process.ExitCode;
    }

    private int BundleImport(Arguments arguments)
    {
        var context = Load(arguments);
        RequireHostAccess();
        var bundle = Bundle.LoadOrEmpty(context.BundlePath, context.Profile.Host, context.Manifest.Stack);

        // What is on disk today, per reference. Two keys that share a reference must hold the same bytes.
        var problems = new List<string>();
        var found = new List<(string Reference, string Where, SecretValue Value)>();
        try
        {
            foreach (var target in context.Manifest.Targets.Where(target => target.EnvFile))
            {
                // What an env target holds is in the stack's .env today, as variables: taken from there, each as
                // the bytes Compose gives the container now.
                var envPath = Path.Combine(Path.GetDirectoryName(context.BundlePath)!, ".env");
                if (!File.Exists(envPath))
                {
                    problems.Add($"{target.Name}: {envPath} does not exist, so there is nothing to take its variables from");
                    continue;
                }

                var (values, refused) = DotEnv.Read(envPath, [.. target.Keys.Select(pair => pair.Key)]);
                foreach (var (key, reference) in target.Keys)
                {
                    var where = $"{target.Name} {key}";
                    if (refused.TryGetValue(key, out var why))
                    {
                        problems.Add($"{where}: in .env it {why}. Set it by hand: secrethive bundle set {context.Manifest.Stack} {reference.BundleKey}");
                    }
                    else if (!values.TryGetValue(key, out var value))
                    {
                        problems.Add($"{where}: .env has no such variable");
                    }
                    else
                    {
                        var same = found.FirstOrDefault(other => other.Reference == reference.BundleKey);
                        if (same.Value is not null && !same.Value.ContentEquals(value.Reveal()))
                        {
                            problems.Add($"{where} and {same.Where} share {reference.BundleKey} but hold different content");
                        }

                        found.Add((reference.BundleKey, where, value));
                    }
                }

                foreach (var unused in values.Where(pair => found.All(item => !ReferenceEquals(item.Value, pair.Value))))
                {
                    unused.Value.Dispose();
                }
            }

            foreach (var target in context.Manifest.Targets.Where(target => !target.EnvFile))
            {
                foreach (var (key, reference) in target.Keys)
                {
                    var where = $"{target.Name} {key}";
                    var path = Path.Combine(target.Path, key);
                    if (services.Files.Stat(path) is not { Kind: EntryKind.File })
                    {
                        problems.Add($"{where}: no such file on disk");
                        continue;
                    }

                    var value = new SecretValue(services.Files.Read(path));
                    if (value.Problem() is { } problem)
                    {
                        problems.Add($"{where}: the file {problem}");
                    }

                    var same = found.FirstOrDefault(other => other.Reference == reference.BundleKey);
                    if (same.Value is not null && !same.Value.ContentEquals(value.Reveal()))
                    {
                        problems.Add($"{where} and {same.Where} share {reference.BundleKey} but hold different content");
                    }

                    found.Add((reference.BundleKey, where, value));
                }
            }

            if (Report(problems))
            {
                return Refused;
            }

            using var recipient = HostKey.LoadPublic(context.Profile.BundleRecipientPath);
            using var host = bundle.Entries.Count > 0 ? HostKey.LoadPrivate(context.Profile.BundleKeyPath) : null;
            var perReference = found.DistinctBy(item => item.Reference).ToList();
            foreach (var (reference, _, value) in perReference)
            {
                if (bundle.Find(reference) is { } entry && host is not null)
                {
                    using var current = BundleSeal.Open(host, bundle, entry);
                    if (current.ContentEquals(value.Reveal()))
                    {
                        services.Out.WriteLine($"unchanged  {reference}");
                        continue;
                    }
                }

                bundle.Set(BundleSeal.Seal(recipient, bundle, reference, value, services.Clock.GetUtcNow()));
                services.Out.WriteLine($"imported   {reference}");
            }

            // Settles, by name only, which references are really one secret: candidates to collapse at the flip.
            foreach (var group in perReference.GroupBy(item => Convert.ToHexString(SHA256.HashData(item.Value.Reveal()))).Where(group => group.Count() > 1))
            {
                services.Out.WriteLine($"identical  {string.Join(" = ", group.Select(item => item.Reference).Order(StringComparer.Ordinal))}");
            }

            bundle.Save(context.BundlePath);
            return Ok;
        }
        finally
        {
            foreach (var item in found)
            {
                item.Value.Dispose();
            }
        }
    }

    /// <summary>
    /// Brings the bundle in step with the server: every reference of the manifest whose version there differs from
    /// the one in the bundle is read (an audited read, under this host's key) and sealed for this host. Nothing is
    /// written unless every reference could be had.
    /// </summary>
    private int BundlePull(Arguments arguments)
    {
        var context = Load(arguments);
        if (!context.Profile.UsesServer)
        {
            throw new InputException($"bundle pull reads from the server: put 'api' in 'providers' in {HostProfile.FileName}, with 'server' and 'server_key'");
        }

        var bundle = Bundle.LoadOrEmpty(context.BundlePath, context.Profile.Host, context.Manifest.Stack);
        using var recipient = HostKey.LoadPublic(context.Profile.BundleRecipientPath);
        var problems = new List<string>();
        var sealedEntries = new List<BundleEntry>();
        var unchanged = new List<string>();
        try
        {
            using var source = new ServerSource(services.Server(context.Profile));
            foreach (var reference in context.Manifest.References.DistinctBy(reference => reference.BundleKey).OrderBy(reference => reference.BundleKey, StringComparer.Ordinal))
            {
                if (source.Find(reference, reference.BundleKey, problems) is not { } remote)
                {
                    continue;
                }

                var version = remote.Version.ToString(System.Globalization.CultureInfo.InvariantCulture);
                if (bundle.Find(reference.BundleKey)?.Version == version)
                {
                    unchanged.Add(reference.BundleKey);
                    continue;
                }

                if (Checked(source, reference, reference.BundleKey, problems) is { } value)
                {
                    using (value)
                    {
                        sealedEntries.Add(BundleSeal.Seal(recipient, bundle, reference.BundleKey, value, services.Clock.GetUtcNow(), version));
                    }
                }
            }
        }
        catch (ServerUnreachableException e)
        {
            throw new InputException($"the server is not reachable: {e.Message}. Nothing was changed.", e);
        }

        if (Report(problems))
        {
            return Refused;
        }

        foreach (var reference in unchanged)
        {
            services.Out.WriteLine($"unchanged  {reference}");
        }

        foreach (var entry in sealedEntries)
        {
            bundle.Set(entry);
            services.Out.WriteLine($"pulled     {entry.Reference}  version {entry.Version}");
        }

        if (sealedEntries.Count == 0)
        {
            return Ok;
        }

        bundle.Save(context.BundlePath);
        return Changed;
    }

    /// <summary>
    /// Moves a stack onto the server: every secret the manifest names that the server does not have is made there
    /// from the bundle, with the fields the manifest reads. What the server already has is compared and never
    /// overwritten: a difference is a decision for a person, not for a deploy. Everything is looked at before
    /// anything is written, and the bundle is then marked with the server's versions, so it is the fallback at once.
    /// </summary>
    private int BundlePush(Arguments arguments)
    {
        var context = Load(arguments);
        var dryRun = arguments.Has("--dry-run");

        // The host's everyday key only reads. The key that may write is named for this one run and stored nowhere.
        var profile = context.Profile;
        if (arguments.Option("--server-key") is { } keyFile)
        {
            profile = profile with { ServerKeyPath = Path.GetFullPath(keyFile, services.WorkingDirectory) };
        }

        if (profile.Server is null || profile.ServerKeyPath is null)
        {
            throw new InputException($"bundle push writes to the server: name it as 'server' in {HostProfile.FileName}, and pass the file of a key that is Secrets Officer in the vault as --server-key");
        }

        var bundle = Bundle.LoadOrEmpty(context.BundlePath, profile.Host, context.Manifest.Stack);
        var secrets = context.Manifest.References
            .DistinctBy(reference => reference.BundleKey)
            .GroupBy(reference => $"{reference.Vault}/{reference.Name}", StringComparer.Ordinal)
            .OrderBy(secret => secret.Key, StringComparer.Ordinal)
            .Select(secret => secret.OrderBy(reference => reference.Part ?? "", StringComparer.Ordinal).ToList())
            .ToList();

        var problems = new List<string>();
        var opened = new Dictionary<string, SecretValue>(StringComparer.Ordinal);
        var missing = new List<List<SecretReference>>();
        var inStep = new List<(string Reference, int Version)>();
        var created = 0;
        string? stopped = null;
        try
        {
            using var host = HostKey.LoadPrivate(profile.BundleKeyPath);
            var server = services.Server(profile);
            using var source = new ServerSource(server);
            var refusedVaults = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var references in secrets)
                {
                    var complete = true;
                    foreach (var reference in references)
                    {
                        if (bundle.Find(reference.BundleKey) is not { } entry)
                        {
                            problems.Add($"{reference.BundleKey}: is not in the bundle");
                            complete = false;
                            continue;
                        }

                        opened[reference.BundleKey] = BundleSeal.Open(host, bundle, entry);
                    }

                    var secret = references[0];
                    if (refusedVaults.Contains(secret.Vault))
                    {
                        continue;
                    }

                    RemoteSecret? remote;
                    try
                    {
                        remote = source.Held(secret);
                    }
                    catch (InputException e)
                    {
                        refusedVaults.Add(secret.Vault);
                        problems.Add($"{secret.Vault}: {e.Message}");
                        continue;
                    }

                    if (!complete)
                    {
                        continue;
                    }

                    if (remote is null)
                    {
                        if (IsCertificate(references, opened))
                        {
                            // A certificate is made from the parts the bundle holds; the server checks that they are one certificate.
                            var unknown = references.Where(reference => !CertificateParts.Contains(reference.Part ?? "")).Select(reference => reference.BundleKey).ToList();
                            if (unknown.Count > 0)
                            {
                                problems.Add($"{secret.Vault}/{secret.Name}: {string.Join(", ", unknown)} is not a part of a certificate (certificate, chain, key, pfx, pfx-password)");
                            }
                            else
                            {
                                missing.Add(references);
                            }
                        }
                        else if (references[0].Part is not null)
                        {
                            problems.Add($"{secret.Vault}/{secret.Name}: the bundle holds fields of it and no value, and a secret cannot be made without one");
                        }
                        else
                        {
                            missing.Add(references);
                        }

                        continue;
                    }

                    var version = remote.Version.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    foreach (var reference in references)
                    {
                        if (Checked(source, reference with { Version = null }, reference.BundleKey, problems) is not { } theirs)
                        {
                            continue;
                        }

                        using (theirs)
                        {
                            if (opened[reference.BundleKey].ContentEquals(theirs.Reveal()))
                            {
                                inStep.Add((reference.BundleKey, remote.Version));
                            }
                            else
                            {
                                problems.Add($"{reference.BundleKey}: the server holds something else (its version {version}). Nothing is overwritten: settle which one is right, change it on the server if need be, then run bundle pull");
                            }
                        }
                    }
                }

                if (Report(problems))
                {
                    services.Error.WriteLine("nothing was written");
                    return Refused;
                }

                foreach (var (reference, version) in inStep)
                {
                    services.Out.WriteLine($"same       {reference}  version {version.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
                }

                if (dryRun)
                {
                    foreach (var references in missing)
                    {
                        services.Out.WriteLine($"create     {references[0].Vault}/{references[0].Name}{Holds(references, opened)}");
                    }

                    services.Error.WriteLine("dry run: nothing was written");
                    return Ok;
                }

                foreach (var references in missing)
                {
                    var secret = references[0];
                    var description = $"Pushed from the bundle of {context.Manifest.Stack} on {profile.Host}";
                    int version;
                    try
                    {
                        version = IsCertificate(references, opened)
                            ? server.CreateCertificate(secret.Vault, secret.Name, [.. references.Select(reference => KeyValuePair.Create(reference.Part!, opened[reference.BundleKey]))], description)
                            : server.Create(secret.Vault, secret.Name, opened[secret.BundleKey], [.. references.Skip(1).Select(reference => KeyValuePair.Create(reference.Part!, opened[reference.BundleKey]))], description);
                    }
                    catch (InputException e)
                    {
                        stopped = e.Message;
                        break;
                    }

                    created++;
                    inStep.AddRange(references.Select(reference => (reference.BundleKey, version)));
                    services.Out.WriteLine($"created    {secret.Vault}/{secret.Name}  version {version.ToString(System.Globalization.CultureInfo.InvariantCulture)}{Holds(references, opened)}");
                }
            }
            catch (ServerUnreachableException e)
            {
                stopped = $"the server is not reachable: {e.Message}";
            }

            // The bundle now says which version of the server each entry is, so status does not call it stale.
            var marked = false;
            using var recipient = HostKey.LoadPublic(profile.BundleRecipientPath);
            foreach (var (reference, number) in inStep)
            {
                var version = number.ToString(System.Globalization.CultureInfo.InvariantCulture);
                if (bundle.Find(reference)!.Version != version)
                {
                    bundle.Set(BundleSeal.Seal(recipient, bundle, reference, opened[reference], services.Clock.GetUtcNow(), version));
                    marked = true;
                }
            }

            if (marked)
            {
                bundle.Save(context.BundlePath);
            }

            if (stopped is not null)
            {
                services.Error.WriteLine($"refused: {stopped}");
                services.Error.WriteLine($"stopped after {created.ToString(System.Globalization.CultureInfo.InvariantCulture)} of {missing.Count.ToString(System.Globalization.CultureInfo.InvariantCulture)}. Run it again: what was made is compared, not made twice.");
                return Refused;
            }

            return created > 0 || marked ? Changed : Ok;
        }
        finally
        {
            foreach (var value in opened.Values)
            {
                value.Dispose();
            }
        }
    }

    private static readonly HashSet<string> CertificateParts = new(StringComparer.Ordinal) { "certificate", "chain", "key", "pfx", "pfx-password" };

    /// <summary>A certificate in a bundle is a set of parts, each a file: the server hands them out as bytes, never as a text value.</summary>
    private static bool IsCertificate(List<SecretReference> references, Dictionary<string, SecretValue> opened) =>
        references.Any(reference => opened[reference.BundleKey].Binary);

    /// <summary>What goes with the value, in words: the sensitive fields of a secret, or the parts of a certificate.</summary>
    private static string Holds(List<SecretReference> references, Dictionary<string, SecretValue> opened) =>
        IsCertificate(references, opened) ? "  parts: " + string.Join(", ", references.Select(reference => reference.Part))
        : references.Count == 1 ? ""
        : "  fields: " + string.Join(", ", references.Skip(1).Select(reference => reference.Part));

    /// <summary>
    /// Whether the bundle still holds what the server has: the fallback is only as good as its last pull. Compares
    /// versions, never values, and says nothing when there is no server to ask.
    /// </summary>
    private List<string> BundleBehindServer(Context context)
    {
        var findings = new List<string>();
        if (!context.Profile.UsesServer || !context.Profile.UsesBundle)
        {
            return findings;
        }

        try
        {
            var bundle = Bundle.LoadOrEmpty(context.BundlePath, context.Profile.Host, context.Manifest.Stack);
            using var source = new ServerSource(services.Server(context.Profile));
            var ignored = new List<string>();
            foreach (var reference in context.Manifest.References.DistinctBy(reference => reference.BundleKey).OrderBy(reference => reference.BundleKey, StringComparer.Ordinal))
            {
                var held = bundle.Find(reference.BundleKey)?.Version;
                if (source.Find(reference, reference.BundleKey, ignored) is { } remote && held != remote.Version.ToString(System.Globalization.CultureInfo.InvariantCulture))
                {
                    findings.Add($"stale    bundle  {reference.BundleKey}  holds {held ?? "nothing"}, the server has version {remote.Version.ToString(System.Globalization.CultureInfo.InvariantCulture)}");
                }
            }
        }
        catch (Exception e) when (e is ServerUnreachableException or InputException)
        {
            services.Error.WriteLine($"skipped: comparing the bundle with the server ({e.Message})");
        }

        return findings;
    }

    private int BundleSet(Arguments arguments)
    {
        var stack = arguments.Word("the stack");
        var referenceText = arguments.Word("the reference");
        var context = Load(arguments, stack);
        SecretReference reference;
        try
        {
            reference = SecretReference.Parse(referenceText, context.Manifest.DefaultVault);
        }
        catch (InputException e)
        {
            throw new InputException($"the reference {e.Message}", e);
        }

        if (reference.Version is not null)
        {
            throw new InputException("a version cannot be chosen: setting a value makes a new one");
        }

        if (!context.Manifest.References.Any(used => used.BundleKey == reference.BundleKey))
        {
            services.Error.WriteLine($"note: nothing in {context.Manifest.Stack}/{Manifest.FileName} references {reference.BundleKey}");
        }

        using var value = services.ReadValue();
        if (value.Problem() is { } problem)
        {
            throw new InputException($"{reference.BundleKey}: the value {problem}. Pipe it with printf '%s', not echo.");
        }

        var bundle = Bundle.LoadOrEmpty(context.BundlePath, context.Profile.Host, context.Manifest.Stack);
        using var recipient = HostKey.LoadPublic(context.Profile.BundleRecipientPath);
        bundle.Set(BundleSeal.Seal(recipient, bundle, reference.BundleKey, value, services.Clock.GetUtcNow()));
        bundle.Save(context.BundlePath);
        services.Out.WriteLine($"sealed     {reference.BundleKey}");
        return Ok;
    }

    private int BundlePrune(Arguments arguments)
    {
        var context = Load(arguments);
        var bundle = Bundle.LoadOrEmpty(context.BundlePath, context.Profile.Host, context.Manifest.Stack);
        var used = context.Manifest.References.Select(reference => reference.BundleKey).ToHashSet(StringComparer.Ordinal);
        var unused = bundle.Entries.Select(entry => entry.Reference).Where(reference => !used.Contains(reference)).ToList();
        foreach (var reference in unused)
        {
            bundle.Remove(reference);
            services.Out.WriteLine($"removed    {reference}");
        }

        if (unused.Count > 0)
        {
            bundle.Save(context.BundlePath);
        }

        return Ok;
    }

    private int HostKeygen(Arguments arguments)
    {
        arguments.EnsureNoMoreWords();
        var repository = Repository(arguments);
        var profile = HostProfile.Load(repository, arguments.Required("--host"));
        HostKey.Create(profile.BundleKeyPath, profile.BundleRecipientPath);
        services.Out.WriteLine($"private    {profile.BundleKeyPath}  (stays on this host; keep a copy in the password manager)");
        services.Out.WriteLine($"public     {profile.BundleRecipientPath}  (commit this)");
        return Ok;
    }

    private Context Load(Arguments arguments, string? stack = null)
    {
        stack ??= arguments.Word("the stack");
        arguments.EnsureNoMoreWords();
        var repository = Repository(arguments);
        var profile = HostProfile.Load(repository, arguments.Required("--host"));
        var manifest = Manifest.Load(repository, stack, profile);
        return new Context(profile, manifest, Path.Combine(repository, stack, Manifest.BundleFileName));
    }

    private string Repository(Arguments arguments) =>
        Path.GetFullPath(arguments.Option("--repo") ?? Environment.GetEnvironmentVariable("SECRETHIVE_REPO") ?? services.WorkingDirectory);

    private void RequireHostAccess()
    {
        if (services.HostAccessProblem is { } problem)
        {
            throw new InputException(problem);
        }
    }

    /// <summary>Resolves and checks every key of the given targets. Nothing has been written when this returns.</summary>
    private ResolvedStack Resolve(Context context, IReadOnlyList<Target> targets, out List<string> problems)
    {
        problems = [];
        var resolved = new ResolvedStack();
        using var source = OpenSource(context, [.. targets.SelectMany(target => target.Keys.Select(pair => pair.Value))]);
        foreach (var target in targets)
        {
            var lines = new List<KeyValuePair<string, SecretValue>>();
            foreach (var (name, reference) in target.Keys)
            {
                if (Checked(source, reference, $"{target.Name} {name}", problems) is not { } value)
                {
                    continue;
                }

                if (target.EnvFile)
                {
                    lines.Add(new(name, value));
                }
                else
                {
                    resolved.Add(target.Name, name, value);
                }
            }

            // An env target is one file made of all its keys: put together here, so everything after this sees a
            // file like any other.
            if (target.EnvFile)
            {
                resolved.Add(target.Name, Target.EnvFileName, EnvFileContent.Compose(lines, target.Name, problems));
                foreach (var line in lines)
                {
                    line.Value.Dispose();
                }
            }
        }

        return resolved;
    }

    /// <summary>
    /// Where this run reads from: the server when the profile names it and it answers, otherwise the bundle. Decided
    /// once, before anything is read, so one run never mixes the two. The server saying no is not "does not answer":
    /// a refusal is reported and the bundle is not used to get around it.
    /// </summary>
    private ValueSource OpenSource(Context context, IReadOnlyList<SecretReference> references)
    {
        if (context.Profile.UsesServer)
        {
            var source = new ServerSource(services.Server(context.Profile));
            try
            {
                if (references.Count > 0)
                {
                    source.Probe(references[0].Vault);
                }

                return source;
            }
            catch (ServerUnreachableException e)
            {
                source.Dispose();
                if (!context.Profile.UsesBundle)
                {
                    throw new InputException($"the server is not reachable ({e.Message}), and this host has no bundle to fall back on", e);
                }

                services.Error.WriteLine($"fallback bundle  {context.Manifest.Stack}: {e.Message}");
            }
            catch
            {
                source.Dispose();
                throw;
            }
        }

        return new BundleSource(Bundle.LoadOrEmpty(context.BundlePath, context.Profile.Host, context.Manifest.Stack), HostKey.LoadPrivate(context.Profile.BundleKeyPath));
    }

    /// <summary>A value from the source, refused when it is empty or has whitespace at its edges: that is a mistake wherever it came from.</summary>
    private static SecretValue? Checked(ValueSource source, SecretReference reference, string where, List<string> problems)
    {
        SecretValue? value;
        try
        {
            value = source.Get(reference, where, problems);
        }
        catch (InputException e)
        {
            problems.Add($"{where}: {e.Message}");
            return null;
        }
        catch (ServerUnreachableException e)
        {
            // It answered a moment ago. Not a reason to switch source halfway through a run.
            problems.Add($"{where}: the server stopped answering ({e.Message})");
            return null;
        }

        if (value?.Problem() is { } problem)
        {
            problems.Add($"{where}: the value of {reference.BundleKey} {problem}");
            value.Dispose();
            return null;
        }

        return value;
    }

    private abstract class ValueSource : IDisposable
    {
        /// <summary>The value, or null with a line added to <paramref name="problems"/> saying why not.</summary>
        public abstract SecretValue? Get(SecretReference reference, string where, List<string> problems);

        public abstract void Dispose();
    }

    private sealed class BundleSource(Bundle bundle, RSA key) : ValueSource
    {
        public override SecretValue? Get(SecretReference reference, string where, List<string> problems)
        {
            if (bundle.Find(reference.BundleKey) is not { } entry)
            {
                problems.Add($"{where}: {reference.BundleKey} is not in the bundle");
                return null;
            }

            if (reference.Version is not null && reference.Version != entry.Version)
            {
                problems.Add($"{where}: {reference} is pinned, the bundle holds version {entry.Version}");
                return null;
            }

            return BundleSeal.Open(key, bundle, entry);
        }

        public override void Dispose() => key.Dispose();
    }

    private sealed class ServerSource(ISecretServer server) : ValueSource
    {
        // What each vault holds, asked once per run: names and versions, no value.
        private readonly Dictionary<string, IReadOnlyDictionary<string, RemoteSecret>> _vaults = new(StringComparer.OrdinalIgnoreCase);

        public void Probe(string vault) => Names(vault);

        /// <summary>What the server has under the name of a reference, or null when it has nothing there. Not a problem either way.</summary>
        public RemoteSecret? Held(SecretReference reference) => Names(reference.Vault).GetValueOrDefault(reference.Name);

        /// <summary>What the server has under a reference, or null with the reason added to <paramref name="problems"/>.</summary>
        public RemoteSecret? Find(SecretReference reference, string where, List<string> problems)
        {
            IReadOnlyDictionary<string, RemoteSecret> names;
            try
            {
                names = Names(reference.Vault);
            }
            catch (InputException e)
            {
                problems.Add($"{where}: {e.Message}");
                return null;
            }

            if (!names.TryGetValue(reference.Name, out var remote))
            {
                problems.Add($"{where}: {reference.Vault}/{reference.Name} is not on the server");
                return null;
            }

            // A pinned reference is answered with exactly that version: it has to be a number the secret has reached.
            if (reference.Version is not null)
            {
                if (!int.TryParse(reference.Version, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var pinned) || pinned < 1 || pinned > remote.Version)
                {
                    problems.Add($"{where}: {reference} is pinned to a version the server does not have (its current version is {remote.Version.ToString(System.Globalization.CultureInfo.InvariantCulture)})");
                    return null;
                }

                return remote with { Version = pinned };
            }

            return remote;
        }

        public override SecretValue? Get(SecretReference reference, string where, List<string> problems)
        {
            if (Find(reference, where, problems) is not { } remote)
            {
                return null;
            }

            var value = server.Read(reference, remote.Certificate);
            if (value is null)
            {
                problems.Add($"{where}: {reference.BundleKey} is not on the server{(reference.Part is null ? "" : $" ({reference.Vault}/{reference.Name} has no '{reference.Part}')")}");
            }

            return value;
        }

        public override void Dispose() => server.Dispose();

        private IReadOnlyDictionary<string, RemoteSecret> Names(string vault)
        {
            if (!_vaults.TryGetValue(vault, out var names))
            {
                _vaults[vault] = names = server.List(vault);
            }

            return names;
        }
    }

    private bool Report(List<string> problems)
    {
        foreach (var problem in problems)
        {
            services.Error.WriteLine($"refused: {problem}");
        }

        return problems.Count > 0;
    }

    private static string Verb(ChangeKind kind) => kind switch
    {
        ChangeKind.Created => "created",
        ChangeKind.Changed => "changed",
        ChangeKind.Fixed => "fixed",
        ChangeKind.Pruned => "pruned",
        _ => "foreign",
    };

    private sealed record Context(HostProfile Profile, Manifest Manifest, string BundlePath);
}
