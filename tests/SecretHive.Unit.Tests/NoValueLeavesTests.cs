using System.Runtime.CompilerServices;

namespace SecretHive.Unit.Tests;

/// <summary>
/// The scan the project requires: a value can only leave a <c>SecretValue</c> (the command) or a <c>SecretBytes</c>
/// (the server) through <c>Reveal()</c>, and only the console is an output. Both are confined to a short list of
/// files, so a new log line that carries a value cannot be added without changing this test.
/// </summary>
public sealed class NoValueLeavesTests
{
    private static readonly string[] MayReveal =
    [
        "SecretValue.cs",    // defines it
        "BundleSeal.cs",     // encrypts it
        "Renderer.cs",       // writes it to its target file
        "App.cs",            // compares it with a file, and hands it to a child's environment in `run`
        "SecretServer.cs",   // sends it to the server in the body of a request, for `bundle push`
    ];

    private static readonly string[] MayRevealOnTheServer =
    [
        "SecretBytes.cs",            // defines it
        "SecretService.cs",          // carries a sensitive field from one version to the next, and seals it again
        "SecretService.Links.cs",    // seals a copy under a key of its own
        "SecretService.Versions.cs", // seals an earlier version again as a new one
        "ApiEndpoints.cs",           // writes it into the response, as bytes
        "OnePasswordConnectEndpoints.cs", // the same, as the fields of an item, for a tool that reads only that way
        "SecretPage.razor",          // shows it after a reveal, which is the audited read
        "SecretPanel.razor",         // the same, in the panel beside a vault's list
        "VaultPage.razor",           // hands it to the clipboard after a copy from the list, which is the audited read
    ];

    private static readonly string[] MayUseConsole = ["Program.cs"];

    [Fact]
    public void Reveal_is_called_only_where_a_value_has_to_be_used() =>
        Assert.Equal(MayReveal.Order(StringComparer.Ordinal), FilesContaining(CommandRoot(), ".Reveal()", "Reveal() =>"));

    [Fact]
    public void On_the_server_too_a_value_is_revealed_only_where_it_has_to_be() =>
        Assert.Equal(
            MayReveal.Concat(MayRevealOnTheServer).Order(StringComparer.Ordinal),
            FilesContaining(SourceRoot(), ".Reveal()", "Reveal() =>"));

    [Fact]
    public void Nothing_in_the_source_touches_the_console_but_the_commands_entry_point() =>
        Assert.Equal(MayUseConsole, FilesContaining(SourceRoot(), "Console."));

    [Fact]
    public void No_output_line_in_the_commands_is_built_from_a_value()
    {
        // Every line a command writes goes through services.Out or services.Error. None of those statements
        // may mention Reveal, a decoded string, or the bytes read from a file.
        var source = File.ReadAllLines(Path.Combine(CommandRoot(), "Commands", "App.cs"));
        var writes = source.Where(line => line.Contains("WriteLine", StringComparison.Ordinal));

        Assert.All(writes, line =>
        {
            Assert.DoesNotContain("Reveal", line, StringComparison.Ordinal);
            Assert.DoesNotContain("GetString", line, StringComparison.Ordinal);
            Assert.DoesNotContain("Read(", line, StringComparison.Ordinal);
        });

        // A value that was put into a variable first would pass the check above. So what a revealed value may be
        // used for in the commands is closed too: compared, hashed, or handed to the child's environment in `run`.
        var revealed = source.Where(line => line.Contains("Reveal()", StringComparison.Ordinal)).ToList();
        Assert.NotEmpty(revealed);
        Assert.All(revealed, line => Assert.True(
            line.Contains("ContentEquals(", StringComparison.Ordinal)
            || line.Contains("SHA256.HashData(", StringComparison.Ordinal)
            || line.Contains("start.Environment[variable] =", StringComparison.Ordinal),
            line.Trim()));
        var decoded = source.Where(line => line.Contains("GetString(", StringComparison.Ordinal)).ToList();
        Assert.Contains("start.Environment[variable] =", Assert.Single(decoded), StringComparison.Ordinal);
    }

    private static IEnumerable<string> FilesContaining(string root, params string[] needles) =>
        Directory.EnumerateFiles(root, "*.cs", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(root, "*.razor", SearchOption.AllDirectories))
            .Where(path => !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}", StringComparison.Ordinal))
            .Where(path => needles.Any(needle => File.ReadAllText(path).Contains(needle, StringComparison.Ordinal)))
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)!;

    private static string CommandRoot([CallerFilePath] string here = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", "..", "src", "SecretHive.Cli"));

    private static string SourceRoot([CallerFilePath] string here = "") =>
        Path.GetFullPath(Path.Combine(Path.GetDirectoryName(here)!, "..", "..", "src"));
}
