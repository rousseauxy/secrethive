using System.Diagnostics;
using System.Globalization;

namespace SecretHive.Cli.Rendering;

/// <summary>A running container, as far as secrets are concerned: when it started and who it runs as.</summary>
internal sealed record ContainerState(DateTimeOffset StartedAt, uint Uid);

internal interface IContainerRuntime
{
    /// <summary>Null when the container does not exist or is not running.</summary>
    ContainerState? Running(string container);
}

/// <summary>
/// Asks the docker command line. The uid is read from the container's main process on the host, not with
/// <c>docker exec id</c>: an image without a shell has no <c>id</c> to run.
/// </summary>
internal sealed class DockerCli(IReadOnlyList<string> command) : IContainerRuntime
{
    public ContainerState? Running(string container)
    {
        var start = new ProcessStartInfo(command[0])
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        foreach (var argument in command.Skip(1).Concat(["inspect", "--format", "{{.State.Running}} {{.State.StartedAt}} {{.State.Pid}}", container]))
        {
            start.ArgumentList.Add(argument);
        }

        using var process = Start(start);
        var output = process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        process.WaitForExit();

        var fields = output.Trim().Split(' ');
        if (process.ExitCode != 0 || fields.Length != 3 || fields[0] != "true")
        {
            return null;
        }

        var started = DateTimeOffset.Parse(fields[1], CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal);
        return new ContainerState(started, ProcessUid(fields[2], container));
    }

    // A host without the container runtime is refused by name. Treating it as "no container is running" would
    // let check and status pass without having looked.
    private Process Start(ProcessStartInfo start)
    {
        try
        {
            return Process.Start(start) ?? throw new InputException($"'{command[0]}' could not be started");
        }
        catch (System.ComponentModel.Win32Exception e)
        {
            throw new InputException($"'{command[0]}' could not be started, so the containers cannot be inspected", e);
        }
    }

    private static uint ProcessUid(string pid, string container)
    {
        // "Uid:\treal\teffective\tsaved\tfilesystem"; the effective uid is the one that opens files.
        try
        {
            var line = File.ReadLines($"/proc/{pid}/status").First(candidate => candidate.StartsWith("Uid:", StringComparison.Ordinal));
            return uint.Parse(line.Split('\t', StringSplitOptions.RemoveEmptyEntries)[2], CultureInfo.InvariantCulture);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or InvalidOperationException or FormatException)
        {
            // The runtime knows the container, and its process is not in the process list this command sees: it runs
            // inside a container of its own. Said in words, because "which user runs it" cannot be answered here.
            throw new InputException(
                $"the process of container '{container}' cannot be seen from here (/proc/{pid}), so which user it runs as cannot be checked. " +
                "Run this on the host, or in a container that shares the host's process list (docker run --pid host).",
                e);
        }
    }
}
