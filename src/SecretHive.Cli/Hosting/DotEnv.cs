namespace SecretHive.Cli.Hosting;

/// <summary>
/// Reads the values a stack keeps in its <c>.env</c> today, to take them out of it. Only what is unmistakable is
/// read: a plain value, or one in single or double quotes with nothing in it that Compose would rewrite. Anything
/// else is refused by name, so no value is stored that differs from what the container gets now.
/// </summary>
internal static class DotEnv
{
    /// <summary>
    /// The value of each of the wanted names, as the bytes Compose hands to a container, or for a name that cannot
    /// be taken as it is, the reason why. A name the file does not have is in neither.
    /// </summary>
    public static (Dictionary<string, SecretValue> Values, Dictionary<string, string> Refused) Read(string path, IReadOnlyCollection<string> wanted)
    {
        var values = new Dictionary<string, SecretValue>(StringComparer.Ordinal);
        var refused = new Dictionary<string, string>(StringComparer.Ordinal);
        var bytes = File.ReadAllBytes(path);
        try
        {
            var start = 0;
            while (start < bytes.Length)
            {
                var end = Array.IndexOf(bytes, (byte)'\n', start);
                end = end < 0 ? bytes.Length : end;
                Line(bytes.AsSpan(start, end - start), wanted, values, refused);
                start = end + 1;
            }
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
        }

        return (values, refused);
    }

    private static void Line(ReadOnlySpan<byte> line, IReadOnlyCollection<string> wanted, Dictionary<string, SecretValue> values, Dictionary<string, string> refused)
    {
        line = line.Trim((byte)' ').TrimEnd((byte)'\r');
        if (line.StartsWith("export "u8))
        {
            line = line[7..].TrimStart((byte)' ');
        }

        var equals = line.IndexOf((byte)'=');
        if (line.IsEmpty || line[0] == (byte)'#' || equals <= 0)
        {
            return;
        }

        var name = System.Text.Encoding.ASCII.GetString(line[..equals].TrimEnd((byte)' '));
        if (!wanted.Contains(name))
        {
            return;
        }

        // A name given twice: Compose takes the last one, so does this.
        if (values.Remove(name, out var earlier))
        {
            earlier.Dispose();
        }

        refused.Remove(name);
        var raw = line[(equals + 1)..].Trim((byte)' ');
        ReadOnlySpan<byte> value;
        if (raw.Length >= 2 && raw[0] == (byte)'\'' && raw[^1] == (byte)'\'')
        {
            value = raw[1..^1];
            if (value.Contains((byte)'\''))
            {
                refused[name] = "has a quote inside its quotes";
                return;
            }
        }
        else if (raw.Length >= 2 && raw[0] == (byte)'"' && raw[^1] == (byte)'"')
        {
            value = raw[1..^1];
            if (value.IndexOfAny((byte)'$', (byte)'\\', (byte)'"') >= 0)
            {
                refused[name] = "is in double quotes with a $, a backslash or a quote inside, which Compose rewrites";
                return;
            }
        }
        else
        {
            value = raw;

            // Unquoted, Compose substitutes $NAME and ends the value at " #". Neither is guessed at here.
            if (value.IndexOfAny((byte)'$', (byte)'\'', (byte)'"') >= 0 || value.IndexOf(" #"u8) >= 0)
            {
                refused[name] = "is unquoted with a $, a quote or a comment in it, which Compose may read differently";
                return;
            }
        }

        if (value.IsEmpty)
        {
            refused[name] = "is empty";
            return;
        }

        values[name] = new SecretValue(value.ToArray());
    }
}
