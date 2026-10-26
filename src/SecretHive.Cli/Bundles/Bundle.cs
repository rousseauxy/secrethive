using System.Buffers;
using System.Text;
using System.Text.Json;

namespace SecretHive.Cli.Bundles;

/// <summary>One sealed value. Everything here is safe to commit; only the host's private key opens it.</summary>
internal sealed record BundleEntry(string Reference, string Version, string SealedAt, byte[] WrappedKey, byte[] Nonce, byte[] Ciphertext, byte[] Tag, bool Binary = false);

/// <summary>
/// A stack's secrets sealed for one host: a header line, then one line per reference, sorted, so a diff in git
/// shows which names changed and nothing else.
/// </summary>
internal sealed class Bundle
{
    private const int FormatVersion = 1;

    private readonly SortedDictionary<string, BundleEntry> _entries = new(StringComparer.Ordinal);

    public Bundle(string host, string stack)
    {
        Host = host;
        Stack = stack;
    }

    public string Host { get; }

    public string Stack { get; }

    public IReadOnlyCollection<BundleEntry> Entries => _entries.Values;

    public BundleEntry? Find(string reference) => _entries.GetValueOrDefault(reference);

    public void Set(BundleEntry entry) => _entries[entry.Reference] = entry;

    public bool Remove(string reference) => _entries.Remove(reference);

    /// <summary>Loads the bundle of a stack, or starts an empty one when the file does not exist yet.</summary>
    public static Bundle LoadOrEmpty(string path, string host, string stack)
    {
        if (!File.Exists(path))
        {
            return new Bundle(host, stack);
        }

        var lines = File.ReadAllLines(path, Encoding.UTF8).Where(line => line.Length > 0).ToList();
        try
        {
            if (lines.Count == 0)
            {
                throw new InputException($"{path}: empty file");
            }

            using var header = JsonDocument.Parse(lines[0]);
            if (header.RootElement.GetProperty("secrethive-bundle").GetInt32() != FormatVersion)
            {
                throw new InputException($"{path}: only bundle format {FormatVersion} is understood");
            }

            var bundle = new Bundle(header.RootElement.GetProperty("host").GetString()!, header.RootElement.GetProperty("stack").GetString()!);
            if (bundle.Host != host || bundle.Stack != stack)
            {
                throw new InputException($"{path}: sealed for {bundle.Host}/{bundle.Stack}, not for {host}/{stack}");
            }

            foreach (var line in lines.Skip(1))
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                bundle.Set(new BundleEntry(
                    root.GetProperty("ref").GetString()!,
                    root.GetProperty("version").GetString()!,
                    root.GetProperty("sealed").GetString()!,
                    root.GetProperty("key").GetBytesFromBase64(),
                    root.GetProperty("nonce").GetBytesFromBase64(),
                    root.GetProperty("data").GetBytesFromBase64(),
                    root.GetProperty("tag").GetBytesFromBase64(),
                    root.TryGetProperty("binary", out var binary) && binary.GetBoolean()));
            }

            return bundle;
        }
        catch (Exception e) when (e is JsonException or KeyNotFoundException or FormatException or InvalidOperationException)
        {
            throw new InputException($"{path}: not a bundle ({e.GetType().Name})", e);
        }
    }

    public void Save(string path)
    {
        var text = new StringBuilder();
        text.Append(Line(writer =>
        {
            writer.WriteNumber("secrethive-bundle", FormatVersion);
            writer.WriteString("host", Host);
            writer.WriteString("stack", Stack);
        }));
        foreach (var entry in _entries.Values)
        {
            text.Append(Line(writer =>
            {
                writer.WriteString("ref", entry.Reference);
                writer.WriteString("version", entry.Version);
                writer.WriteString("sealed", entry.SealedAt);
                writer.WriteBase64String("key", entry.WrappedKey);
                writer.WriteBase64String("nonce", entry.Nonce);
                writer.WriteBase64String("data", entry.Ciphertext);
                writer.WriteBase64String("tag", entry.Tag);

                // Only said when true: a part of a certificate, which is a file and not a line of text.
                if (entry.Binary)
                {
                    writer.WriteBoolean("binary", true);
                }
            }));
        }

        // Replaced in one step so an interrupted save never leaves half a bundle in the checkout.
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, text.ToString(), new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
        File.Move(temporary, path, overwrite: true);
    }

    private static string Line(Action<Utf8JsonWriter> write)
    {
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            write(writer);
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(buffer.WrittenSpan) + "\n";
    }
}
