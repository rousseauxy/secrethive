using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace SecretHive.Cli.Hosting;

/// <summary>
/// A YAML mapping read strictly: every key has to be asked for, and one that is left over is an error. A
/// misspelt <c>owner</c> that silently falls back to a default is exactly the mistake this tool exists to prevent.
/// </summary>
internal sealed class YamlMap
{
    private readonly Dictionary<string, YamlNode> _nodes = new(StringComparer.Ordinal);
    private readonly List<string> _order = [];
    private readonly HashSet<string> _taken = new(StringComparer.Ordinal);
    private readonly string _where;

    private YamlMap(YamlMappingNode node, string where)
    {
        _where = where;
        foreach (var (key, value) in node.Children)
        {
            var name = key is YamlScalarNode { Value: { } text } ? text : throw new InputException($"{where}: a key is not plain text");
            if (!_nodes.TryAdd(name, value))
            {
                throw new InputException($"{where}: '{name}' appears twice");
            }

            _order.Add(name);
        }
    }

    public IReadOnlyList<string> Keys => _order;

    public static YamlMap Load(string path)
    {
        var stream = new YamlStream();
        try
        {
            using var reader = new StreamReader(path);
            stream.Load(reader);
        }
        catch (IOException e)
        {
            throw new InputException($"{path}: cannot be read ({e.GetType().Name})", e);
        }
        catch (YamlException e)
        {
            // The message of a YAML error can quote the offending text; the position is enough.
            throw new InputException($"{path}: not valid YAML at line {e.Start.Line}", e);
        }

        if (stream.Documents.Count != 1 || stream.Documents[0].RootNode is not YamlMappingNode root)
        {
            throw new InputException($"{path}: expected one YAML document holding a mapping");
        }

        return new YamlMap(root, Path.GetFileName(path));
    }

    public string Text(string key) => OptionalText(key) ?? throw new InputException($"{_where}: '{key}' is missing");

    public string? OptionalText(string key)
    {
        if (!_nodes.TryGetValue(key, out var node))
        {
            return null;
        }

        _taken.Add(key);
        return node is YamlScalarNode { Value: { Length: > 0 } text } ? text : throw new InputException($"{_where}: '{key}' must be a non-empty text value");
    }

    public IReadOnlyList<string> TextList(string key)
    {
        if (!_nodes.TryGetValue(key, out var node))
        {
            return [];
        }

        _taken.Add(key);
        if (node is not YamlSequenceNode sequence)
        {
            throw new InputException($"{_where}: '{key}' must be a list");
        }

        return [.. sequence.Children.Select(child => child is YamlScalarNode { Value: { Length: > 0 } text }
            ? text
            : throw new InputException($"{_where}: '{key}' must be a list of text values"))];
    }

    public YamlMap? Map(string key)
    {
        if (!_nodes.TryGetValue(key, out var node))
        {
            return null;
        }

        _taken.Add(key);
        return node is YamlMappingNode mapping ? new YamlMap(mapping, $"{_where}: {key}") : throw new InputException($"{_where}: '{key}' must be a mapping");
    }

    /// <summary>Call after everything expected was read.</summary>
    public void EnsureNothingElse()
    {
        var unknown = _order.Where(key => !_taken.Contains(key)).ToList();
        if (unknown.Count > 0)
        {
            throw new InputException($"{_where}: unknown key '{string.Join("', '", unknown)}'");
        }
    }
}
