namespace SecretHive.Cli.Commands;

/// <summary>
/// The command line, split into positional words, options and whatever follows <c>--</c>. There is no option that
/// takes a secret, by construction: values only ever arrive on standard input or from a prompt.
/// </summary>
internal sealed class Arguments
{
    private static readonly HashSet<string> Flags = new(StringComparer.Ordinal) { "--dry-run" };
    private static readonly HashSet<string> Valued = new(StringComparer.Ordinal) { "--host", "--repo", "--target", "--server-key" };

    private readonly Dictionary<string, string> _options = new(StringComparer.Ordinal);
    private readonly Queue<string> _words = new();

    public Arguments(IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];
            if (arg == "--")
            {
                Rest = [.. args.Skip(i + 1)];
                break;
            }

            if (Flags.Contains(arg))
            {
                _options[arg] = "";
            }
            else if (Valued.Contains(arg))
            {
                _options[arg] = ++i < args.Count ? args[i] : throw new InputException($"{arg} needs a value");
            }
            else if (arg.StartsWith('-'))
            {
                throw new InputException($"unknown option {arg}");
            }
            else
            {
                _words.Enqueue(arg);
            }
        }
    }

    public IReadOnlyList<string> Rest { get; } = [];

    public bool Has(string flag) => _options.ContainsKey(flag);

    public string? Option(string name) => _options.GetValueOrDefault(name);

    public string Required(string name) => Option(name) ?? throw new InputException($"{name} is required");

    public string? NextWord() => _words.TryDequeue(out var word) ? word : null;

    public string Word(string what) => NextWord() ?? throw new InputException($"{what} is missing");

    public void EnsureNoMoreWords()
    {
        if (_words.TryPeek(out var extra))
        {
            throw new InputException($"unexpected '{extra}'");
        }
    }
}
