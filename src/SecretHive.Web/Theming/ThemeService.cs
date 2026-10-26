using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using YamlDotNet.Core;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace SecretHive.Web.Theming;

/// <summary>One theme, as a chooser needs to know it.</summary>
public sealed record ThemeSummary(string Name, string Label, string? Description);

/// <summary>What the top bar shows for a theme: the name, and the logo's address when the pack has one.</summary>
public sealed record ThemeBrand(string Title, string? LogoUrl, string LogoAlt, bool HideTitle, string? FaviconUrl = null)
{
    public static readonly ThemeBrand Default = new("SecretHive", null, "SecretHive", HideTitle: false);
}

public interface IThemeService
{
    /// <summary>Every theme found, by label.</summary>
    IReadOnlyList<ThemeSummary> Packs { get; }

    /// <summary>The compiled stylesheet and its entity tag, or null when no such theme exists.</summary>
    (string Css, string ETag)? GetCss(string name);

    ThemePack? GetPack(string name);

    /// <summary>The brand of a theme, or the default one when there is no such theme or it names no brand.</summary>
    ThemeBrand GetBrand(string? name);

    /// <summary>
    /// A file a pack's branding names, to serve: its path and content type. Null for anything else - a file the pack does
    /// not name is never served, whatever sits in the directory.
    /// </summary>
    (string Path, string ContentType)? GetAsset(string name, string file);

    /// <summary>Re-reads the themes directory, so a pack can be added or edited without a restart.</summary>
    void Reload();

    /// <summary>Where an operator's own packs are read from.</summary>
    string OperatorDirectory { get; }
}

/// <summary>
/// Which pack is in use, for everyone: read from the settings when the server starts and changed on the appearance
/// page. Kept here so drawing a page does not ask the database what it looks like.
/// </summary>
public sealed class ThemeChoice
{
    public const string SettingKey = "appearance.theme";

    private volatile string? name;

    /// <summary>The chosen pack, or null for the built-in look.</summary>
    public string? Name
    {
        get => name;
        set => name = string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}

/// <summary>
/// Loads theme packs (<c>*.yaml</c>) and compiles each into a small stylesheet of custom-property
/// overrides, served after <c>app.css</c>. The base stylesheet defines every token with a default, so a
/// pack that sets three colours is a valid theme and everything it does not mention still looks right.
///
/// YAML rather than JSON, and the same token names as the theme format it came from, so one pack can be
/// dropped into either without editing: a brand is defined once, not once per product.
/// </summary>
public sealed partial class ThemeService : IThemeService
{
    private static readonly IDeserializer Yaml = new DeserializerBuilder()
        .WithNamingConvention(CamelCaseNamingConvention.Instance)
        // A pack written for that other application carries keys this one has no use for, such as its
        // branding block. Those are ignored rather than refused, which is what makes packs portable.
        .IgnoreUnmatchedProperties()
        .Build();

    // The packs that ship with the server, then the operator's own folder, which wins when both have a name.
    private readonly string[] directories;
    private readonly Dictionary<string, string> origins = new(StringComparer.OrdinalIgnoreCase);
    private readonly ILogger<ThemeService> logger;
    private readonly ConcurrentDictionary<string, (ThemePack Pack, string Css, string ETag)> packs =
        new(StringComparer.OrdinalIgnoreCase);

    public ThemeService(IWebHostEnvironment environment, IConfiguration configuration, ILogger<ThemeService> logger)
    {
        ArgumentNullException.ThrowIfNull(environment);
        ArgumentNullException.ThrowIfNull(configuration);
        this.logger = logger;
        // An empty setting means "not set": the folder "themes" in the data folder, which is where an operator can
        // put a file without rebuilding an image.
        var configured = configuration["SecretHive:Theming:Path"];
        var own = string.IsNullOrWhiteSpace(configured)
            ? Path.Combine(configuration["SecretHive:DataDirectory"] ?? "/data", "themes")
            : configured;
        directories = [Path.Combine(environment.WebRootPath ?? "wwwroot", "themes"), own];
        OperatorDirectory = own;
        Reload();
    }

    /// <summary>Where an operator's own packs are read from.</summary>
    public string OperatorDirectory { get; }

    public IReadOnlyList<ThemeSummary> Packs =>
        [.. packs.Values
            .Select(entry => new ThemeSummary(entry.Pack.Name, entry.Pack.Label ?? entry.Pack.Name, entry.Pack.Description))
            .OrderBy(summary => summary.Label, StringComparer.OrdinalIgnoreCase)];

    public (string Css, string ETag)? GetCss(string name) =>
        packs.TryGetValue(name, out var entry) ? (entry.Css, entry.ETag) : null;

    public ThemePack? GetPack(string name) => packs.TryGetValue(name, out var entry) ? entry.Pack : null;

    /// <summary>The largest logo served. A logo is kilobytes; anything near this is a mistake worth refusing.</summary>
    public const long MaxAssetBytes = 1024 * 1024;

    private static readonly Dictionary<string, string> AssetTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        [".svg"] = "image/svg+xml",
        [".png"] = "image/png",
        [".webp"] = "image/webp",
        [".jpg"] = "image/jpeg",
        [".jpeg"] = "image/jpeg",
        [".gif"] = "image/gif",
    };

    public ThemeBrand GetBrand(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) || !packs.TryGetValue(name, out var entry) || entry.Pack.Branding is not { } branding)
        {
            return ThemeBrand.Default;
        }

        var title = string.IsNullOrWhiteSpace(branding.TitlePlain) ? ThemeBrand.Default.Title : branding.TitlePlain.Trim();
        var logo = ImageUrl(entry.Pack.Name, branding.Logo, "logo");
        var favicon = ImageUrl(entry.Pack.Name, branding.Favicon, "favicon") ?? logo;
        var alt = string.IsNullOrWhiteSpace(branding.LogoAlt) ? title : branding.LogoAlt.Trim();
        return new ThemeBrand(title, logo, alt, branding.HideTitle && logo is not null, favicon);
    }

    /// <summary>Where a branding image is fetched from: a data: URL as it is, a file next to the pack through the assets endpoint.</summary>
    private string? ImageUrl(string pack, string? configured, string what)
    {
        var value = configured?.Trim();
        if (string.IsNullOrEmpty(value))
        {
            return null;
        }

        if (value.StartsWith("data:image/", StringComparison.OrdinalIgnoreCase))
        {
            return value;
        }

        if (IsPlainFileName(value) && AssetTypes.ContainsKey(Path.GetExtension(value)))
        {
            return $"/themes/{Uri.EscapeDataString(pack)}/assets/{Uri.EscapeDataString(value)}";
        }

        logger.LogWarning("Theme {Theme} names a {What} that is neither a file next to the pack nor a data: URL; it is not shown.", pack, what);
        return null;
    }

    public (string Path, string ContentType)? GetAsset(string name, string file)
    {
        if (!packs.TryGetValue(name, out var entry)
            || new[] { entry.Pack.Branding?.Logo, entry.Pack.Branding?.Favicon }
                .Select(v => v?.Trim())
                .FirstOrDefault(v => string.Equals(v, file, StringComparison.OrdinalIgnoreCase)) is not { } named
            || !IsPlainFileName(named)
            || !AssetTypes.TryGetValue(Path.GetExtension(named), out var type))
        {
            return null;
        }

        var path = Path.Combine(origins[entry.Pack.Name], named);
        var info = new FileInfo(path);
        return info.Exists && info.Length <= MaxAssetBytes ? (path, type) : null;
    }

    /// <summary>A name in the pack's own directory: no separators, no parent references, nothing a path could escape through.</summary>
    private static bool IsPlainFileName(string value) =>
        value.Length is > 0 and <= 128
        && value.IndexOfAny(['/', '\\', ':']) < 0
        && value != "." && value != ".."
        && value.IndexOfAny(Path.GetInvalidFileNameChars()) < 0;

    public void Reload()
    {
        packs.Clear();
        origins.Clear();
        foreach (var directory in directories.Where(Directory.Exists))
        {
            foreach (var file in Directory.GetFiles(directory, "*.yaml").Concat(Directory.GetFiles(directory, "*.yml")))
            {
                try
                {
                    var pack = Yaml.Deserialize<ThemePack>(File.ReadAllText(file));
                    if (string.IsNullOrWhiteSpace(pack?.Name) || !NamePattern().IsMatch(pack.Name))
                    {
                        logger.LogWarning("Theme {File} has no usable name (letters, digits and dashes) and was skipped.", Path.GetFileName(file));
                        continue;
                    }

                    var css = Compile(pack);
                    var tag = "\"" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(css)))[..16] + "\"";
                    packs[pack.Name] = (pack, css, tag);
                    origins[pack.Name] = directory;
                    logger.LogInformation("Theme loaded: {Theme} from {File}.", pack.Name, Path.GetFileName(file));
                }
                catch (Exception ex) when (ex is YamlException or IOException or UnauthorizedAccessException)
                {
                    // One broken pack must not stop the others, and never the server.
                    logger.LogError(ex, "Theme {File} could not be read.", Path.GetFileName(file));
                }
            }
        }
    }

    // A pack's name becomes part of an address and of a file path; nothing but these is ever one.
    [System.Text.RegularExpressions.GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9-]{0,63}$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex NamePattern();

    /// <summary>Turns a pack into the stylesheet: fonts and radii ride along with the light tokens.</summary>
    private static string Compile(ThemePack pack)
    {
        var css = new StringBuilder();
        css.Append("/* theme: ").Append(pack.Name).AppendLine(" — generated from YAML, do not edit */");

        if (!string.IsNullOrWhiteSpace(pack.Fonts?.FontUrl))
        {
            css.Append("@import url('").Append(pack.Fonts.FontUrl).AppendLine("');");
        }

        var light = new Dictionary<string, string>(pack.Tokens?.Light ?? [], StringComparer.OrdinalIgnoreCase);
        Add(light, "font-ui", pack.Fonts?.Ui);
        Add(light, "font-display", pack.Fonts?.Display);
        Add(light, "font-mono", pack.Fonts?.Mono);
        Add(light, "r-1", pack.Layout?.Radius);
        Add(light, "r-2", pack.Layout?.RadiusLarge);
        Add(light, "page-width", pack.Layout?.PageWidth);

        Block(css, ":root", light);

        // Both selectors, in the order the base stylesheet uses them: the media query answers the
        // reader's system preference, the attribute answers an explicit choice and must win. Each is the base
        // stylesheet's own selector, so this file, which comes after it, wins: a bare [data-theme="dark"] weighs
        // less than the base's :root[data-theme="dark"], and a pack's dark colours were lost on an explicit choice.
        Block(css, "@media (prefers-color-scheme: dark) { :root:not([data-theme=\"light\"])", pack.Tokens?.Dark, closeMedia: true);
        Block(css, ":root[data-theme=\"dark\"]", pack.Tokens?.Dark);

        if (!string.IsNullOrWhiteSpace(pack.CustomCss))
        {
            css.AppendLine().AppendLine(pack.CustomCss);
        }

        return css.ToString();
    }

    private static void Add(Dictionary<string, string> tokens, string name, string? value)
    {
        if (!string.IsNullOrWhiteSpace(value))
        {
            tokens[name] = value;
        }
    }

    private static void Block(StringBuilder css, string selector, IReadOnlyDictionary<string, string>? tokens, bool closeMedia = false)
    {
        if (tokens is not { Count: > 0 })
        {
            return;
        }

        css.Append(selector).AppendLine(" {");
        foreach (var (key, value) in tokens)
        {
            var name = key.StartsWith("--", StringComparison.Ordinal) ? key : "--" + key;
            css.Append("  ").Append(name).Append(": ").Append(value).AppendLine(";");
        }

        css.AppendLine(closeMedia ? "} }" : "}");
    }
}
