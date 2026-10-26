namespace SecretHive.Web.Theming;

/// <summary>
/// A declarative theme, loaded from a YAML file. Token keys map one to one onto the CSS custom
/// properties in <c>app.css</c>, so a pack only states what it changes and anything the tokens cannot
/// express goes in <see cref="CustomCss"/>. Drop a file in the themes directory and pick it in
/// configuration: no rebuild, no redeploy.
/// </summary>
public sealed class ThemePack
{
    /// <summary>File-name-safe identifier, also the URL segment: <c>/themes/{name}.css</c>.</summary>
    public string Name { get; set; } = "";

    /// <summary>What to show a person choosing a theme. Falls back to the name.</summary>
    public string? Label { get; set; }

    public string? Description { get; set; }

    public ThemeFonts? Fonts { get; set; }

    public ThemeLayout? Layout { get; set; }

    public ThemeTokens? Tokens { get; set; }

    public ThemeBranding? Branding { get; set; }

    /// <summary>Appended verbatim after the token blocks, for the rare rule tokens cannot express.</summary>
    public string? CustomCss { get; set; }
}

public sealed class ThemeFonts
{
    /// <summary>Body and interface font stack, emitted as <c>--font-ui</c>.</summary>
    public string? Ui { get; set; }

    /// <summary>Heading font stack, emitted as <c>--font-display</c>.</summary>
    public string? Display { get; set; }

    /// <summary>Monospace stack for versions, ids and code, emitted as <c>--font-mono</c>.</summary>
    public string? Mono { get; set; }

    /// <summary>
    /// Optional stylesheet to import for the fonts. Self-hosting is preferred: an import reaches out to
    /// another origin on every page load, which an air-gapped install cannot do.
    /// </summary>
    public string? FontUrl { get; set; }
}

/// <summary>
/// The name and logo in the top bar. The same block the theme format it came from reads - <c>titlePlain</c> is its key - with a
/// logo added; keys either application has no use for are ignored.
/// </summary>
public sealed class ThemeBranding
{
    /// <summary>The product name next to the logo, and in page titles' place of "SecretHive". Empty keeps "SecretHive".</summary>
    public string? TitlePlain { get; set; }

    /// <summary>
    /// The logo, shown on the top bar - dark in both light and dark mode, so one image serves both. Either a file name next
    /// to the pack (<c>acme-logo.svg</c>; SVG, PNG, WebP, JPEG or GIF, at most 1 MB), served by this server, or a
    /// <c>data:image/...</c> URL. Deliberately not a link to another site: the logo would then depend on that site, and
    /// every reader's browser would call it.
    /// </summary>
    public string? Logo { get; set; }

    /// <summary>
    /// The browser tab's icon, the same kinds of value as <see cref="Logo"/>. Empty: the logo, and with no logo either,
    /// SecretHive's own mark. Unlike the logo it is drawn on whatever the browser's tab bar is, light or dark.
    /// </summary>
    public string? Favicon { get; set; }

    /// <summary>What a screen reader says for the logo. Empty: the title.</summary>
    public string? LogoAlt { get; set; }

    /// <summary>When the logo already carries the name, the text beside it can go.</summary>
    public bool HideTitle { get; set; }
}

public sealed class ThemeLayout
{
    /// <summary>The widest the page's content grows, emitted as <c>--page-width</c> (default 1280px).</summary>
    public string? PageWidth { get; set; }

    /// <summary>Base corner radius, emitted as <c>--r-1</c>.</summary>
    public string? Radius { get; set; }

    /// <summary>Card and panel radius, emitted as <c>--r-2</c>.</summary>
    public string? RadiusLarge { get; set; }
}

public sealed class ThemeTokens
{
    /// <summary>Applied to <c>:root</c>. A key may be written with or without the leading dashes.</summary>
    public Dictionary<string, string>? Light { get; set; }

    /// <summary>Applied to <c>[data-theme="dark"]</c>.</summary>
    public Dictionary<string, string>? Dark { get; set; }
}
