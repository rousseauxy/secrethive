using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Web.Theming;

namespace SecretHive.Unit.Tests;

/// <summary>
/// Theme packs: YAML that restates colours and a name. What ships, what an operator adds, what the pages then
/// link, and that a pack can make the server hand out nothing but the images it names.
/// </summary>
public sealed class ThemeTests : IAsyncLifetime
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-themes-").FullName;
    private WebApplicationFactory<SecretHive.Web.ServerMarker> _factory = null!;
    private HttpClient _client = null!;

    public ValueTask InitializeAsync()
    {
        MasterKey.Create(Path.Combine(_directory, "master.key"));
        File.WriteAllText(Path.Combine(_directory, "admin.token"), Token);
        var themes = Directory.CreateDirectory(Path.Combine(_directory, "themes")).FullName;

        // An operator's pack with a logo beside it, in the format the sibling applications read.
        File.WriteAllText(Path.Combine(themes, "acme.yaml"), """
            name: acme
            label: Acme
            description: The house colours.
            fonts:
              ui: "'Inter', sans-serif"
            branding:
              titlePlain: Acme Vault
              logo: acme-logo.svg
              logoAlt: Acme
            layout:
              radius: 2px
            tokens:
              light:
                accent: "#aa3300"
              dark:
                --accent: "#ff7744"
            someOtherApplicationsKey: ignored
            """);
        File.WriteAllText(Path.Combine(themes, "acme-logo.svg"), "<svg xmlns=\"http://www.w3.org/2000/svg\"/>");
        File.WriteAllText(Path.Combine(themes, "not-named-by-any-pack.svg"), "<svg xmlns=\"http://www.w3.org/2000/svg\"/>");
        File.WriteAllText(Path.Combine(themes, "broken.yaml"), "name: [this is not\n  a pack");
        File.WriteAllText(Path.Combine(themes, "bad-name.yaml"), "name: ../escape\ntokens:\n  light:\n    accent: red\n");

        _factory = new WebApplicationFactory<SecretHive.Web.ServerMarker>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("SecretHive:MasterKeyFile", Path.Combine(_directory, "master.key"));
            builder.UseSetting("SecretHive:Auth:BootstrapAdminTokenFile", Path.Combine(_directory, "admin.token"));
            builder.UseSetting("SecretHive:DataDirectory", _directory);
            builder.UseSetting("SecretHive:Tls:Enabled", "false");
            builder.UseSetting("SecretHive:Database:Provider", "Sqlite");
            builder.UseSetting("SecretHive:Database:ConnectionString", $"Data Source={Path.Combine(_directory, "secrethive.db")};Pooling=False");
            builder.UseSetting("Logging:LogLevel:Default", "Critical");
        });
        _client = _factory.CreateClient();
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _client.Dispose();
        await _factory.DisposeAsync();
        Directory.Delete(_directory, recursive: true);
    }

    [Fact]
    public async Task The_packs_that_ship_and_the_operators_own_are_found_and_a_broken_one_stops_nothing()
    {
        var themes = _factory.Services.GetRequiredService<IThemeService>();
        Assert.Equal(["acme", "cobalt", "graphite", "zinc"], themes.Packs.Select(pack => pack.Name).Order());
        Assert.Equal(Path.Combine(_directory, "themes"), themes.OperatorDirectory);

        // A pack states only what it changes; what it says becomes custom properties for light, and for dark both ways the page asks.
        var css = await _client.GetStringAsync("/themes/acme.css");
        Assert.Contains("--accent: #aa3300;", css);
        Assert.Contains("--font-ui: 'Inter', sans-serif;", css);
        Assert.Contains("--r-1: 2px;", css);
        // As specific as the base stylesheet's own dark block, which it has to win over on an explicit choice.
        Assert.Contains("\n:root[data-theme=\"dark\"] {\n  --accent: #ff7744;", css.ReplaceLineEndings("\n"));
        Assert.Contains("@media (prefers-color-scheme: dark)", css);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync("/themes/nothing-by-this-name.css")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _client.GetAsync("/themes/broken.css")).StatusCode);

        // The shipped packs carry this server's name, whatever the application they were written for is called.
        Assert.Equal("SecretHive", themes.GetBrand("cobalt").Title);
        Assert.Null(themes.GetBrand("cobalt").LogoUrl);
    }

    [Fact]
    public async Task A_pack_can_have_the_server_hand_out_the_images_it_names_and_nothing_else()
    {
        var logo = await _client.GetAsync("/themes/acme/assets/acme-logo.svg");
        Assert.Equal(HttpStatusCode.OK, logo.StatusCode);
        Assert.Equal("image/svg+xml", logo.Content.Headers.ContentType!.MediaType);

        // An SVG opened by itself is a document; it is served so that nothing in it runs as this site.
        Assert.Contains("sandbox", logo.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("nosniff", logo.Headers.GetValues("X-Content-Type-Options").Single());

        foreach (var path in new[]
        {
            "/themes/acme/assets/not-named-by-any-pack.svg",
            "/themes/acme/assets/acme.yaml",
            "/themes/acme/assets/..%2Fmaster.key",
            "/themes/acme/assets/..%5Cmaster.key",
            "/themes/cobalt/assets/acme-logo.svg",
            "/themes/..%2F..%2Fmaster/assets/key",
        })
        {
            Assert.True(HttpStatusCode.NotFound == (await _client.GetAsync(path)).StatusCode, path);
        }
    }

    [Fact]
    public async Task The_chosen_pack_dresses_every_page_the_sign_in_page_included_and_survives_a_restart()
    {
        var before = await _client.GetStringAsync("/login");
        Assert.DoesNotContain("/themes/", before, StringComparison.Ordinal);

        // Chosen, as the appearance page does it: the setting, and the holder the pages read.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var store = scope.ServiceProvider.GetRequiredService<SecretHive.Application.Ports.ISecretStore>();
            await store.SetSettingAsync(ThemeChoice.SettingKey, "acme", default);
            await store.SaveAsync(default);
        }

        _factory.Services.GetRequiredService<ThemeChoice>().Name = "acme";
        var after = await _client.GetStringAsync("/login");
        Assert.Contains("<link rel=\"stylesheet\" href=\"/themes/acme.css\"", after, StringComparison.Ordinal);
        Assert.True(after.IndexOf("/themes/acme.css", StringComparison.Ordinal) > after.IndexOf("app", StringComparison.Ordinal), "the pack comes after the server's own stylesheet, or it would not win");
        Assert.Contains("href=\"/themes/acme/assets/acme-logo.svg\"", after, StringComparison.Ordinal); // the tab's icon
        var brand = _factory.Services.GetRequiredService<IThemeService>().GetBrand("acme");
        Assert.Equal(("Acme Vault", "/themes/acme/assets/acme-logo.svg", "Acme"), (brand.Title, brand.LogoUrl, brand.LogoAlt));

        // A pack that was chosen and then taken away leaves the built-in look, not a page asking for a missing file.
        File.Delete(Path.Combine(_directory, "themes", "acme.yaml"));
        _factory.Services.GetRequiredService<IThemeService>().Reload();
        Assert.DoesNotContain("/themes/acme.css", await _client.GetStringAsync("/login"), StringComparison.Ordinal);
    }
}
