using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Unit.Tests;

/// <summary>
/// The read side of the 1Password Connect API, called the way Termix's Secret Sources plugin calls it for
/// <c>op://vault/item/field</c>: the vault by a title filter, the item by a title filter, then the item with its
/// fields. Who may read what is the key's business, as everywhere else, and every value handed out is on record.
/// </summary>
public sealed class OnePasswordConnectTests : IAsyncLifetime
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";
    private const string Base = "/api/1password-connect/v1";
    private const string DeployKey = "-----BEGIN OPENSSH PRIVATE KEY-----\ngenerated-key-material\n-----END OPENSSH PRIVATE KEY-----\n";
    private static readonly Caller Setup = new("setup", Unrestricted: true);

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-connect-").FullName;
    private WebApplicationFactory<SecretHive.Web.ServerMarker> _factory = null!;
    private HttpClient _bootstrap = null!;
    private User _termix = null!;
    private Caller _admin = null!;

    public async ValueTask InitializeAsync()
    {
        MasterKey.Create(Path.Combine(_directory, "master.key"));
        File.WriteAllText(Path.Combine(_directory, "admin.token"), Token);
        _factory = new WebApplicationFactory<SecretHive.Web.ServerMarker>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("SecretHive:MasterKeyFile", Path.Combine(_directory, "master.key"));
            builder.UseSetting("SecretHive:Auth:BootstrapAdminTokenFile", Path.Combine(_directory, "admin.token"));
            builder.UseSetting("SecretHive:DataDirectory", _directory);
            builder.UseSetting("SecretHive:Tls:Enabled", "false");
            builder.UseSetting("SecretHive:Database:Provider", "Sqlite");
            builder.UseSetting("SecretHive:Database:ConnectionString", $"Data Source={Path.Combine(_directory, "secrethive.db")};Pooling=False");
            builder.UseSetting("Logging:LogLevel:Default", "Warning");
        });
        _bootstrap = Client(Token);

        // A vault of host credentials for Termix, and one it has nothing to do with.
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/termix-hosts", new { });
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/billing", new { });
        var made = await _bootstrap.PutAsJsonAsync("/api/v1/vaults/termix-hosts/secrets/web-1", new
        {
            value = "generated-ssh-password",
            fields = new object[]
            {
                new { name = "username", value = "deploy" },
                new { name = "url", value = "ssh://web-1.example.org", type = "Url" },
                new { name = "passphrase", value = "generated-passphrase", sensitive = true },
            },
        });
        Assert.True(made.IsSuccessStatusCode, await made.Content.ReadAsStringAsync());
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/termix-hosts/secrets/web-2", new { value = "generated-other-password" });
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/termix-hosts/secrets/deploy-key", new { value = DeployKey });
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/billing/secrets/token", new { value = "generated-billing-value" });

        await using var scope = _factory.Services.CreateAsyncScope();
        var root = (await scope.ServiceProvider.GetRequiredService<SecretHive.Application.Ports.IUserStore>().FindByUserNameAsync("admin", default))!;
        _admin = new Caller("admin", UserKey: root.Key, Role: UserRole.SuperAdmin);
        _termix = (await scope.ServiceProvider.GetRequiredService<AccountService>().CreateServiceAsync(new AccountActor(root.Key, UserRole.SuperAdmin), "termix", "Termix's secret source", default)).User!;
        await scope.ServiceProvider.GetRequiredService<SecretService>().AssignAsync("termix-hosts", _termix.Key, null, VaultRole.SecretsUser, Setup);
    }

    public ValueTask DisposeAsync()
    {
        _bootstrap.Dispose();
        _factory.Dispose();
        Directory.Delete(_directory, recursive: true);
        return ValueTask.CompletedTask;
    }

    private HttpClient Client(string? bearer)
    {
        var client = _factory.CreateClient();
        if (bearer is not null)
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        }

        return client;
    }

    private async Task<HttpClient> TermixAsync(string? vault = null, VaultRole? max = null)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var (_, secret) = await scope.ServiceProvider.GetRequiredService<KeyService>().CreateAsync(_admin, _termix.Key, "termix", 30, vault, max);
        return Client(secret);
    }

    private static string Filter(string title) => "?filter=" + Uri.EscapeDataString($"title eq \"{title}\"");

    private static async Task<JsonElement> Json(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.Clone();
    }

    private async Task<List<AuditEvent>> ReadsAsync()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Audit
            .Where(row => row.Code == "secret.value.read" && row.Principal == "termix").ToListAsync();
    }

    [Fact]
    public async Task A_reference_resolves_the_way_the_plugin_asks_and_every_value_handed_out_is_on_record()
    {
        using var termix = await TermixAsync();

        // The plugin's test: how many vaults the token sees. Only the ones its owner has a role in.
        var all = await Json(await termix.GetAsync($"{Base}/vaults"));
        Assert.Equal(["termix-hosts"], all.EnumerateArray().Select(vault => vault.GetProperty("name").GetString()));

        // op://Termix-Hosts/WEB-1/password: vault and item by title, matched without regard to case.
        var vaults = await Json(await termix.GetAsync($"{Base}/vaults{Filter("Termix-Hosts")}"));
        var vaultId = Assert.Single(vaults.EnumerateArray()).GetProperty("id").GetString();
        var items = await Json(await termix.GetAsync($"{Base}/vaults/{vaultId}/items{Filter("WEB-1")}"));
        var item = Assert.Single(items.EnumerateArray());
        Assert.Equal("web-1", item.GetProperty("title").GetString());
        Assert.False(item.TryGetProperty("fields", out _));
        Assert.DoesNotContain("generated-", items.GetRawText(), StringComparison.Ordinal);
        Assert.Empty(await ReadsAsync());

        var full = await Json(await termix.GetAsync($"{Base}/vaults/{vaultId}/items/{item.GetProperty("id").GetString()}"));
        var fields = full.GetProperty("fields").EnumerateArray().ToDictionary(field => field.GetProperty("id").GetString()!, field => field);
        Assert.Equal("generated-ssh-password", fields["password"].GetProperty("value").GetString());
        Assert.Equal("PASSWORD", fields["password"].GetProperty("purpose").GetString());
        Assert.Equal("CONCEALED", fields["password"].GetProperty("type").GetString());
        Assert.Equal("generated-passphrase", fields["passphrase"].GetProperty("value").GetString());
        Assert.Equal("CONCEALED", fields["passphrase"].GetProperty("type").GetString());
        Assert.False(fields.ContainsKey("private_key"));
        Assert.Equal("deploy", fields["username"].GetProperty("value").GetString());
        Assert.Equal("USERNAME", fields["username"].GetProperty("purpose").GetString());
        Assert.Equal("URL", fields["url"].GetProperty("type").GetString());

        // Two values left the server: the secret's own and its sensitive field. Two reads, by Termix's identity.
        var reads = await ReadsAsync();
        Assert.Equal(2, reads.Count);
        Assert.All(reads, row => Assert.Equal("termix-hosts", row.Vault));
    }

    [Fact]
    public async Task A_private_key_held_as_the_value_is_also_the_field_a_private_key_reference_asks_for()
    {
        using var termix = await TermixAsync();

        // op://termix-hosts/deploy-key/private key: the plugin takes the field with the id private_key.
        var full = await Json(await termix.GetAsync($"{Base}/vaults/termix-hosts/items/deploy-key"));
        var fields = full.GetProperty("fields").EnumerateArray().ToDictionary(field => field.GetProperty("id").GetString()!, field => field);
        Assert.Equal(DeployKey, fields["private_key"].GetProperty("value").GetString());
        Assert.Equal("private key", fields["private_key"].GetProperty("label").GetString());
        Assert.Equal(DeployKey, fields["password"].GetProperty("value").GetString());

        // The same value under two ids is one value read.
        Assert.Single(await ReadsAsync());
    }

    [Fact]
    public async Task What_the_key_may_not_read_it_does_not_get_and_nothing_changes_through_here()
    {
        // A key limited to Reader lists the items but reads no value.
        using (var reader = await TermixAsync(max: VaultRole.Reader))
        {
            Assert.Equal(HttpStatusCode.OK, (await reader.GetAsync($"{Base}/vaults/termix-hosts/items")).StatusCode);
            var refused = await reader.GetAsync($"{Base}/vaults/termix-hosts/items/web-1");
            Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
            var body = await refused.Content.ReadAsStringAsync();
            Assert.Contains("\"status\":403", body, StringComparison.Ordinal);
            Assert.DoesNotContain("generated-", body, StringComparison.Ordinal);
        }

        using var termix = await TermixAsync();

        // A vault it has no role in does not exist for it, by any of the three calls.
        Assert.Equal("[]", await termix.GetStringAsync($"{Base}/vaults{Filter("billing")}"));
        Assert.Equal(HttpStatusCode.NotFound, (await termix.GetAsync($"{Base}/vaults/billing/items")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await termix.GetAsync($"{Base}/vaults/billing/items/token")).StatusCode);

        // An item that is not there, a filter it does not understand, no key at all.
        Assert.Equal(HttpStatusCode.NotFound, (await termix.GetAsync($"{Base}/vaults/termix-hosts/items/web-9")).StatusCode);
        Assert.Equal("[]", await termix.GetStringAsync($"{Base}/vaults/termix-hosts/items{Filter("web-9")}"));
        Assert.Equal(HttpStatusCode.BadRequest, (await termix.GetAsync($"{Base}/vaults?filter=" + Uri.EscapeDataString("name sw \"t\""))).StatusCode);
        using (var anonymous = Client(null))
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync($"{Base}/vaults")).StatusCode);
        }

        // Only reads: the write routes of the real thing are not here.
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await termix.PutAsJsonAsync($"{Base}/vaults/termix-hosts/items/web-1", new { title = "web-1" })).StatusCode);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, (await termix.DeleteAsync($"{Base}/vaults/termix-hosts/items/web-1")).StatusCode);
        Assert.Empty(await ReadsAsync());
    }

    [Fact]
    public async Task A_secret_linked_in_from_another_vault_comes_with_its_user_name()
    {
        // The host's credential lives with its stack; Termix's vault holds a link to it, made after the user name was set.
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/srv-stack", new { });
        Assert.True((await _bootstrap.PutAsJsonAsync("/api/v1/vaults/srv-stack/secrets/web-3", new
        {
            value = "generated-web-3-password",
            fields = new object[] { new { name = "username", value = "deploy" } },
        })).IsSuccessStatusCode);
        Assert.True((await _bootstrap.PostAsJsonAsync("/api/v1/vaults/srv-stack/secrets/web-3/link", new { vault = "termix-hosts" })).IsSuccessStatusCode);

        using var termix = await TermixAsync();
        var full = await Json(await termix.GetAsync($"{Base}/vaults/termix-hosts/items/web-3"));
        var fields = full.GetProperty("fields").EnumerateArray().ToDictionary(field => field.GetProperty("id").GetString()!, field => field.GetProperty("value").GetString());
        Assert.Equal(("generated-web-3-password", "deploy"), (fields["password"], fields["username"]));

        // A user name changed where the credential lives reaches Termix's name too.
        Assert.True((await _bootstrap.PutAsJsonAsync("/api/v1/vaults/srv-stack/secrets/web-3", new
        {
            value = "generated-web-3-password-2",
            fields = new object[] { new { name = "username", value = "deploy-2" } },
        })).IsSuccessStatusCode);
        full = await Json(await termix.GetAsync($"{Base}/vaults/termix-hosts/items/web-3"));
        Assert.Contains(full.GetProperty("fields").EnumerateArray(), field => field.GetProperty("id").GetString() == "username" && field.GetProperty("value").GetString() == "deploy-2");
    }

    [Fact]
    public async Task A_disabled_secret_hands_out_nothing()
    {
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>();
            var entry = await context.Entries.SingleAsync(candidate => candidate.Name == "web-2");
            entry.Enabled = false;
            await context.SaveChangesAsync();
        }

        using var termix = await TermixAsync();
        var refused = await termix.GetAsync($"{Base}/vaults/termix-hosts/items/web-2");
        Assert.False(refused.IsSuccessStatusCode);
        Assert.DoesNotContain("generated-", await refused.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Empty(await ReadsAsync());
    }
}
