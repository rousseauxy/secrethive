using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Infrastructure.Encryption;

namespace SecretHive.Unit.Tests;

/// <summary>
/// What the admin pages do, done through the API with the bootstrap token: accounts, service identities and their
/// keys, groups and their members, the theme. The same outcomes and the same audit codes as the pages; and a key,
/// which manages nothing, is refused at the door.
/// </summary>
public sealed class AdminApiTests : IDisposable
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-admin-api-").FullName;
    private readonly WebApplicationFactory<SecretHive.Web.ServerMarker> _factory;
    private readonly HttpClient _admin;

    public AdminApiTests()
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
        _admin = _factory.CreateClient();
        _admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
    }

    public void Dispose()
    {
        _admin.Dispose();
        _factory.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private async Task<List<(string Code, string Severity, string? Detail)>> AuditAsync() =>
        [.. (await Json(await _admin.GetAsync("/api/v1/audit?take=200"))).EnumerateArray()
            .Select(row => (row.GetProperty("code").GetString()!, row.GetProperty("severity").GetString()!, row.GetProperty("detail").GetString()))];

    [Fact]
    public async Task A_service_identity_a_super_admin_made_an_admin_acts_as_one_through_its_keys_and_no_further()
    {
        HttpClient Client(string key)
        {
            var client = _factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
            return client;
        }

        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/service-identities/robot", new { description = "the assistant's admin" })).StatusCode);
        var made = await Json(await _admin.PostAsJsonAsync("/api/v1/service-identities/robot/keys", new { label = "admin work", days = 30 }));
        using var robot = Client(made.GetProperty("key").GetString()!);

        // Before the role: a key, which manages nothing.
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.GetAsync("/api/v1/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.PutAsJsonAsync("/api/v1/vaults/made-by-robot", new { })).StatusCode);

        // Only Admin, never Super admin; set by a super admin, the widening on record as a security event.
        Assert.Equal(HttpStatusCode.Forbidden, (await _admin.PutAsJsonAsync("/api/v1/service-identities/robot/role", new { role = "SuperAdmin" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/service-identities/robot/role", new { role = "Admin" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/service-identities/nobody/role", new { role = "Admin" })).StatusCode);
        Assert.Contains(await AuditAsync(), row => row == ("service.role.changed", "Security", "robot user -> admin"));
        Assert.Equal("Admin", (await Json(await _admin.GetAsync("/api/v1/service-identities"))).EnumerateArray().Single(item => item.GetProperty("userName").GetString() == "robot").GetProperty("role").GetString());

        // Now its key does what an admin does: vaults, renaming, identities and their keys, accounts, the whole trail.
        Assert.Equal(HttpStatusCode.Created, (await robot.PutAsJsonAsync("/api/v1/vaults/made-by-robot", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await robot.PostAsJsonAsync("/api/v1/vaults/made-by-robot/rename", new { name = "renamed-by-robot" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await robot.GetAsync("/api/v1/users")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await robot.GetAsync("/api/v1/audit?take=5")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await robot.PutAsJsonAsync("/api/v1/service-identities/helper", new { description = "a job" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await robot.PostAsJsonAsync("/api/v1/service-identities/helper/keys", new { label = "job", days = 1 })).StatusCode);

        // And nothing a super admin does: deleting a vault, sign-in providers, backups, roles of identities.
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.DeleteAsync("/api/v1/vaults/renamed-by-robot")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.PutAsJsonAsync("/api/v1/service-identities/helper/role", new { role = "Admin" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.PutAsJsonAsync("/api/v1/service-identities/robot/role", new { role = "User" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.GetAsync("/api/v1/backups")).StatusCode);

        // Its own keys are a super admin's to make and end: a stolen key cannot make the next one.
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.PostAsJsonAsync("/api/v1/service-identities/robot/keys", new { label = "another", days = 30 })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.GetAsync("/api/v1/service-identities/robot/keys")).StatusCode);

        // Being an admin is no right to read a value: that takes a role in the vault, as for anyone.
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { })).StatusCode);
        Assert.True((await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-value" })).IsSuccessStatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.GetAsync("/api/v1/vaults/shop/secrets/token/value")).StatusCode);

        // A key narrowed to one vault is no administrator of the whole server.
        var narrowed = await Json(await _admin.PostAsJsonAsync("/api/v1/service-identities/robot/keys", new { label = "one vault", days = 1, vault = "shop" }));
        using (var oneVault = Client(narrowed.GetProperty("key").GetString()!))
        {
            Assert.Equal(HttpStatusCode.Forbidden, (await oneVault.GetAsync("/api/v1/users")).StatusCode);
        }

        // An admin who is a person cannot make a key for it either, or disable it: it holds their own rank.
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/users/ops", new { role = "Admin", password = "generated-first-password" })).StatusCode);
        var ops = (await Json(await _admin.GetAsync("/api/v1/users"))).EnumerateArray().Single(user => user.GetProperty("userName").GetString() == "ops").GetProperty("key").GetInt32();
        var robotKey = (await Json(await _admin.GetAsync("/api/v1/service-identities"))).EnumerateArray().Single(user => user.GetProperty("userName").GetString() == "robot").GetProperty("key").GetInt32();
        using (var scope = _factory.Services.CreateScope())
        {
            var asOps = new SecretHive.Application.Secrets.Caller("ops", UserKey: ops, Role: SecretHive.Domain.Entities.UserRole.Admin);
            var refused = await Assert.ThrowsAsync<SecretHive.Domain.DomainException>(() => scope.ServiceProvider.GetRequiredService<SecretHive.Application.Accounts.KeyService>().CreateAsync(asOps, robotKey, "by ops", 1, null, null));
            Assert.Equal("access.denied", refused.Code);
            Assert.Equal(SecretHive.Application.Accounts.AccountOutcome.Forbidden, await scope.ServiceProvider.GetRequiredService<SecretHive.Application.Accounts.AccountService>().SetDisabledAsync(new SecretHive.Application.Accounts.AccountActor(ops, SecretHive.Domain.Entities.UserRole.Admin), robotKey, true, default));
        }

        // Taken back: every key of it is a plain key again at its next request.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/service-identities/robot/role", new { role = "User" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await robot.GetAsync("/api/v1/users")).StatusCode);
        Assert.Contains(await AuditAsync(), row => row == ("service.role.changed", "Notice", "robot admin -> user"));
    }

    [Fact]
    public async Task The_trail_is_paged_back_by_the_last_id_seen_with_nothing_skipped_or_twice()
    {
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { })).StatusCode);
        for (var i = 0; i < 23; i++)
        {
            await _admin.PutAsJsonAsync($"/api/v1/vaults/shop/secrets/s{i}", new { value = "generated-page-value" });
        }

        var everything = (await Json(await _admin.GetAsync("/api/v1/audit?take=500"))).EnumerateArray().Select(row => row.GetProperty("id").GetInt64()).ToList();
        var paged = new List<long>();
        long? before = null;
        while (true)
        {
            var page = (await Json(await _admin.GetAsync("/api/v1/audit?take=10" + (before is { } id ? $"&before={id}" : "")))).EnumerateArray().Select(row => row.GetProperty("id").GetInt64()).ToList();
            paged.AddRange(page);
            if (page.Count < 10)
            {
                break;
            }

            before = page[^1];
        }

        Assert.True(everything.Count >= 24);
        Assert.Equal(everything, paged);

        // The same for one vault.
        var shop = (await Json(await _admin.GetAsync("/api/v1/vaults/shop/audit?take=5"))).EnumerateArray().Select(row => row.GetProperty("id").GetInt64()).ToList();
        var next = (await Json(await _admin.GetAsync($"/api/v1/vaults/shop/audit?take=5&before={shop[^1]}"))).EnumerateArray().Select(row => row.GetProperty("id").GetInt64()).ToList();
        Assert.Equal(5, next.Count);
        Assert.True(next.Max() < shop.Min());
    }

    [Fact]
    public async Task Pins_are_kept_per_identity_over_the_api_and_only_on_what_it_may_see()
    {
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/hidden", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-pin-value" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/service-identities/pinner", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop/access", new { user = "pinner", role = "Reader" })).StatusCode);
        var made = await Json(await _admin.PostAsJsonAsync("/api/v1/service-identities/pinner/keys", new { label = "pins", days = 30 }));
        using var pinner = _factory.CreateClient();
        pinner.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", made.GetProperty("key").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await pinner.PutAsJsonAsync("/api/v1/pins", new { vault = "shop" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await pinner.PutAsJsonAsync("/api/v1/pins", new { vault = "shop", secret = "token" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await pinner.PutAsJsonAsync("/api/v1/pins", new { vault = "hidden" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await pinner.PutAsJsonAsync("/api/v1/pins", new { vault = "shop", secret = "nothing" })).StatusCode);
        var pins = (await Json(await pinner.GetAsync("/api/v1/pins"))).EnumerateArray().Select(pin => (pin.GetProperty("vault").GetString(), pin.GetProperty("secret").GetString())).ToList();
        Assert.Equal([("shop", (string?)null), ("shop", "token")], pins);

        // Another identity's list is its own; the bootstrap token is no account and keeps none.
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PutAsJsonAsync("/api/v1/pins", new { vault = "shop" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await pinner.DeleteAsync("/api/v1/pins?vault=shop&secret=token")).StatusCode);
        Assert.Single((await Json(await pinner.GetAsync("/api/v1/pins"))).EnumerateArray());
    }

    [Fact]
    public async Task Folders_are_arranged_and_given_roles_over_the_api_by_an_administrator_only()
    {
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/folders/oci", new { description = "everything on OCI" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/folders/apps", new { parent = "oci" })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PutAsJsonAsync("/api/v1/folders/APPS", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/folders/web", new { parent = "nowhere" })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PostAsJsonAsync("/api/v1/folders/oci/move", new { folder = "apps" })).StatusCode);

        // A vault made straight into a folder, another moved in; the list of vaults says where each is.
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { folder = "apps" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/mail", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/mail/folder", new { folder = "oci" })).StatusCode);
        var vaults = (await Json(await _admin.GetAsync("/api/v1/vaults"))).EnumerateArray().ToDictionary(vault => vault.GetProperty("name").GetString()!, vault => vault.GetProperty("folder").GetString());
        Assert.Equal(("apps", "oci"), (vaults["shop"], vaults["mail"]));
        var folders = (await Json(await _admin.GetAsync("/api/v1/folders"))).EnumerateArray().Select(folder => (folder.GetProperty("name").GetString(), folder.GetProperty("vaults").GetInt32())).ToList();
        Assert.Equal([("oci", 1), ("apps", 1)], folders);

        // A role on the top folder, given to an identity by name: its key reads in the vault beneath.
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/service-identities/host-oci", new { description = "the OCI host" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/folders/oci/access", new { user = "host-oci", role = "SecretsUser" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-folder-value" })).StatusCode);
        var made = await Json(await _admin.PostAsJsonAsync("/api/v1/service-identities/host-oci/keys", new { label = "deploys", days = 30 }));
        using var host = _factory.CreateClient();
        host.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", made.GetProperty("key").GetString());
        Assert.Equal("generated-folder-value", (await Json(await host.GetAsync("/api/v1/vaults/shop/secrets/token/value"))).GetProperty("value").GetString());
        var inherited = (await Json(await _admin.GetAsync("/api/v1/vaults/shop/access"))).EnumerateArray().Single(entry => entry.GetProperty("name").GetString() == "host-oci");
        Assert.Equal(("SecretsUser", "oci"), (inherited.GetProperty("role").GetString(), inherited.GetProperty("from").GetString()));

        // That key manages no folder.
        Assert.Equal(HttpStatusCode.Forbidden, (await host.PutAsJsonAsync("/api/v1/folders/mine", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await host.PutAsJsonAsync("/api/v1/vaults/shop/folder", new { folder = (string?)null })).StatusCode);

        // To the top, the role no longer reaches; on record as a loss.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop/folder", new { folder = (string?)null })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await host.GetAsync("/api/v1/vaults/shop/secrets/token/value")).StatusCode);
        Assert.Contains(await AuditAsync(), row => row == ("vault.folder.changed", "Notice", "to the top; loses: user host-oci"));
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/folders/oci/access?userKey=" + (await Json(await _admin.GetAsync("/api/v1/folders/oci/access"))).EnumerateArray().Single().GetProperty("userKey").GetInt32())).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.DeleteAsync("/api/v1/folders/oci")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/folders/apps")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.PostAsJsonAsync("/api/v1/folders/oci/rename", new { name = "cloud" })).StatusCode);
        Assert.Equal("cloud", (await Json(await _admin.GetAsync("/api/v1/vaults"))).EnumerateArray().Single(vault => vault.GetProperty("name").GetString() == "mail").GetProperty("folder").GetString());
    }

    [Fact]
    public async Task Accounts_are_made_changed_and_removed_through_the_api_with_the_pages_audit_codes()
    {
        // Only the first administrator exists.
        var before = await Json(await _admin.GetAsync("/api/v1/users"));
        Assert.Single(before.EnumerateArray(), user => user.GetProperty("userName").GetString() == "admin");

        var created = await _admin.PutAsJsonAsync("/api/v1/users/ops", new { displayName = "Operations", email = "ops@example.test", role = "Admin", password = "generated-first-password" });
        Assert.Equal(HttpStatusCode.Created, created.StatusCode);
        var shown = await Json(created);
        Assert.Equal(("ops", "Admin", true), (shown.GetProperty("userName").GetString(), shown.GetProperty("role").GetString(), shown.GetProperty("mustChangePassword").GetBoolean()));
        Assert.DoesNotContain("generated-first-password", await created.Content.ReadAsStringAsync());

        // Taken, too short, not a name: each refused with a code, and nothing made.
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PutAsJsonAsync("/api/v1/users/OPS", new { password = "generated-first-password" })).StatusCode);
        var tooShort = await _admin.PutAsJsonAsync("/api/v1/users/dev", new { password = "short" });
        Assert.Equal(HttpStatusCode.BadRequest, tooShort.StatusCode);
        Assert.Equal("user.password.short", (await Json(tooShort)).GetProperty("code").GetString());
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PutAsJsonAsync("/api/v1/users/not a name", new { password = "generated-first-password" })).StatusCode);
        Assert.Equal(2, (await Json(await _admin.GetAsync("/api/v1/users"))).GetArrayLength());

        // Role, disabled, a new first password, and gone.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/users/ops/role", new { role = "User" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/users/ops/disabled", new { disabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/users/ops/password", new { password = "generated-second-password" })).StatusCode);
        var ops = (await Json(await _admin.GetAsync("/api/v1/users"))).EnumerateArray().Single(user => user.GetProperty("userName").GetString() == "ops");
        Assert.Equal(("User", true, true), (ops.GetProperty("role").GetString(), ops.GetProperty("isDisabled").GetBoolean(), ops.GetProperty("mustChangePassword").GetBoolean()));
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/users/ops")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync("/api/v1/users/ops")).StatusCode);

        // The last super admin stays: the rule from the page holds here too.
        var last = await _admin.PutAsJsonAsync("/api/v1/users/admin/disabled", new { disabled = true });
        Assert.Equal(HttpStatusCode.Conflict, last.StatusCode);
        Assert.Equal("user.last_super_admin", (await Json(last)).GetProperty("code").GetString());

        var audit = await AuditAsync();
        Assert.Contains(("user.created", "Security", "ops role=admin"), audit);
        Assert.Contains(("user.role.changed", "Notice", "ops admin -> user"), audit);
        Assert.Contains(("user.disabled", "Notice", "ops"), audit);
        Assert.Contains(("user.password.reset", "Security", "ops"), audit);
        Assert.Contains(("user.deleted", "Notice", "ops"), audit);
        Assert.DoesNotContain(audit, row => row.Detail?.Contains("generated-", StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task A_service_identitys_keys_are_listed_limited_and_revoked_and_the_identity_disabled_and_removed()
    {
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/service-identities/host-web-1", new { description = "the web host" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/network-groups/lan", new { ranges = new[] { "192.0.2.0/24" } })).StatusCode);
        var made = await Json(await _admin.PostAsJsonAsync("/api/v1/service-identities/host-web-1/keys", new { label = "deploys", days = 30 }));
        var secret = made.GetProperty("key").GetString()!;

        // A key can be asked for without an end date; the answer and the list say so with an empty date.
        var endless = await Json(await _admin.PostAsJsonAsync("/api/v1/service-identities/host-web-1/keys", new { label = "no end", noEndDate = true }));
        Assert.Equal(JsonValueKind.Null, endless.GetProperty("expiresUtc").ValueKind);
        var endlessKey = (await Json(await _admin.GetAsync("/api/v1/service-identities/host-web-1/keys"))).EnumerateArray().Single(item => item.GetProperty("label").GetString() == "no end");
        Assert.Equal(JsonValueKind.Null, endlessKey.GetProperty("expiresUtc").ValueKind);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/api/v1/service-identities/host-web-1/keys/{endlessKey.GetProperty("key").GetInt32()}")).StatusCode);

        // Listed by prefix and limits, never the key itself; a person's account has no keys here.
        var listed = await _admin.GetAsync("/api/v1/service-identities/host-web-1/keys");
        var keys = await Json(listed);
        var key = keys.EnumerateArray().Single(item => item.GetProperty("label").GetString() == "deploys");
        Assert.Equal(made.GetProperty("prefix").GetString(), key.GetProperty("prefix").GetString());
        Assert.DoesNotContain(secret, await listed.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync("/api/v1/service-identities/admin/keys")).StatusCode);
        var id = key.GetProperty("key").GetInt32();

        // Limited to a network group, then to a range, then one line taken off again.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PostAsJsonAsync($"/api/v1/service-identities/host-web-1/keys/{id}/networks", new { group = "lan" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PostAsJsonAsync($"/api/v1/service-identities/host-web-1/keys/{id}/networks", new { range = "198.51.100.7" })).StatusCode);
        var lines = (await Json(await _admin.GetAsync("/api/v1/service-identities/host-web-1/keys"))).EnumerateArray().Single(item => item.GetProperty("label").GetString() == "deploys").GetProperty("networks");
        Assert.Equal(2, lines.GetArrayLength());
        var line = lines.EnumerateArray().Single(candidate => candidate.GetProperty("label").GetString() == "198.51.100.7/32").GetProperty("key").GetInt32();
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/api/v1/service-identities/host-web-1/keys/{id}/networks/{line}")).StatusCode);
        Assert.Single((await Json(await _admin.GetAsync("/api/v1/service-identities/host-web-1/keys"))).EnumerateArray().Single(item => item.GetProperty("label").GetString() == "deploys").GetProperty("networks").EnumerateArray());

        // Its highest role is changed in place: lowered quietly, widened or lifted as a security event.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/api/v1/service-identities/host-web-1/keys/{id}/max-role", new { maxRole = "Reader" })).StatusCode);
        Assert.Equal("Reader", (await Json(await _admin.GetAsync("/api/v1/service-identities/host-web-1/keys"))).EnumerateArray().Single(item => item.GetProperty("label").GetString() == "deploys").GetProperty("maxRole").GetString());
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/api/v1/service-identities/host-web-1/keys/{id}/max-role", new { maxRole = "SecretsUser" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/api/v1/service-identities/host-web-1/keys/{id}/max-role", new { maxRole = (string?)null })).StatusCode);
        Assert.Equal(JsonValueKind.Null, (await Json(await _admin.GetAsync("/api/v1/service-identities/host-web-1/keys"))).EnumerateArray().Single(item => item.GetProperty("label").GetString() == "deploys").GetProperty("maxRole").ValueKind);
        var limits = (await AuditAsync()).Where(row => row.Code == "key.limit.changed").Select(row => (row.Severity, row.Detail![row.Detail!.IndexOf("\" ", StringComparison.Ordinal)..])).ToList();
        Assert.Equal(
            [("Security", "\" at most Secrets User -> its owner's role"), ("Security", "\" at most Reader -> at most Secrets User"), ("Notice", "\" its owner's role -> at most Reader")],
            limits);

        // A key manages nothing: with it, the routes of this file do not even say what exists.
        using var asHost = _factory.CreateClient();
        asHost.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await asHost.GetAsync("/api/v1/users")).StatusCode); // outside its networks: no credential at all
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/api/v1/service-identities/host-web-1/keys/{id}/networks/{lines[0].GetProperty("key").GetInt32()}")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await asHost.GetAsync("/api/v1/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await asHost.GetAsync("/api/v1/service-identities")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await asHost.GetAsync("/api/v1/groups")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await asHost.GetAsync("/api/v1/service-identities/host-web-1/keys")).StatusCode);

        // Revoked under its owner: a key named under another identity does not exist.
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/service-identities/other", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync($"/api/v1/service-identities/other/keys/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/api/v1/service-identities/host-web-1/keys/{id}")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await asHost.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PutAsJsonAsync($"/api/v1/service-identities/host-web-1/keys/{id}/max-role", new { maxRole = "Reader" })).StatusCode); // a key that has ended

        // Disabled, listed as such, then gone with its keys and roles.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/service-identities/host-web-1/disabled", new { disabled = true })).StatusCode);
        var services = await Json(await _admin.GetAsync("/api/v1/service-identities"));
        Assert.True(services.EnumerateArray().Single(service => service.GetProperty("userName").GetString() == "host-web-1").GetProperty("isDisabled").GetBoolean());
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/users/host-web-1/disabled", new { disabled = false })).StatusCode); // not a person
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/service-identities/host-web-1")).StatusCode);
        Assert.DoesNotContain((await Json(await _admin.GetAsync("/api/v1/service-identities"))).EnumerateArray(), service => service.GetProperty("userName").GetString() == "host-web-1");

        var audit = await AuditAsync();
        Assert.Contains(audit, row => row.Code == "key.network.added" && row.Detail!.Contains("host-web-1", StringComparison.Ordinal));
        Assert.Contains(audit, row => row.Code == "key.network.removed");
        Assert.Contains(audit, row => row.Code == "key.revoked" && row.Detail!.StartsWith("host-web-1 ", StringComparison.Ordinal));
        Assert.Contains(("service.disabled", "Notice", "host-web-1"), audit);
        Assert.Contains(("service.deleted", "Notice", "host-web-1"), audit);
        Assert.DoesNotContain(audit, row => row.Detail?.Contains(secret, StringComparison.Ordinal) == true);
    }

    [Fact]
    public async Task Groups_members_and_provider_links_are_managed_through_the_api()
    {
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/users/dev", new { password = "generated-first-password" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/groups/developers", new { description = "the team" })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/providers/forge", new { authority = "https://forge.example.test/api/actions", enabled = false, acceptApiTokens = true, apiAudiences = new[] { "https://vault.example.test" } })).StatusCode);

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/groups/developers/members/dev", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/groups/developers/members/nobody", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/groups/nobody/members/dev", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/groups/developers/provider-links", new { provider = "forge", group = "acme/shop" })).StatusCode);

        var groups = await Json(await _admin.GetAsync("/api/v1/groups"));
        var developers = Assert.Single(groups.EnumerateArray());
        Assert.Equal("dev", Assert.Single(developers.GetProperty("members").EnumerateArray()).GetProperty("user").GetString());
        var link = Assert.Single(developers.GetProperty("providerLinks").EnumerateArray());
        Assert.Equal("acme/shop", link.GetProperty("group").GetString());

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/api/v1/groups/developers/provider-links/{link.GetProperty("key").GetInt32()}")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/groups/developers/members/dev")).StatusCode);
        developers = Assert.Single((await Json(await _admin.GetAsync("/api/v1/groups"))).EnumerateArray());
        Assert.Empty(developers.GetProperty("members").EnumerateArray());
        Assert.Empty(developers.GetProperty("providerLinks").EnumerateArray());
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/groups/developers")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.DeleteAsync("/api/v1/groups/developers")).StatusCode);

        var audit = await AuditAsync();
        Assert.Contains(("group.member.added", "Notice", "developers + dev"), audit);
        Assert.Contains(("group.member.removed", "Info", "developers - dev"), audit);
        Assert.Contains(audit, row => row.Code == "group.provider.unlinked");
        Assert.Contains(("group.deleted", "Notice", "developers"), audit);
    }

    [Fact]
    public async Task The_theme_for_everyone_is_read_and_chosen_through_the_api()
    {
        var packs = await Json(await _admin.GetAsync("/api/v1/settings/theme"));
        Assert.Equal(JsonValueKind.Null, packs.GetProperty("name").ValueKind);
        Assert.Contains(packs.GetProperty("packs").EnumerateArray(), pack => pack.GetProperty("name").GetString() == "graphite");

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/settings/theme", new { name = "graphite" })).StatusCode);
        Assert.Equal("graphite", (await Json(await _admin.GetAsync("/api/v1/settings/theme"))).GetProperty("name").GetString());
        var unknown = await _admin.PutAsJsonAsync("/api/v1/settings/theme", new { name = "nothing-like-it" });
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal("theme.not_found", (await Json(unknown)).GetProperty("code").GetString());
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/settings/theme", new { name = "" })).StatusCode);
        Assert.Equal(JsonValueKind.Null, (await Json(await _admin.GetAsync("/api/v1/settings/theme"))).GetProperty("name").ValueKind);

        var audit = await AuditAsync();
        Assert.Contains(("appearance.theme.changed", "Info", "graphite"), audit);
        Assert.Contains(("appearance.theme.changed", "Info", "built-in"), audit);
    }
}
