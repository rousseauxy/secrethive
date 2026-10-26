using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Unit.Tests;

/// <summary>A tool with a key of its own, over HTTP: what it may do is what its owner may do, inside the key's limits.</summary>
public sealed class ApiKeyTests : IAsyncLifetime
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";
    private static readonly Caller Setup = new("setup", Unrestricted: true);

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-keys-").FullName;
    private WebApplicationFactory<SecretHive.Web.ServerMarker> _factory = null!;
    private HttpClient _bootstrap = null!;
    private User _job = null!;
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

        // Two vaults with a secret each, and a service identity that reads values in one and only sees the other.
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/shop", new { });
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/billing", new { });
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-shop-value" });
        await _bootstrap.PutAsJsonAsync("/api/v1/vaults/billing/secrets/token", new { value = "generated-billing-value" });

        var root = await With<Ports, User>(async ports => (await ports.Users.FindByUserNameAsync("admin", default))!);
        _admin = new Caller("admin", UserKey: root.Key, Role: UserRole.SuperAdmin);
        _job = await With<AccountService, User>(async accounts => (await accounts.CreateServiceAsync(new AccountActor(root.Key, UserRole.SuperAdmin), "stack-web-1-shop", "the shop stack on web-1", default)).User!);
        await With<SecretService, bool>(async service =>
        {
            await service.AssignAsync("shop", _job.Key, null, VaultRole.SecretsOfficer, Setup);
            await service.AssignAsync("billing", _job.Key, null, VaultRole.Reader, Setup);
            return true;
        });
    }

    public ValueTask DisposeAsync()
    {
        _bootstrap.Dispose();
        _factory.Dispose();
        Directory.Delete(_directory, recursive: true);
        return ValueTask.CompletedTask;
    }

    /// <summary>The two stores a test reaches for directly, resolved together.</summary>
    private sealed record Ports(SecretHive.Application.Ports.IUserStore Users);

    private async Task<T> With<TService, T>(Func<TService, Task<T>> act)
        where TService : notnull
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var service = typeof(TService) == typeof(Ports)
            ? (TService)(object)new Ports(scope.ServiceProvider.GetRequiredService<SecretHive.Application.Ports.IUserStore>())
            : scope.ServiceProvider.GetRequiredService<TService>();
        return await act(service);
    }

    private HttpClient Client(string bearer)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
        return client;
    }

    private Task<(KeySummary Key, string Secret)> NewKey(string label, string? vault = null, VaultRole? max = null, int? days = 30) =>
        With<KeyService, (KeySummary, string)>(keys => keys.CreateAsync(_admin, _job.Key, label, days, vault, max));

    /// <summary>The audit rows, newest first.</summary>
    private async Task<List<AuditEvent>> Audit()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Audit.OrderByDescending(row => row.Id).ToListAsync();
    }

    private static async Task<string?> ValueOf(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("value").GetString();

    [Fact]
    public async Task A_key_acts_as_its_owner_and_the_read_is_on_record_under_the_owners_name()
    {
        var (summary, secret) = await NewKey("deploy on web-1");
        using var job = Client(secret);

        Assert.StartsWith("shv_" + summary.Prefix + "_", secret);
        Assert.Equal("generated-shop-value", await ValueOf(await job.GetAsync("/api/v1/vaults/shop/secrets/token/value")));

        // In the other vault its owner is a Reader: it sees what exists and reads no value.
        Assert.Equal(HttpStatusCode.OK, (await job.GetAsync("/api/v1/vaults/billing/secrets")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await job.GetAsync("/api/v1/vaults/billing/secrets/token/value")).StatusCode);
        Assert.Equal(["billing", "shop"], JsonDocument.Parse(await job.GetStringAsync("/api/v1/vaults")).RootElement.EnumerateArray().Select(vault => vault.GetProperty("name").GetString()));

        // A key manages nothing: no vaults, no whole audit trail, no keys.
        Assert.Equal(HttpStatusCode.Forbidden, (await job.PutAsJsonAsync("/api/v1/vaults/mine", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await job.GetAsync("/api/v1/audit")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await job.GetAsync("/api/v1/account/keys")).StatusCode);

        var audit = await _bootstrap.GetStringAsync("/api/v1/audit");
        Assert.Contains("\"code\":\"secret.value.read\",\"severity\":\"Info\",\"principal\":\"stack-web-1-shop\",\"vault\":\"shop\"", audit);
        Assert.Contains("key.created", audit);
        Assert.DoesNotContain(secret, audit);

        // When and from where it was used is kept, because that is what says an old key is safe to revoke.
        var listed = Assert.Single(await With<KeyService, IReadOnlyList<KeySummary>>(keys => keys.ListAsync(_admin, _job.Key)));
        Assert.NotNull(listed.LastUsedUtc);
    }

    [Fact]
    public async Task A_key_capped_at_secrets_writer_sets_what_its_owner_may_and_reads_nothing()
    {
        var (summary, secret) = await NewKey("rotation", max: VaultRole.SecretsWriter);
        using var rotation = Client(secret);

        Assert.Equal(HttpStatusCode.OK, (await rotation.GetAsync("/api/v1/vaults/shop/secrets")).StatusCode);
        Assert.True((await rotation.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-rotated" })).IsSuccessStatusCode);
        var refused = await rotation.GetAsync("/api/v1/vaults/shop/secrets/token/value");
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);
        Assert.Contains("This key is limited to Secrets Writer; its owner holds Secrets Officer", await refused.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Equal(HttpStatusCode.Forbidden, (await rotation.DeleteAsync("/api/v1/vaults/shop/secrets/token")).StatusCode);

        // What it set is what the owner's other key reads.
        var (_, full) = await NewKey("reads");
        using var reads = Client(full);
        Assert.Equal("generated-rotated", await ValueOf(await reads.GetAsync("/api/v1/vaults/shop/secrets/token/value")));

        // From Secrets Writer to Reader takes the setting away; back again gives it, and giving is a security event.
        await With<KeyService, bool>(async keys =>
        {
            await keys.SetMaxRoleAsync(_admin, summary.Key, VaultRole.Reader);
            return true;
        });
        Assert.Equal(HttpStatusCode.Forbidden, (await rotation.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-no" })).StatusCode);
        await With<KeyService, bool>(async keys =>
        {
            await keys.SetMaxRoleAsync(_admin, summary.Key, VaultRole.SecretsWriter);
            return true;
        });
        var changes = (await Audit()).Where(row => row.Code == "key.limit.changed").Select(row => row.Severity).ToList();
        Assert.Equal([AuditSeverity.Security, AuditSeverity.Notice], changes);

        // The role is given by its name over the API, like any other.
        Assert.True((await _bootstrap.PutAsJsonAsync("/api/v1/vaults/billing/access", new { user = "stack-web-1-shop", role = "SecretsWriter" })).IsSuccessStatusCode);
    }

    [Fact]
    public async Task A_secret_is_renamed_over_the_api_by_a_key_of_an_officer_and_a_reader_is_refused()
    {
        var (_, secret) = await NewKey("rename");
        using var officer = Client(secret);
        var (_, readOnly) = await NewKey("reads", max: VaultRole.Reader);
        using var reader = Client(readOnly);

        Assert.Equal(HttpStatusCode.Forbidden, (await reader.PostAsJsonAsync("/api/v1/vaults/shop/secrets/token/rename", new { name = "api-token" })).StatusCode);
        var renamed = await officer.PostAsJsonAsync("/api/v1/vaults/shop/secrets/token/rename", new { name = "api-token" });
        Assert.Equal(HttpStatusCode.OK, renamed.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await officer.GetAsync("/api/v1/vaults/shop/secrets/api-token/value")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await officer.GetAsync("/api/v1/vaults/shop/secrets/token/value")).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await officer.PostAsJsonAsync("/api/v1/vaults/shop/secrets/api-token/rename", new { name = "API-TOKEN" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await officer.PostAsJsonAsync("/api/v1/vaults/shop/secrets/api-token/rename", new { name = "no good" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await officer.PostAsJsonAsync("/api/v1/vaults/shop/secrets/token/rename", new { name = "elsewhere" })).StatusCode);
    }

    [Fact]
    public async Task A_renamed_vault_keeps_the_keys_narrowed_to_it_and_only_an_administrator_renames_over_the_api()
    {
        var (summary, secret) = await NewKey("billing report", vault: "billing");
        using var key = Client(secret);

        // A key manages nothing, whoever owns it.
        Assert.Equal(HttpStatusCode.Forbidden, (await key.PostAsJsonAsync("/api/v1/vaults/billing/rename", new { name = "invoices" })).StatusCode);

        var renamed = await _bootstrap.PostAsJsonAsync("/api/v1/vaults/billing/rename", new { name = "invoices" });
        Assert.Equal(HttpStatusCode.OK, renamed.StatusCode);
        Assert.Contains("\"invoices\"", await renamed.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        // The key is narrowed to the vault, not to its name: it follows.
        Assert.Equal(HttpStatusCode.OK, (await key.GetAsync("/api/v1/vaults/invoices/secrets")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await key.GetAsync("/api/v1/vaults/billing/secrets")).StatusCode);
        Assert.Equal("invoices", (await With<KeyService, IReadOnlyList<KeySummary>>(keys => keys.ListAsync(_admin, _job.Key))).Single(item => item.Key == summary.Key).Vault);

        // The refusals, in the API's words.
        Assert.Equal(HttpStatusCode.Conflict, (await _bootstrap.PostAsJsonAsync("/api/v1/vaults/invoices/rename", new { name = "shop" })).StatusCode);
        Assert.Equal(HttpStatusCode.Conflict, (await _bootstrap.PostAsJsonAsync("/api/v1/vaults/invoices/rename", new { name = "INVOICES" })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _bootstrap.PostAsJsonAsync("/api/v1/vaults/invoices/rename", new { name = "no good" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _bootstrap.PostAsJsonAsync("/api/v1/vaults/billing/rename", new { name = "elsewhere" })).StatusCode);
    }

    [Fact]
    public async Task A_key_can_be_narrowed_to_one_vault_and_capped_at_a_role()
    {
        var (_, onlyBilling) = await NewKey("billing report", vault: "billing");
        var (_, readOnly) = await NewKey("inventory", max: VaultRole.Reader);
        using var billing = Client(onlyBilling);
        using var inventory = Client(readOnly);

        // Only its one vault exists for it, whatever its owner holds elsewhere.
        Assert.Equal(HttpStatusCode.NotFound, (await billing.GetAsync("/api/v1/vaults/shop/secrets")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await billing.GetAsync("/api/v1/vaults/billing/secrets")).StatusCode);

        // Capped at Reader: it lists the vault its owner is an officer of, and reads and writes nothing there.
        Assert.Equal(HttpStatusCode.OK, (await inventory.GetAsync("/api/v1/vaults/shop/secrets")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await inventory.GetAsync("/api/v1/vaults/shop/secrets/token/value")).StatusCode);
        var refused = await inventory.PutAsJsonAsync("/api/v1/vaults/shop/secrets/other", new { value = "generated-x" });
        Assert.Equal(HttpStatusCode.Forbidden, refused.StatusCode);

        // The refusal says that it is the key's limit, not the owner's role, and so does the trail.
        Assert.Contains("This key is limited to Reader; its owner holds Secrets Officer", await refused.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        await using var scope = _factory.Services.CreateAsyncScope();
        var rows = await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Audit.Where(row => row.Code == "access.denied").Select(row => row.Detail).ToListAsync();
        Assert.Contains("needs Secrets Writer or Secrets Officer; the key is limited to Reader, its owner holds Secrets Officer", rows);
        Assert.Contains("needs Secrets User; the key is limited to Reader, its owner holds Secrets Officer", rows);

        // The limit is lifted in place, by an administrator: the same key now follows its owner's role, at its next request.
        var owned = (await With<KeyService, IReadOnlyList<KeySummary>>(keys => keys.ListAsync(_admin, _job.Key))).Single(key => key.Label == "inventory");
        await With<KeyService, bool>(async keys =>
        {
            await keys.SetMaxRoleAsync(_admin, owned.Key, null);
            return true;
        });
        Assert.Equal(HttpStatusCode.OK, (await inventory.PutAsJsonAsync("/api/v1/vaults/shop/secrets/other", new { value = "generated-x" })).StatusCode);
    }

    [Fact]
    public async Task Two_keys_work_at_once_for_a_rotation_a_third_is_refused_and_a_revoked_key_is_refused_on_record()
    {
        var (old, oldSecret) = await NewKey("in use");
        var (_, newSecret) = await NewKey("being rolled out");
        using var before = Client(oldSecret);
        using var after = Client(newSecret);

        Assert.Equal(HttpStatusCode.OK, (await before.GetAsync("/api/v1/vaults/shop/secrets")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await after.GetAsync("/api/v1/vaults/shop/secrets")).StatusCode);
        Assert.Equal("key.too_many", (await Assert.ThrowsAsync<DomainException>(() => NewKey("a third"))).Code);

        await With<KeyService, bool>(async keys =>
        {
            await keys.RevokeAsync(_admin, old.Key);
            return true;
        });

        Assert.Equal(HttpStatusCode.Unauthorized, (await before.GetAsync("/api/v1/vaults/shop/secrets")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await after.GetAsync("/api/v1/vaults/shop/secrets")).StatusCode);
        var audit = await _bootstrap.GetStringAsync("/api/v1/audit");
        Assert.Contains("key.revoked", audit);
        Assert.Contains("\"code\":\"key.refused\",\"severity\":\"Security\"", audit);

        // The slot is free again; the record of the revoked key stays.
        await NewKey("the next one");
        Assert.Equal(3, (await With<KeyService, IReadOnlyList<KeySummary>>(keys => keys.ListAsync(_admin, _job.Key))).Count);
    }

    [Fact]
    public async Task A_key_without_an_end_date_works_until_it_is_revoked_and_making_it_is_a_security_event()
    {
        var (summary, secret) = await NewKey("no end", days: null);
        Assert.Null(summary.ExpiresUtc);
        Assert.True(summary.IsActive(DateTime.UtcNow.AddYears(50)));

        using var client = Client(secret);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/vaults")).StatusCode);

        var made = (await Audit()).First(row => row.Code == "key.created");
        Assert.Equal(AuditSeverity.Security, made.Severity);
        Assert.Contains("no end date", made.Detail, StringComparison.Ordinal);

        // It counts as a working key, and a dated one beside it is an ordinary event.
        await NewKey("dated");
        Assert.Equal(AuditSeverity.Notice, (await Audit()).First(row => row.Code == "key.created").Severity);
        Assert.Equal("key.too_many", (await Assert.ThrowsAsync<DomainException>(() => NewKey("a third"))).Code);

        await With<KeyService, bool>(async keys =>
        {
            await keys.RevokeAsync(_admin, summary.Key);
            return true;
        });
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/vaults")).StatusCode);
    }

    [Fact]
    public async Task A_dated_key_ends_within_the_longest_life_and_nothing_that_is_not_a_key_gets_in()
    {
        Assert.Equal("key.expiry.invalid", (await Assert.ThrowsAsync<DomainException>(() => NewKey("forever", days: 0))).Code);
        Assert.Equal("key.expiry.invalid", (await Assert.ThrowsAsync<DomainException>(() => NewKey("too long", days: 400))).Code);
        Assert.Equal("key.label.invalid", (await Assert.ThrowsAsync<DomainException>(() => NewKey(" "))).Code);

        var (summary, secret) = await NewKey("real");
        using var altered = Client(secret[..^1] + (secret[^1] == 'A' ? 'B' : 'A'));
        using var samePrefix = Client($"shv_{summary.Prefix}_generated-not-the-key");
        using var nonsense = Client("shv_nonsense");

        Assert.Equal(HttpStatusCode.Unauthorized, (await altered.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await samePrefix.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await nonsense.GetAsync("/api/v1/vaults")).StatusCode);

        // Only a hash is kept: the key is nowhere in the database file.
        var database = File.ReadAllBytes(Path.Combine(_directory, "secrethive.db")).Concat(File.Exists(Path.Combine(_directory, "secrethive.db-wal")) ? ReadShared(Path.Combine(_directory, "secrethive.db-wal")) : []).ToArray();
        Assert.DoesNotContain(secret, System.Text.Encoding.Latin1.GetString(database));
    }

    [Fact]
    public async Task A_person_manages_their_own_keys_and_an_administrator_only_those_of_a_service()
    {
        var person = await With<AccountService, User>(async accounts => (await accounts.CreateAsync(new AccountActor(_admin.UserKey!.Value, UserRole.SuperAdmin), "alice", "", "", UserRole.User, "generated-password-1", default)).User!);
        var alice = new Caller("alice", UserKey: person.Key);

        var (mine, _) = await With<KeyService, (KeySummary, string)>(keys => keys.CreateAsync(alice, person.Key, "my script", 30, null, null));

        Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => With<KeyService, (KeySummary, string)>(keys => keys.CreateAsync(_admin, person.Key, "for alice", 30, null, null)))).Code);
        Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => With<KeyService, IReadOnlyList<KeySummary>>(keys => keys.ListAsync(alice, _job.Key)))).Code);
        Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => With<KeyService, bool>(async keys =>
        {
            await keys.RevokeAsync(_admin, mine.Key);
            return true;
        }))).Code);

        // A service identity has no password and cannot be given one: its name is not a way to sign in.
        Assert.Equal(SignInStatus.Invalid, (await With<AccountService, SignInResult>(accounts => accounts.SignInAsync("stack-web-1-shop", "", default))).Status);
        Assert.Equal(AccountOutcome.Forbidden, await With<AccountService, AccountOutcome>(accounts => accounts.ResetPasswordAsync(new AccountActor(_admin.UserKey!.Value, UserRole.SuperAdmin), _job.Key, "generated-password-2", default)));
    }

    private static byte[] ReadShared(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }
}
