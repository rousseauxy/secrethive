using Microsoft.EntityFrameworkCore;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Accounts;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;
using SecretHive.Infrastructure.Sqlite;

namespace SecretHive.Unit.Tests;

/// <summary>
/// Where a vault and a key may be used from: network groups, literal ranges, and the refusals when a caller with
/// every right is in the wrong place.
/// </summary>
public sealed class NetworkTests : IAsyncLifetime
{
    private const string Lan = "192.0.2.10";
    private const string Elsewhere = "198.51.100.9";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-networks-").FullName;
    private KeyRing _keyRing = null!;
    private MasterKey _master = null!;
    private Caller _admin = null!;       // instance admin, no role in the vault
    private Caller _vaultAdmin = null!;
    private Caller _reader = null!;
    private User _job = null!;

    private SecretHiveDbContext NewContext()
    {
        var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
        builder.UseSecretHiveSqlite($"Data Source={Path.Combine(_directory, "networks.db")};Pooling=False");
        return new SecretHiveDbContext(builder.Options);
    }

    private async Task<T> With<T>(Func<SecretService, Task<T>> act)
    {
        await using var context = NewContext();
        return await act(new SecretService(new EfSecretStore(context), _keyRing, TimeProvider.System, new EfAccessStore(context), new EfUserStore(context)));
    }

    private Task With(Func<SecretService, Task> act) => With(async service =>
    {
        await act(service);
        return 0;
    });

    private async Task<T> Groups<T>(Func<NetworkService, Task<T>> act)
    {
        await using var context = NewContext();
        return await act(new NetworkService(new EfAccessStore(context), new AuditWriter(new EfSecretStore(context), TimeProvider.System), TimeProvider.System));
    }

    private Task Groups(Func<NetworkService, Task> act) => Groups(async service =>
    {
        await act(service);
        return 0;
    });

    private async Task<T> Keys<T>(Func<KeyService, Task<T>> act)
    {
        await using var context = NewContext();
        var store = new EfSecretStore(context);
        return await act(new KeyService(new EfKeyStore(context), new EfUserStore(context), store, new AuditWriter(store, TimeProvider.System), TimeProvider.System, new EfAccessStore(context)));
    }

    private static async Task<string> Code(Func<Task> act) => (await Assert.ThrowsAsync<DomainException>(act)).Code;

    private async Task<List<AuditEvent>> Audit(string code)
    {
        await using var context = NewContext();
        return await context.Audit.Where(row => row.Code == code).OrderBy(row => row.Id).ToListAsync();
    }

    private async Task<Caller> AccountAsync(string name, UserRole role)
    {
        await using var context = NewContext();
        var accounts = new AccountService(new EfUserStore(context), new PlatformPasswordHasher(), TimeProvider.System);
        var (_, user) = await accounts.CreateAsync(new AccountActor(-1, UserRole.SuperAdmin), name, "", "", role, "generated-password-123", default);
        return new Caller(name, Lan, "ui", user!.Key, role);
    }

    public async ValueTask InitializeAsync()
    {
        MasterKey.Create(Path.Combine(_directory, "master.key"));
        _master = MasterKey.Load(Path.Combine(_directory, "master.key"));
        _keyRing = new KeyRing(_master);
        await using (var context = NewContext())
        {
            await context.Database.MigrateAsync();
            var accounts = new AccountService(new EfUserStore(context), new PlatformPasswordHasher(), TimeProvider.System);
            _job = (await accounts.CreateServiceAsync(new AccountActor(-1, UserRole.SuperAdmin), "stack-web-1-shop", "", default)).User!;
        }

        _admin = await AccountAsync("an-admin", UserRole.Admin);
        _vaultAdmin = await AccountAsync("vault-admin", UserRole.User);
        _reader = await AccountAsync("reader", UserRole.User);
        var setup = Caller.System("setup");
        await With(service => service.CreateVaultAsync("shop", null, setup));
        await With(service => service.SetAsync(new SetSecret("shop", "token", "generated-shop-value"u8.ToArray()), setup));
        await With(service => service.AssignAsync("shop", _vaultAdmin.UserKey, null, VaultRole.VaultAdmin, setup));
        await With(service => service.AssignAsync("shop", _reader.UserKey, null, VaultRole.SecretsUser, setup));
        await With(service => service.AssignAsync("shop", _job.Key, null, VaultRole.SecretsUser, setup));
    }

    public ValueTask DisposeAsync()
    {
        _keyRing.Dispose();
        _master.Dispose();
        Directory.Delete(_directory, recursive: true);
        return ValueTask.CompletedTask;
    }

    [Theory]
    [InlineData("192.168.10.0/24", "192.168.10.0/24")]
    [InlineData(" 192.168.10.5 ", "192.168.10.5/32")]
    [InlineData("fd7a:115c:a1e0::/48", "fd7a:115c:a1e0::/48")]
    [InlineData("::1", "::1/128")]
    [InlineData("::ffff:192.0.2.1", "192.0.2.1/32")]
    public void A_range_is_kept_in_one_form(string written, string kept) => Assert.Equal(kept, Networks.Normalize(written));

    [Theory]
    [InlineData("")]
    [InlineData("the lan")]
    [InlineData("192.168.10.5/24")] // reads as one host, matches 256
    [InlineData("192.168.10.0/33")]
    [InlineData("0.0.0.0/0")]       // limits nothing
    [InlineData("::/0")]
    [InlineData("192.168.10.0/24; drop table")]
    public void What_is_not_a_range_is_refused(string written) =>
        Assert.Equal("network.range.invalid", Assert.Throws<DomainException>(() => Networks.Normalize(written)).Code);

    [Fact]
    public void An_address_is_inside_a_range_or_it_is_not_and_an_unreadable_one_never_is()
    {
        string[] ranges = ["192.0.2.0/24", "fd7a::/16"];
        Assert.True(Networks.Contains(ranges, "192.0.2.200"));
        Assert.True(Networks.Contains(ranges, "::ffff:192.0.2.200"));
        Assert.True(Networks.Contains(ranges, "fd7a::1"));
        Assert.False(Networks.Contains(ranges, "192.0.3.1"));
        Assert.False(Networks.Contains(ranges, null));
        Assert.False(Networks.Contains(ranges, "unknown"));
        Assert.False(Networks.Contains([], "192.0.2.1"));
    }

    [Fact]
    public async Task A_vault_with_networks_listed_refuses_its_secrets_from_anywhere_else_whatever_the_role()
    {
        // Nothing listed: from anywhere.
        using (var open = await With(service => service.ReadAsync("shop", "token", _reader with { Address = Elsewhere })))
        {
            Assert.Equal(20, open.Length);
        }

        await With(service => service.AllowNetworkAsync("shop", null, "192.0.2.0/24", _vaultAdmin));

        // Inside: as before. Outside: refused for the reader, the Vault Admin and the token that may do everything.
        using (var inside = await With(service => service.ReadAsync("shop", "token", _reader)))
        {
            Assert.Equal(20, inside.Length);
        }

        var everything = new Caller("bootstrap-token", Elsewhere, Unrestricted: true);
        foreach (var caller in new[] { _reader with { Address = Elsewhere }, _vaultAdmin with { Address = Elsewhere }, everything, _reader with { Address = null } })
        {
            Assert.Equal("access.network.refused", await Code(() => With(service => service.ReadAsync("shop", "token", caller))));
            Assert.Equal("access.network.refused", await Code(() => With(service => service.ListAsync("shop", caller))));
            Assert.Equal("access.network.refused", await Code(() => With(service => service.SetAsync(new SetSecret("shop", "token", "generated-x"u8.ToArray()), caller))));
        }

        var refusals = await Audit("access.network.refused");
        Assert.Equal(12, refusals.Count);
        Assert.All(refusals, row => Assert.Equal((AuditSeverity.Security, "shop"), (row.Severity, row.Vault)));
        Assert.Contains(refusals, row => row.Principal == "reader" && row.Address == Elsewhere);

        // The value was not changed by the refused writes, and the server's own jobs are not callers from a network.
        using (var value = await With(service => service.ReadAsync("shop", "token", Caller.System("retention"))))
        {
            Assert.Equal("generated-shop-value", System.Text.Encoding.UTF8.GetString(value.Reveal()));
        }

        // Someone with no role still learns nothing, not even that a network rule exists.
        var stranger = new Caller("stranger", Elsewhere, UserKey: 9999);
        Assert.Equal("vault.not_found", await Code(() => With(service => service.ReadAsync("shop", "token", stranger))));

        // Whoever manages access can still see and correct the list from outside it: a wrong range is not a lock-out.
        var outside = _vaultAdmin with { Address = Elsewhere };
        var line = Assert.Single(await With(service => service.ListNetworksAsync("shop", outside)));
        Assert.Equal("192.0.2.0/24", line.Label);
        Assert.NotEmpty(await With(service => service.ListAccessAsync("shop", outside)));
        await With(service => service.AllowNetworkAsync("shop", null, "198.51.100.0/24", outside));
        using (var corrected = await With(service => service.ReadAsync("shop", "token", _reader with { Address = Elsewhere })))
        {
            Assert.Equal(20, corrected.Length);
        }

        // A reader of the vault decides nothing about its networks.
        Assert.Equal("access.denied", await Code(() => With(service => service.AllowNetworkAsync("shop", null, "203.0.113.0/24", _reader))));
        Assert.Equal("access.denied", await Code(() => With(service => service.ListNetworksAsync("shop", _reader))));
        Assert.Equal("network.line.exists", await Code(() => With(service => service.AllowNetworkAsync("shop", null, "192.0.2.0/24", _vaultAdmin))));
        Assert.Equal("network.line.invalid", await Code(() => With(service => service.AllowNetworkAsync("shop", null, null, _vaultAdmin))));

        // Taking lines away is quiet until the last one, which opens the vault to every address again.
        var lines = await With(service => service.ListNetworksAsync("shop", _vaultAdmin));
        await With(service => service.DisallowNetworkAsync("shop", lines[0].Key, _vaultAdmin));
        await With(service => service.DisallowNetworkAsync("shop", lines[1].Key, _vaultAdmin));
        var removed = await Audit("vault.network.removed");
        Assert.Equal([AuditSeverity.Notice, AuditSeverity.Security], removed.Select(row => row.Severity));
        Assert.Contains("no longer limited", removed[1].Detail, StringComparison.Ordinal);
        using var anywhere = await With(service => service.ReadAsync("shop", "token", _reader with { Address = "203.0.113.50" }));
        Assert.Equal(20, anywhere.Length);
    }

    [Fact]
    public async Task A_network_group_is_edited_by_administrators_only_and_a_change_says_how_far_it_reaches()
    {
        Assert.Equal("access.denied", await Code(() => Groups(service => service.CreateAsync("tailnet", null, "100.64.0.0/10", _vaultAdmin))));
        await Groups(service => service.CreateAsync("tailnet", "the tailnet", "100.64.0.0/10", _admin));
        Assert.Equal("network.group.exists", await Code(() => Groups(service => service.CreateAsync("Tailnet", null, "", _admin))));
        Assert.Equal("network.range.invalid", await Code(() => Groups(service => service.CreateAsync("broken", null, "10.0.0.5/8", _admin))));
        var group = Assert.Single(await Groups(service => service.ListAsync(_admin)));
        Assert.Equal((0, 0), (group.Vaults, group.Keys));

        // A Vault Admin attaches an existing group to their own vault; they cannot change what the group is.
        await With(service => service.AllowNetworkAsync("shop", group.Key, null, _vaultAdmin));
        Assert.Equal("access.denied", await Code(() => Groups(service => service.UpdateAsync(group.Key, null, "0.0.0.0/1", _vaultAdmin))));
        Assert.Equal("access.denied", await Code(() => Groups(service => service.ListAsync(_vaultAdmin))));
        var (made, _) = await Keys(keys => keys.CreateAsync(_admin, _job.Key, "deploy", 30, null, null));
        await Keys(async keys =>
        {
            await keys.AllowNetworkAsync(_admin, made.Key, group.Key, null);
            return 0;
        });

        // The vault follows the group at once: inside the tailnet yes, on the LAN no.
        using (var inside = await With(service => service.ReadAsync("shop", "token", _reader with { Address = "100.64.0.4" })))
        {
            Assert.Equal(20, inside.Length);
        }

        Assert.Equal("access.network.refused", await Code(() => With(service => service.ReadAsync("shop", "token", _reader))));

        // Adding a range to the group opens the vault and the key in one edit: a security event that says so.
        await Groups(service => service.UpdateAsync(group.Key, "tailnet and LAN", "100.64.0.0/10\n192.0.2.0/24", _admin));
        using (var lan = await With(service => service.ReadAsync("shop", "token", _reader)))
        {
            Assert.Equal(20, lan.Length);
        }

        var widened = Assert.Single(await Audit("network.group.changed"));
        Assert.Equal(AuditSeverity.Security, widened.Severity);
        Assert.Equal("tailnet: 100.64.0.0/10 -> 100.64.0.0/10 192.0.2.0/24; reaches 1 vaults, 1 keys", widened.Detail);

        // Narrowing it is on record without the alarm; emptying it allows nothing rather than everything.
        await Groups(service => service.UpdateAsync(group.Key, null, "", _admin));
        Assert.Equal(AuditSeverity.Notice, (await Audit("network.group.changed"))[1].Severity);
        Assert.Equal("access.network.refused", await Code(() => With(service => service.ReadAsync("shop", "token", _reader))));
        Assert.Equal("access.network.refused", await Code(() => With(service => service.ReadAsync("shop", "token", _reader with { Address = "100.64.0.4" }))));

        // A group that is still listed is not deleted from under what relies on it.
        Assert.Equal("network.group.in_use", await Code(() => Groups(service => service.DeleteAsync(group.Key, _admin))));
        var line = Assert.Single(await With(service => service.ListNetworksAsync("shop", _vaultAdmin)));
        Assert.Equal(("tailnet", group.Key), (line.Label, line.GroupKey!.Value));
        await With(service => service.DisallowNetworkAsync("shop", line.Key, _vaultAdmin));
        Assert.Equal("network.group.in_use", await Code(() => Groups(service => service.DeleteAsync(group.Key, _admin))));
        var keyLine = Assert.Single((await Keys(keys => keys.ListAsync(_admin, _job.Key))).Single().Networks);
        await Keys(async keys =>
        {
            await keys.DisallowNetworkAsync(_admin, made.Key, keyLine.Key);
            return 0;
        });
        await Groups(service => service.DeleteAsync(group.Key, _admin));
        Assert.Empty(await Groups(service => service.ListAsync(_admin)));
    }

    [Fact]
    public async Task A_key_limited_to_a_network_is_no_credential_anywhere_else_and_the_attempt_is_on_record()
    {
        var (made, secret) = await Keys(keys => keys.CreateAsync(_admin, _job.Key, "deploy on web-1", 30, null, null));
        Assert.NotNull(await Keys(keys => keys.AuthenticateAsync(secret, Elsewhere)));

        await Keys(async keys =>
        {
            await keys.AllowNetworkAsync(_admin, made.Key, null, Lan);
            return 0;
        });
        Assert.NotNull(await Keys(keys => keys.AuthenticateAsync(secret, Lan)));
        Assert.Null(await Keys(keys => keys.AuthenticateAsync(secret, Elsewhere)));
        Assert.Null(await Keys(keys => keys.AuthenticateAsync(secret, null)));

        var refused = await Audit("access.network.refused");
        Assert.Equal(2, refused.Count);
        Assert.Equal((AuditSeverity.Security, "stack-web-1-shop", Elsewhere), (refused[0].Severity, refused[0].Principal, refused[0].Address));
        Assert.DoesNotContain(secret, refused[0].Detail!, StringComparison.Ordinal);

        // A key's own limit and the vault's are both held: inside the key's network and outside the vault's is still refused.
        await With(service => service.AllowNetworkAsync("shop", null, "203.0.113.0/24", _vaultAdmin));
        var identity = (await Keys(keys => keys.AuthenticateAsync(secret, Lan)))!;
        var asKey = new Caller(identity.Owner.UserName, Lan, "api", identity.Owner.Key, KeyId: identity.Key.Key);
        Assert.Equal("access.network.refused", await Code(() => With(service => service.ReadAsync("shop", "token", asKey))));

        // Only its owner, or an administrator for a service identity, changes where a key works.
        Assert.Equal("access.denied", await Code(() => Keys(async keys =>
        {
            await keys.AllowNetworkAsync(_reader, made.Key, null, Elsewhere);
            return 0;
        })));
        var line = Assert.Single((await Keys(keys => keys.ListAsync(_admin, _job.Key))).Single().Networks);
        await Keys(async keys =>
        {
            await keys.DisallowNetworkAsync(_admin, made.Key, line.Key);
            return 0;
        });
        Assert.NotNull(await Keys(keys => keys.AuthenticateAsync(secret, Elsewhere)));
        Assert.Equal(AuditSeverity.Security, Assert.Single(await Audit("key.network.removed")).Severity);
    }
}
