using System.Text;
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
/// Who may do what: the four roles in a vault, groups, and what an instance administrator can and cannot do.
/// Every check is made in the use case, so these tests go through nothing else.
/// </summary>
public sealed class VaultAccessTests : IAsyncLifetime
{
    private const string Password = "generated-password-123";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-access-").FullName;
    private KeyRing _keyRing = null!;

    private Caller _root = null!;      // super admin
    private Caller _admin = null!;     // admin
    private Caller _reader = null!;
    private Caller _user = null!;
    private Caller _officer = null!;
    private Caller _vaultAdmin = null!;
    private Caller _stranger = null!;
    private Caller _teamMember = null!;

    private SecretHiveDbContext NewContext()
    {
        var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
        builder.UseSecretHiveSqlite($"Data Source={Path.Combine(_directory, "access.db")};Pooling=False");
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

    private async Task<T> Groups<T>(Func<GroupService, Task<T>> act)
    {
        await using var context = NewContext();
        var store = new EfSecretStore(context);
        return await act(new GroupService(new EfAccessStore(context), new EfUserStore(context), new AuditWriter(store, TimeProvider.System), TimeProvider.System));
    }

    private async Task<string> CodeOf(Func<SecretService, Task> act) => (await Assert.ThrowsAsync<DomainException>(() => With(act))).Code;

    private async Task<Caller> AccountAsync(string name, UserRole role)
    {
        await using var context = NewContext();
        var accounts = new AccountService(new EfUserStore(context), new PlatformPasswordHasher(), TimeProvider.System);
        var (_, user) = await accounts.CreateAsync(new AccountActor(-1, UserRole.SuperAdmin), name, "", "", role, Password, default);
        return new Caller(name, "192.0.2.1", "ui", user!.Key, role);
    }

    private static ReadOnlyMemory<byte> Bytes(string text) => Encoding.UTF8.GetBytes(text);

    public async ValueTask InitializeAsync()
    {
        var keyPath = Path.Combine(_directory, "master.key");
        MasterKey.Create(keyPath);
        _keyRing = new KeyRing(MasterKey.Load(keyPath));
        await using (var context = NewContext())
        {
            await context.Database.MigrateAsync();
        }

        _root = await AccountAsync("root", UserRole.SuperAdmin);
        _admin = await AccountAsync("ops", UserRole.Admin);
        _reader = await AccountAsync("reader", UserRole.User);
        _user = await AccountAsync("user", UserRole.User);
        _officer = await AccountAsync("officer", UserRole.User);
        _vaultAdmin = await AccountAsync("vault-admin", UserRole.User);
        _stranger = await AccountAsync("stranger", UserRole.User);
        _teamMember = await AccountAsync("team-member", UserRole.User);

        // The admin makes the vault, and so runs it; everyone else gets a role from them.
        await With(service => service.CreateVaultAsync("shop", null, _admin));
        await With(service => service.AssignAsync("shop", _reader.UserKey, null, VaultRole.Reader, _admin));
        await With(service => service.AssignAsync("shop", _user.UserKey, null, VaultRole.SecretsUser, _admin));
        await With(service => service.AssignAsync("shop", _officer.UserKey, null, VaultRole.SecretsOfficer, _admin));
        await With(service => service.AssignAsync("shop", _vaultAdmin.UserKey, null, VaultRole.VaultAdmin, _admin));
        await With(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-value"), Fields: [new FieldInput("owner", Bytes("team-a")), new FieldInput("pin", Bytes("generated-pin"), Sensitive: true)]), _officer));
    }

    public ValueTask DisposeAsync()
    {
        _keyRing.Dispose();
        Directory.Delete(_directory, recursive: true);
        return ValueTask.CompletedTask;
    }

    [Fact]
    public async Task The_home_page_counts_pins_and_lists_changes_and_ending_certificates_only_where_the_caller_may_see()
    {
        var site = new TestCertificate("soon.example.test", validDays: 10);
        await With(service => service.ImportCertificateAsync(new ImportCertificate("shop", "site", [site.CertificatePart, site.PfxPart, TestCertificate.PasswordPart()]), _officer));
        var home = await With(service => service.HomeAsync(_user));
        var shop = Assert.Single(home.Vaults);
        Assert.Equal((2, VaultRole.SecretsUser, false), (shop.Secrets, shop.Role, shop.Pinned));
        Assert.Contains(home.Changed, change => change.Secret == "token" && change.Vault == "shop" && change.By == "officer");
        Assert.Equal("site", Assert.Single(home.Ending).Secret);
        Assert.Null(home.SecurityEvents24h);
        Assert.NotNull((await With(service => service.HomeAsync(_root))).SecurityEvents24h);
        Assert.Empty((await With(service => service.HomeAsync(_stranger))).Vaults);

        // Pins are one's own: a vault and a secret, pinning twice is once, and nobody else sees them.
        await With(service => service.SetPinAsync("shop", null, true, _user));
        await With(service => service.SetPinAsync("shop", "token", true, _user));
        await With(service => service.SetPinAsync("shop", "token", true, _user));
        home = await With(service => service.HomeAsync(_user));
        Assert.True(Assert.Single(home.Vaults).Pinned);
        Assert.Equal("token", Assert.Single(home.PinnedSecrets).Name);
        Assert.True(await With(service => service.IsPinnedAsync("shop", "token", _user)));
        Assert.False(await With(service => service.IsPinnedAsync("shop", "token", _officer)));
        Assert.Equal([("shop", (string?)null), ("shop", "token")], await With(service => service.ListPinsAsync(_user)));

        // Nobody pins what they cannot see, and a caller that is no account keeps no pins.
        Assert.Equal("vault.not_found", await CodeOf(service => service.SetPinAsync("shop", null, true, _stranger)));
        Assert.Equal("pin.no_account", await CodeOf(service => service.SetPinAsync("shop", null, true, new Caller("job", Groups: [1]))));

        // A pin on a deleted secret is not shown.
        await With(service => service.DeleteAsync("shop", "token", _officer));
        Assert.Empty((await With(service => service.HomeAsync(_user))).PinnedSecrets);

        // Where the vault's networks refuse the caller, the home page says nothing of what is in it.
        await With(service => service.AllowNetworkAsync("shop", null, "198.51.100.0/24", _admin));
        home = await With(service => service.HomeAsync(_user));
        Assert.Null(Assert.Single(home.Vaults).Secrets);
        Assert.Empty(home.Changed);
        Assert.Empty(home.Ending);
    }

    [Fact]
    public async Task A_role_on_a_folder_counts_in_every_vault_beneath_it_and_leaves_with_the_vault()
    {
        // oci > apps > shop: a role on the top folder reaches the vault two levels down.
        await With(service => service.CreateFolderAsync("oci", null, "everything on OCI", _admin));
        await With(service => service.CreateFolderAsync("apps", "oci", null, _admin));
        await With(service => service.MoveVaultToFolderAsync("shop", "apps", _admin));
        Assert.Null(await With(service => service.RoleAsync("shop", _stranger)));

        await With(service => service.AssignFolderAsync("oci", _stranger.UserKey, null, VaultRole.SecretsUser, _admin));
        Assert.Equal(VaultRole.SecretsUser, await With(service => service.RoleAsync("shop", _stranger)));
        using (var value = await With(service => service.ReadAsync("shop", "token", _stranger)))
        {
            Assert.Equal("generated-value", Encoding.UTF8.GetString(value.Reveal()));
        }

        // It only adds: a higher role in the vault itself stays, and the two add up.
        await With(service => service.AssignFolderAsync("apps", _reader.UserKey, null, VaultRole.SecretsWriter, _admin));
        Assert.Equal(VaultRole.SecretsUser, await With(service => service.RoleAsync("shop", _user)));
        Assert.True(await With(service => service.CanSetAsync("shop", _reader)));

        // The vault's access list shows what it inherits, and from where; the folder's list shows its own.
        var listed = await With(service => service.ListAccessAsync("shop", _admin));
        Assert.Contains(listed, entry => entry.Name == "stranger" && entry.Role == VaultRole.SecretsUser && entry.From == "oci");
        Assert.Contains(listed, entry => entry.Name == "reader" && entry.Role == VaultRole.Reader && entry.From is null);
        Assert.Contains(listed, entry => entry.Name == "reader" && entry.Role == VaultRole.SecretsWriter && entry.From == "apps");
        var onApps = await With(service => service.ListFolderAccessAsync("apps", _admin));
        Assert.Contains(onApps, entry => entry.Name == "reader" && entry.From is null);
        Assert.Contains(onApps, entry => entry.Name == "stranger" && entry.From == "oci");

        // Out of the folder, the inherited role is gone at once.
        await With(service => service.MoveVaultToFolderAsync("shop", null, _admin));
        Assert.Null(await With(service => service.RoleAsync("shop", _stranger)));
        Assert.Equal("vault.not_found", await CodeOf(service => service.ReadAsync("shop", "token", _stranger)));
    }

    [Fact]
    public async Task A_move_says_who_gains_and_who_loses_and_is_a_security_event_when_anyone_gains()
    {
        await Groups(service => service.CreateAsync("operations", null, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        var operations = Assert.Single(await Groups(service => service.ListAsync(_admin)));
        await With(service => service.CreateFolderAsync("prod", null, null, _admin));
        await With(service => service.CreateFolderAsync("test", null, null, _admin));
        await With(service => service.AssignFolderAsync("prod", null, operations.Key, VaultRole.SecretsOfficer, _admin));
        await With(service => service.AssignFolderAsync("test", _stranger.UserKey, null, VaultRole.Reader, _admin));

        await With(service => service.MoveVaultToFolderAsync("shop", "prod", _admin));
        await With(service => service.MoveVaultToFolderAsync("shop", "test", _admin));
        var trail = await With(service => service.AuditAsync(50, _root));
        var moves = trail.Where(row => row.Code == "vault.folder.changed").OrderBy(row => row.Id).ToList();
        Assert.Equal(2, moves.Count);
        Assert.Equal(AuditSeverity.Security, moves[0].Severity);
        Assert.Equal("into prod; gains: group operations Secrets Officer", moves[0].Detail);
        Assert.Equal(AuditSeverity.Security, moves[1].Severity);
        Assert.Equal("into test; gains: user stranger Reader; loses: group operations", moves[1].Detail);

        // Only losing is no security event; nor is a move between folders that give the same.
        await With(service => service.MoveVaultToFolderAsync("shop", null, _admin));
        var last = (await With(service => service.AuditAsync(5, _root))).First(row => row.Code == "vault.folder.changed");
        Assert.Equal((AuditSeverity.Notice, "to the top; loses: user stranger"), (last.Severity, last.Detail));

        // A grant on a folder always is one, and says how far it reaches.
        var granted = trail.Where(row => row.Code == "folder.role.assigned").OrderBy(row => row.Id).First();
        Assert.Equal((AuditSeverity.Security, "folder prod: group operations = Secrets Officer, reaching 0 vault(s)"), (granted.Severity, granted.Detail));

        // Moving a folder carries what it inherits along: the vault in it gains what the new parent gives.
        await With(service => service.CreateFolderAsync("inner", null, null, _admin));
        await With(service => service.MoveVaultToFolderAsync("shop", "inner", _admin));
        await With(service => service.MoveFolderAsync("inner", "prod", _admin));
        Assert.Equal(VaultRole.SecretsOfficer, await With(service => service.RoleAsync("shop", new Caller("job", Groups: [operations.Key]))));
        var moved = (await With(service => service.AuditAsync(5, _root))).First(row => row.Code == "folder.moved");
        Assert.Equal((AuditSeverity.Security, "folder inner: into prod; gains: group operations Secrets Officer"), (moved.Severity, moved.Detail));
    }

    [Fact]
    public async Task Only_an_administrator_arranges_folders_and_the_tree_stays_a_tree()
    {
        Assert.Equal("access.denied", await CodeOf(service => service.CreateFolderAsync("oci", null, null, _vaultAdmin)));
        await With(service => service.CreateFolderAsync("oci", null, null, _admin));
        await With(service => service.CreateFolderAsync("apps", "oci", null, _admin));
        await With(service => service.CreateFolderAsync("web", "apps", null, _admin));

        Assert.Equal("access.denied", await CodeOf(service => service.AssignFolderAsync("oci", _stranger.UserKey, null, VaultRole.VaultAdmin, _vaultAdmin)));
        Assert.Equal("access.denied", await CodeOf(service => service.MoveVaultToFolderAsync("shop", "oci", _vaultAdmin)));
        Assert.Equal("access.denied", await CodeOf(service => service.ListFolderAccessAsync("oci", _vaultAdmin)));
        Assert.Equal("folder.exists", await CodeOf(service => service.CreateFolderAsync("APPS", null, null, _admin)));
        Assert.Equal("folder.name.invalid", await CodeOf(service => service.CreateFolderAsync("no good", null, null, _admin)));
        Assert.Equal("folder.not_found", await CodeOf(service => service.CreateFolderAsync("x", "nowhere", null, _admin)));
        Assert.Equal("folder.move.circle", await CodeOf(service => service.MoveFolderAsync("oci", "web", _admin)));
        Assert.Equal("folder.move.circle", await CodeOf(service => service.MoveFolderAsync("apps", "apps", _admin)));
        Assert.Equal("folder.move.same", await CodeOf(service => service.MoveFolderAsync("web", "apps", _admin)));

        await With(service => service.MoveVaultToFolderAsync("shop", "web", _admin));
        Assert.Equal("vault.folder.same", await CodeOf(service => service.MoveVaultToFolderAsync("shop", "web", _admin)));
        Assert.Equal("folder.not_empty", await CodeOf(service => service.DeleteFolderAsync("web", _admin)));
        Assert.Equal("folder.not_empty", await CodeOf(service => service.DeleteFolderAsync("apps", _admin)));

        // A rename keeps the vaults and the roles; an empty folder goes, with its roles.
        await With(service => service.AssignFolderAsync("web", _stranger.UserKey, null, VaultRole.Reader, _admin));
        await With(service => service.RenameFolderAsync("web", "websites", _admin));
        Assert.Equal(VaultRole.Reader, await With(service => service.RoleAsync("shop", _stranger)));
        Assert.Equal("websites", Assert.Single(await With(service => service.ListVaultsAsync(_admin))).Folder);
        await With(service => service.MoveVaultToFolderAsync("shop", null, _admin));
        await With(service => service.DeleteFolderAsync("websites", _admin));
        Assert.Null(await With(service => service.RoleAsync("shop", _stranger)));
        Assert.Equal(["oci", "apps"], (await With(service => service.ListFoldersAsync(_admin))).Select(folder => folder.Name));
    }

    [Fact]
    public async Task A_key_stays_within_its_vault_and_its_cap_whatever_a_folder_gives()
    {
        await With(service => service.CreateVaultAsync("mail", null, _admin));
        await With(service => service.CreateFolderAsync("all", null, null, _admin));
        await With(service => service.MoveVaultToFolderAsync("shop", "all", _admin));
        await With(service => service.MoveVaultToFolderAsync("mail", "all", _admin));
        await With(service => service.AssignFolderAsync("all", _stranger.UserKey, null, VaultRole.SecretsOfficer, _admin));
        var shop = Assert.Single(await With(service => service.ListVaultsAsync(_admin)), vault => vault.Name == "shop");
        Assert.Equal("all", shop.Folder);

        var vaultId = await VaultIdAsync("shop");
        var key = _stranger with { KeyId = 7, OnlyVault = vaultId, MaxRole = VaultRole.Reader };
        Assert.Equal(VaultRole.Reader, await With(service => service.RoleAsync("shop", key)));
        Assert.Null(await With(service => service.RoleAsync("mail", key)));
        Assert.Equal(VaultRole.SecretsOfficer, await With(service => service.RoleAsync("mail", _stranger)));
    }

    [Fact]
    public async Task Someone_who_is_no_administrator_sees_only_the_folders_on_the_way_to_their_vaults()
    {
        await With(service => service.CreateVaultAsync("mail", null, _admin));
        await With(service => service.CreateFolderAsync("oci", null, null, _admin));
        await With(service => service.CreateFolderAsync("apps", "oci", null, _admin));
        await With(service => service.CreateFolderAsync("secret-project", null, null, _admin));
        await With(service => service.MoveVaultToFolderAsync("shop", "apps", _admin));
        await With(service => service.MoveVaultToFolderAsync("mail", "secret-project", _admin));

        Assert.Equal(["oci", "apps"], (await With(service => service.ListFoldersAsync(_reader))).Select(folder => folder.Name));
        Assert.Equal(["oci", "apps"], Assert.Single(await With(service => service.ListMyVaultsAsync(_reader))).Folders);
        Assert.Empty(await With(service => service.ListFoldersAsync(_stranger)));
        Assert.Equal(3, (await With(service => service.ListFoldersAsync(_admin))).Count);

        // Made straight into a folder, a vault inherits from the start, and the creation says so.
        await With(service => service.AssignFolderAsync("oci", _stranger.UserKey, null, VaultRole.Reader, _admin));
        await With(service => service.CreateVaultAsync("web", null, _admin, "apps"));
        Assert.Equal(VaultRole.Reader, await With(service => service.RoleAsync("web", _stranger)));
        var created = (await With(service => service.AuditAsync(5, _root))).First(row => row.Code == "vault.created");
        Assert.Equal((AuditSeverity.Security, "in apps; gains: user stranger Reader"), (created.Severity, created.Detail));
    }

    private async Task<Guid> VaultIdAsync(string name)
    {
        await using var context = NewContext();
        return (await context.Vaults.AsNoTracking().FirstAsync(vault => vault.Name == name)).Id;
    }

    [Fact]
    public async Task The_list_beside_the_pages_holds_each_vault_a_caller_has_a_role_in_with_that_role()
    {
        await With(service => service.CreateVaultAsync("mail", null, _admin));
        await With(service => service.AssignAsync("mail", _officer.UserKey, null, VaultRole.SecretsOfficer, _admin));

        Assert.Equal([("mail", VaultRole.SecretsOfficer), ("shop", VaultRole.SecretsOfficer)], (await With(service => service.ListMyVaultsAsync(_officer))).Select(vault => (vault.Name, vault.Role)));
        Assert.Equal([("shop", VaultRole.Reader)], (await With(service => service.ListMyVaultsAsync(_reader))).Select(vault => (vault.Name, vault.Role)));
        Assert.Empty(await With(service => service.ListMyVaultsAsync(_stranger)));

        // An administrator without a role sees every vault, as a Reader.
        Assert.All(await With(service => service.ListMyVaultsAsync(_root)), vault => Assert.Equal(VaultRole.Reader, vault.Role));
        Assert.Equal(2, (await With(service => service.ListMyVaultsAsync(_root))).Count);
    }

    [Fact]
    public async Task A_vault_does_not_exist_for_someone_with_no_role_in_it()
    {
        Assert.Empty(await With(service => service.ListVaultsAsync(_stranger)));
        Assert.Equal("vault.not_found", await CodeOf(service => service.ListAsync("shop", _stranger)));
        Assert.Equal("vault.not_found", await CodeOf(service => service.ReadAsync("shop", "token", _stranger)));
        Assert.Equal("vault.not_found", await CodeOf(service => service.SetAsync(new SetSecret("shop", "mine", Bytes("generated")), _stranger)));
        Assert.Null(await With(service => service.RoleAsync("shop", _stranger)));
    }

    [Fact]
    public async Task A_reader_sees_what_exists_and_never_a_value()
    {
        var listed = Assert.Single(await With(service => service.ListAsync("shop", _reader)));

        Assert.Equal(("token", "team-a"), (listed.Name, listed.Fields["owner"]));
        Assert.Equal(["pin"], listed.SensitiveFields);
        Assert.Equal("access.denied", await CodeOf(service => service.ReadAsync("shop", "token", _reader)));
        Assert.Equal("access.denied", await CodeOf(service => service.ReadAsync("shop", "token", _reader, "field:pin")));
        Assert.Equal("access.denied", await CodeOf(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-two")), _reader)));
        Assert.Equal("access.denied", await CodeOf(service => service.AuditAsync(10, _reader, "shop")));

        // The refusal is on record, with what was needed and what was held, and no read happened.
        var audit = await With(service => service.AuditAsync(50, _root));
        Assert.Contains(audit, row => row.Code == "access.denied" && row.Principal == "reader" && row.Detail == "needs Secrets User, has Reader");
        Assert.DoesNotContain(audit, row => row.Code == "secret.value.read" && row.Principal == "reader");
    }

    [Fact]
    public async Task A_secrets_user_reads_values_and_changes_nothing()
    {
        using var value = await With(service => service.ReadAsync("shop", "token", _user));
        using var pin = await With(service => service.ReadAsync("shop", "token", _user, "field:pin"));

        Assert.Equal("generated-value", Encoding.UTF8.GetString(value.Reveal()));
        Assert.Equal("generated-pin", Encoding.UTF8.GetString(pin.Reveal()));
        Assert.Equal("access.denied", await CodeOf(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-two")), _user)));
        Assert.Equal("access.denied", await CodeOf(service => service.DeleteAsync("shop", "token", _user)));
        Assert.Equal("access.denied", await CodeOf(service => service.UpdateDetailsAsync("shop", "token", "changed", [], _user)));
        Assert.Equal("access.denied", await CodeOf(service => service.ListAsync("shop", _user, bin: true)));
    }

    [Fact]
    public async Task A_secrets_writer_sets_values_and_stores_certificates_and_never_reads_one()
    {
        var writer = await AccountAsync("rotation", UserRole.User);
        await With(service => service.AssignAsync("shop", writer.UserKey, null, VaultRole.SecretsWriter, _admin));
        Assert.Equal(VaultRole.SecretsWriter, await With(service => service.RoleAsync("shop", writer)));

        // It sees what a Reader sees.
        var listed = Assert.Single(await With(service => service.ListAsync("shop", writer)));
        Assert.Equal(("token", "team-a"), (listed.Name, listed.Fields["owner"]));
        Assert.Equal(["pin"], listed.SensitiveFields);
        Assert.Single(await With(service => service.ListVersionsAsync("shop", "token", writer)));

        // It sets a new version, a new secret, and a certificate. What it does not name stays, unread.
        Assert.Equal(2, await With(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-rotated"), Merge: true), writer)));
        Assert.Equal(1, await With(service => service.SetAsync(new SetSecret("shop", "fresh", Bytes("generated-fresh")), writer)));
        var site = new TestCertificate("shop.example.test");
        Assert.Equal(1, await With(service => service.ImportCertificateAsync(new ImportCertificate("shop", "site", [site.CertificatePart, site.KeyPart]), writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.ReadPartAsync("shop", "site", CertificatePartKind.Key, writer)));
        using (var rotated = await With(service => service.ReadAsync("shop", "token", _user)))
        using (var pin = await With(service => service.ReadAsync("shop", "token", _user, "field:pin")))
        {
            Assert.Equal("generated-rotated", Encoding.UTF8.GetString(rotated.Reveal()));
            Assert.Equal("generated-pin", Encoding.UTF8.GetString(pin.Reveal()));
        }

        // It reads nothing: not the value it just set, not a field, not an earlier version, not through a copy.
        Assert.Equal("access.denied", await CodeOf(service => service.ReadAsync("shop", "token", writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.ReadAsync("shop", "fresh", writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.ReadAsync("shop", "token", writer, "field:pin")));
        Assert.Equal("access.denied", await CodeOf(service => service.ReadAsync("shop", "token", writer, number: 1)));
        await With(service => service.CreateVaultAsync("spare", null, _admin));
        await With(service => service.AssignAsync("spare", writer.UserKey, null, VaultRole.VaultAdmin, _admin));
        Assert.Equal("access.denied", await CodeOf(service => service.CopyAsync("shop", "token", "spare", null, writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.MoveAsync("shop", "token", "spare", null, writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.LinkAsync("shop", "token", "spare", null, writer)));

        // And it changes nothing else.
        Assert.Equal("access.denied", await CodeOf(service => service.DeleteAsync("shop", "token", writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.RestoreVersionAsync("shop", "token", 1, writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.UpdateDetailsAsync("shop", "token", "changed", [], writer)));
        Assert.Equal("access.denied", await CodeOf(service => service.ListAsync("shop", writer, bin: true)));
        Assert.Equal("access.denied", await CodeOf(service => service.AuditAsync(10, writer, "shop")));
        Assert.Equal("access.denied", await CodeOf(service => service.AssignAsync("shop", _stranger.UserKey, null, VaultRole.Reader, writer)));

        // On record: what it set, what it was refused, and no read.
        var audit = await With(service => service.AuditAsync(100, _root));
        Assert.Contains(audit, row => row.Code == "secret.version.set" && row.Principal == "rotation");
        Assert.Contains(audit, row => row.Code == "access.denied" && row.Principal == "rotation" && row.Detail == "needs Secrets User, has Secrets Writer");
        Assert.Contains(audit, row => row.Code == "access.denied" && row.Principal == "rotation" && row.Detail == "needs Secrets Officer, has Secrets Writer");
        Assert.DoesNotContain(audit, row => row.Code == "secret.value.read" && row.Principal == "rotation");

        // Whoever may not set is told which roles may.
        Assert.Equal("access.denied", await CodeOf(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-no")), _user)));
        Assert.Contains(await With(service => service.AuditAsync(5, _root)), row => row.Detail == "needs Secrets Writer or Secrets Officer, has Secrets User");
        Assert.True(await With(service => service.CanSetAsync("shop", writer)));
        Assert.True(await With(service => service.CanSetAsync("shop", _officer)));
        Assert.False(await With(service => service.CanSetAsync("shop", _user)));
        Assert.False(await With(service => service.CanSetAsync("shop", _reader)));
        Assert.False(await With(service => service.CanSetAsync("shop", _stranger)));
    }

    [Fact]
    public async Task Reading_through_one_assignment_and_setting_through_another_add_up_and_a_number_that_is_no_role_is_refused()
    {
        await Groups(service => service.CreateAsync("rotators", null, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        var group = Assert.Single(await Groups(service => service.ListAsync(_admin)));
        await Groups(service => service.AddMemberAsync(group.Key, _teamMember.UserKey!.Value, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        await With(service => service.AssignAsync("shop", null, group.Key, VaultRole.SecretsWriter, _admin));
        await With(service => service.AssignAsync("shop", _teamMember.UserKey, null, VaultRole.SecretsUser, _admin));

        // Shown as what they can read; they set as well, and still change nothing else.
        Assert.Equal(VaultRole.SecretsUser, await With(service => service.RoleAsync("shop", _teamMember)));
        Assert.True(await With(service => service.CanSetAsync("shop", _teamMember)));
        await With(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-both"), Merge: true), _teamMember));
        using (var value = await With(service => service.ReadAsync("shop", "token", _teamMember)))
        {
            Assert.Equal("generated-both", Encoding.UTF8.GetString(value.Reveal()));
        }

        Assert.Equal("access.denied", await CodeOf(service => service.DeleteAsync("shop", "token", _teamMember)));

        // Giving a writing role is an ordinary event, also to a group the giver is in: it reads nothing.
        Assert.Equal(AuditSeverity.Notice, (await With(service => service.AuditAsync(50, _root))).First(row => row.Code == "vault.role.assigned" && row.Detail == "group rotators = Secrets Writer").Severity);
        Assert.Equal("access.role.invalid", await CodeOf(service => service.AssignAsync("shop", _stranger.UserKey, null, (VaultRole)7, _admin)));
        Assert.Equal("access.role.invalid", await CodeOf(service => service.AssignAsync("shop", _stranger.UserKey, null, 0, _admin)));
    }

    [Fact]
    public async Task A_secret_is_renamed_with_its_versions_links_and_history_and_a_new_secret_under_the_old_name_starts_clean()
    {
        await With(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-two"), Merge: true), _officer));
        await With(service => service.CreateVaultAsync("mail", null, _admin));
        await With(service => service.AssignAsync("mail", _officer.UserKey, null, VaultRole.SecretsOfficer, _admin));
        await With(service => service.LinkAsync("shop", "token", "mail", null, _officer));
        await With(service => service.SetAsync(new SetSecret("shop", "other", Bytes("generated-other")), _officer));
        using (var before = await With(service => service.ReadAsync("shop", "token", _user)))
        {
            Assert.Equal("generated-two", Encoding.UTF8.GetString(before.Reveal()));
        }

        // Who may not, and what is refused before anything changes.
        Assert.Equal("access.denied", await CodeOf(service => service.RenameSecretAsync("shop", "token", "api-token", _user)));
        Assert.Equal("secret.rename.same", await CodeOf(service => service.RenameSecretAsync("shop", "token", "TOKEN", _officer)));
        Assert.Equal("secret.name.taken", await CodeOf(service => service.RenameSecretAsync("shop", "token", "Other", _officer)));
        Assert.Equal("secret.name.invalid", await CodeOf(service => service.RenameSecretAsync("shop", "token", "no good", _officer)));
        Assert.Equal("secret.not_found", await CodeOf(service => service.RenameSecretAsync("shop", "nothing", "api-token", _officer)));

        await With(service => service.RenameSecretAsync("shop", "token", "api-token", _officer));

        // The value, both versions, the sensitive field and the link come along; the old name answers nothing.
        using (var after = await With(service => service.ReadAsync("shop", "api-token", _user)))
        using (var pin = await With(service => service.ReadAsync("shop", "api-token", _user, "field:pin")))
        {
            Assert.Equal("generated-two", Encoding.UTF8.GetString(after.Reveal()));
            Assert.Equal("generated-pin", Encoding.UTF8.GetString(pin.Reveal()));
        }

        Assert.Equal(2, (await With(service => service.ListVersionsAsync("shop", "api-token", _user))).Count);
        Assert.Equal(["shop/api-token"], await With(service => service.LinkedNamesAsync("mail", "token", _officer)));
        Assert.Equal("secret.not_found", await CodeOf(service => service.ReadAsync("shop", "token", _user)));

        // Its history is all of it, under both names, with the rename on record.
        var activity = await With(service => service.AuditAsync(100, _officer, "shop", "api-token"));
        Assert.Contains(activity, row => row.Code == "secret.value.read" && row.Secret == "token" && row.Principal == "user");
        Assert.Contains(activity, row => row.Code == "secret.value.read" && row.Secret == "api-token" && row.Principal == "user");
        var renamed = Assert.Single(activity, row => row.Code == "secret.renamed");
        Assert.Equal((AuditSeverity.Notice, "token -> api-token", "officer"), (renamed.Severity, renamed.Detail, renamed.Principal));

        // A new secret under the old name is a new secret: none of that history is its own.
        await With(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-new")), _officer));
        var fresh = await With(service => service.AuditAsync(100, _officer, "shop", "token"));
        Assert.All(fresh, row => Assert.NotEqual("secret.value.read", row.Code));
        Assert.Single(fresh, row => row.Code == "secret.created");
    }

    [Fact]
    public async Task A_vault_is_renamed_with_everything_in_it_and_its_history_and_only_by_an_administrator()
    {
        // What the vault holds before: a second version, something in the bin, a network, a link, a read.
        await With(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-two"), Merge: true), _officer));
        await With(service => service.SetAsync(new SetSecret("shop", "old", Bytes("generated-old")), _officer));
        await With(service => service.DeleteAsync("shop", "old", _officer));
        await With(service => service.AllowNetworkAsync("shop", null, "192.0.2.0/24", _vaultAdmin));
        await With(service => service.CreateVaultAsync("mail", null, _admin));
        await With(service => service.AssignAsync("mail", _officer.UserKey, null, VaultRole.SecretsOfficer, _admin));
        await With(service => service.LinkAsync("shop", "token", "mail", null, _officer));
        using (var before = await With(service => service.ReadAsync("shop", "token", _user)))
        {
            Assert.Equal("generated-two", Encoding.UTF8.GetString(before.Reveal()));
        }

        var access = (await With(service => service.ListAccessAsync("shop", _admin))).Select(entry => (entry.Name, entry.Role)).ToList();

        // Who may not, and what is refused before anything changes.
        Assert.Equal("access.denied", await CodeOf(service => service.RenameVaultAsync("shop", "store", _vaultAdmin)));
        Assert.Equal("access.denied", await CodeOf(service => service.RenameVaultAsync("shop", "store", _officer)));
        Assert.Equal("vault.rename.same", await CodeOf(service => service.RenameVaultAsync("shop", "shop", _admin)));
        Assert.Equal("vault.rename.same", await CodeOf(service => service.RenameVaultAsync("shop", "SHOP", _admin)));
        Assert.Equal("vault.exists", await CodeOf(service => service.RenameVaultAsync("shop", "Mail", _admin)));
        Assert.Equal("vault.name.invalid", await CodeOf(service => service.RenameVaultAsync("shop", "no good", _admin)));
        Assert.Equal("vault.not_found", await CodeOf(service => service.RenameVaultAsync("nowhere", "store", _admin)));

        await With(service => service.RenameVaultAsync("shop", "store", _admin));

        // Everything is there under the new name, and nothing answers to the old one.
        Assert.Equal(access, (await With(service => service.ListAccessAsync("store", _admin))).Select(entry => (entry.Name, entry.Role)).ToList());
        using (var after = await With(service => service.ReadAsync("store", "token", _user)))
        {
            Assert.Equal("generated-two", Encoding.UTF8.GetString(after.Reveal()));
        }

        Assert.Equal(2, (await With(service => service.ListVersionsAsync("store", "token", _user))).Count);
        Assert.Equal("old", Assert.Single(await With(service => service.ListAsync("store", _officer, bin: true))).Name);
        Assert.Equal("192.0.2.0/24", Assert.Single(await With(service => service.ListNetworksAsync("store", _vaultAdmin))).Label);
        Assert.Equal(["store/token"], await With(service => service.LinkedNamesAsync("mail", "token", _officer)));
        Assert.Equal(VaultRole.SecretsOfficer, await With(service => service.RoleAsync("store", _officer)));
        Assert.Equal("vault.not_found", await CodeOf(service => service.ReadAsync("shop", "token", _user)));
        Assert.Contains("store", (await With(service => service.ListVaultsAsync(_user))).Select(vault => vault.Name));
        Assert.DoesNotContain("shop", (await With(service => service.ListVaultsAsync(_user))).Select(vault => vault.Name));

        // The vault's activity is all of it, before and after, each row with the name it had then.
        await With(service => service.ReadAsync("store", "token", _user).ContinueWith(read => { read.Result.Dispose(); return 0; }, TaskScheduler.Default));
        var activity = await With(service => service.AuditAsync(500, _officer, "store"));
        Assert.Contains(activity, row => row.Code == "secret.created" && row.Vault == "shop");
        Assert.Contains(activity, row => row.Code == "secret.value.read" && row.Vault == "shop" && row.Principal == "user");
        Assert.Contains(activity, row => row.Code == "secret.value.read" && row.Vault == "store" && row.Principal == "user");
        var renamed = Assert.Single(activity, row => row.Code == "vault.renamed");
        Assert.Equal((AuditSeverity.Security, "shop -> store", "ops"), (renamed.Severity, renamed.Detail, renamed.Principal));
        Assert.Contains(await With(service => service.AuditAsync(50, _officer, "store", "token")), row => row.Code == "secret.value.read" && row.Vault == "shop");
    }

    [Fact]
    public async Task A_secrets_officer_changes_deletes_and_restores_but_does_not_hand_out_roles_or_purge()
    {
        await With(service => service.SetAsync(new SetSecret("shop", "token", Bytes("generated-two"), KeepDetails: true, KeepSensitiveFields: ["pin"]), _officer));
        await With(service => service.DeleteAsync("shop", "token", _officer));
        var binned = Assert.Single(await With(service => service.ListAsync("shop", _officer, bin: true)));
        Assert.NotEmpty(await With(service => service.AuditAsync(10, _officer, "shop")));

        Assert.Equal("access.denied", await CodeOf(service => service.PurgeAsync("shop", binned.EntryId, _officer)));
        Assert.Equal("access.denied", await CodeOf(service => service.AssignAsync("shop", _stranger.UserKey, null, VaultRole.Reader, _officer)));
        Assert.Equal("access.denied", await CodeOf(service => service.ListAccessAsync("shop", _officer)));
        Assert.Equal("access.denied", await CodeOf(service => service.SetPurgeProtectionAsync("shop", true, _officer)));
        Assert.Equal("access.denied", await CodeOf(service => service.AuditAsync(10, _officer)));

        await With(service => service.RestoreAsync("shop", binned.EntryId, _officer));
        Assert.Single(await With(service => service.ListAsync("shop", _officer)));
    }

    [Fact]
    public async Task A_vault_admin_hands_out_roles_and_purges_and_switching_protection_off_takes_a_super_admin()
    {
        await With(service => service.AssignAsync("shop", _stranger.UserKey, null, VaultRole.Reader, _vaultAdmin));
        Assert.Single(await With(service => service.ListAsync("shop", _stranger)));
        Assert.Equal(5, (await With(service => service.ListAccessAsync("shop", _vaultAdmin))).Count(entry => entry.UserKey is not null && entry.Name != "ops"));

        await With(service => service.UnassignAsync("shop", _stranger.UserKey, null, _vaultAdmin));
        Assert.Equal("vault.not_found", await CodeOf(service => service.ListAsync("shop", _stranger)));

        await With(service => service.SetPurgeProtectionAsync("shop", true, _vaultAdmin));
        Assert.Equal("access.denied", await CodeOf(service => service.SetPurgeProtectionAsync("shop", false, _vaultAdmin)));
        Assert.Equal("access.denied", await CodeOf(service => service.SetPurgeProtectionAsync("shop", false, _admin)));
        await With(service => service.AssignAsync("shop", _root.UserKey, null, VaultRole.VaultAdmin, _root));
        await With(service => service.SetPurgeProtectionAsync("shop", false, _root));

        // A new Vault Admin, and an administrator giving a role to themselves, are security events.
        var audit = await With(service => service.AuditAsync(50, _root));
        Assert.Contains(audit, row => row.Code == "vault.role.assigned" && row.Severity == AuditSeverity.Security && row.Detail == "user root = Vault Admin");
        Assert.Contains(audit, row => row.Code == "vault.role.assigned" && row.Severity == AuditSeverity.Notice && row.Detail == "user stranger = Reader");
        Assert.Contains(audit, row => row.Code == "vault.role.removed" && row.Detail == "user stranger");
    }

    [Fact]
    public async Task An_instance_administrator_sees_every_vault_and_hands_out_roles_but_reads_no_value_without_one()
    {
        // The super admin has no role in "shop": it sees the vault, as a Reader does, and that is all.
        Assert.Single(await With(service => service.ListVaultsAsync(_root)));
        Assert.Equal(VaultRole.Reader, await With(service => service.RoleAsync("shop", _root)));
        Assert.Single(await With(service => service.ListAsync("shop", _root)));
        Assert.Equal("access.denied", await CodeOf(service => service.ReadAsync("shop", "token", _root)));

        // It can give itself the role, and that is what makes the read possible, on record.
        await With(service => service.AssignAsync("shop", _root.UserKey, null, VaultRole.SecretsUser, _root));
        using var value = await With(service => service.ReadAsync("shop", "token", _root));
        Assert.Equal("generated-value", Encoding.UTF8.GetString(value.Reveal()));
        var audit = await With(service => service.AuditAsync(50, _root));
        Assert.Contains(audit, row => row.Code == "vault.role.assigned" && row.Severity == AuditSeverity.Security && row.Detail == "user root = Secrets User");

        // A user cannot make a vault, see every bin, or change retention.
        Assert.Equal("access.denied", await CodeOf(service => service.CreateVaultAsync("mine", null, _officer)));
        Assert.Equal("access.denied", await CodeOf(service => service.ListAllBinsAsync(_officer)));
        Assert.Equal("access.denied", await CodeOf(service => service.SetRetentionDaysAsync(30, _officer)));
    }

    [Fact]
    public async Task A_search_finds_what_a_reader_may_see_in_their_own_vaults_and_never_looks_at_a_value()
    {
        // A second vault the reader has no role in, holding a secret with the same word in its name.
        await With(service => service.CreateVaultAsync("mail", null, _admin));
        await With(service => service.AssignAsync("mail", _officer.UserKey, null, VaultRole.SecretsOfficer, _admin));
        await With(service => service.SetAsync(new SetSecret("mail", "smtp-token", Bytes("generated-smtp"), Description: "for the relay"), _officer));

        // By name, by vault name, by an ordinary field's value, by several words at once; whatever the case.
        Assert.Equal("token", Assert.Single(await With(service => service.SearchAsync("TOKEN", _reader))).Name);
        Assert.Equal("shop", Assert.Single(await With(service => service.SearchAsync("team-a", _reader))).Vault);
        Assert.Single(await With(service => service.SearchAsync("shop tok", _reader)));
        Assert.Empty(await With(service => service.SearchAsync("shop relay", _reader)));
        Assert.Equal(["token", "smtp-token"], (await With(service => service.SearchAsync("token", _officer))).Select(found => found.Name));
        Assert.Equal("smtp-token", Assert.Single(await With(service => service.SearchAsync("relay", _officer))).Name);

        // Never a value or a sensitive field, and nothing for someone with no vault; too little to go on finds nothing.
        Assert.Empty(await With(service => service.SearchAsync("generated-value", _officer)));
        Assert.Empty(await With(service => service.SearchAsync("generated-pin", _officer)));
        Assert.Empty(await With(service => service.SearchAsync("token", _stranger)));
        Assert.Empty(await With(service => service.SearchAsync("t", _officer)));
        Assert.Empty(await With(service => service.SearchAsync(null, _officer)));

        // What is in a bin is not found.
        await With(service => service.DeleteAsync("mail", "smtp-token", _officer));
        Assert.Equal("token", Assert.Single(await With(service => service.SearchAsync("token", _officer))).Name);

        // A vault limited to another network is passed over quietly: no result, and no refusal on record.
        await With(service => service.AllowNetworkAsync("shop", null, "198.51.100.0/24", _vaultAdmin));
        Assert.Empty(await With(service => service.SearchAsync("token", _officer)));
        var audit = await With(service => service.AuditAsync(100, _root));
        Assert.DoesNotContain(audit, row => row.Code is "access.network.refused" or "secret.value.read");
    }

    [Fact]
    public async Task A_link_that_is_refused_makes_nothing()
    {
        await With(service => service.CreateVaultAsync("mail", null, _admin));
        await With(service => service.AssignAsync("mail", _vaultAdmin.UserKey, null, VaultRole.SecretsUser, _admin));

        // Vault Admin here, only reading there: refused, and there is no second name afterwards.
        Assert.Equal("access.denied", await CodeOf(service => service.LinkAsync("shop", "token", "mail", null, _vaultAdmin)));
        Assert.Empty(await With(service => service.ListAsync("mail", _vaultAdmin)));
        Assert.False(Assert.Single(await With(service => service.ListAsync("shop", _vaultAdmin))).IsLinked);

        // The refusal is on record under the secret it was tried on, naming the vault it was meant for.
        var activity = await With(service => service.AuditAsync(10, _vaultAdmin, "shop", "token"));
        Assert.Contains(activity, row => row.Code == "access.denied" && row.Principal == "vault-admin" && row.Detail == "link into mail needs Secrets Officer there, has Secrets User");

        // With an officer's role there, the link is made, and a second attempt says the name is taken.
        await With(service => service.AssignAsync("mail", _vaultAdmin.UserKey, null, VaultRole.SecretsOfficer, _admin));
        await With(service => service.LinkAsync("shop", "token", "mail", null, _vaultAdmin));
        Assert.Equal(["mail/token"], Assert.Single(await With(service => service.ListAsync("shop", _vaultAdmin))).LinkedWith);
        Assert.Equal("secret.name.taken", await CodeOf(service => service.LinkAsync("shop", "token", "mail", null, _vaultAdmin)));
    }

    [Fact]
    public async Task Every_route_by_which_an_administrator_comes_to_read_a_value_is_a_security_event()
    {
        // A machine whose keys the administrator can make, and a group the administrator is in.
        int machine;
        await using (var context = NewContext())
        {
            var accounts = new AccountService(new EfUserStore(context), new PlatformPasswordHasher(), TimeProvider.System);
            machine = (await accounts.CreateServiceAsync(new AccountActor(-1, UserRole.SuperAdmin), "host-web-1", "", default)).User!.Key;
        }

        await With(service => service.AssignAsync("shop", machine, null, VaultRole.Reader, _admin));
        await With(service => service.AssignAsync("shop", machine, null, VaultRole.SecretsUser, _admin));
        await Groups(service => service.CreateAsync("operations", null, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        var operations = (await Groups(service => service.ListAsync(_admin))).Single(group => group.Name == "operations");
        await Groups(service => service.AddMemberAsync(operations.Key, _teamMember.UserKey!.Value, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        await Groups(service => service.AddMemberAsync(operations.Key, _admin.UserKey!.Value, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        await With(service => service.AssignAsync("shop", null, operations.Key, VaultRole.SecretsUser, _admin));

        var audit = await With(service => service.AuditAsync(50, _root));
        Assert.Contains(audit, row => row.Code == "vault.role.assigned" && row.Severity == AuditSeverity.Notice && row.Detail == "user host-web-1 = Reader");
        Assert.Contains(audit, row => row.Code == "vault.role.assigned" && row.Severity == AuditSeverity.Security && row.Detail == "user host-web-1 = Secrets User");
        Assert.Contains(audit, row => row.Code == "group.member.added" && row.Severity == AuditSeverity.Notice && row.Detail == "operations + team-member");
        Assert.Contains(audit, row => row.Code == "group.member.added" && row.Severity == AuditSeverity.Security && row.Detail == "operations + ops");
        Assert.Contains(audit, row => row.Code == "vault.role.assigned" && row.Severity == AuditSeverity.Security && row.Detail == "group operations = Secrets User");
    }

    [Fact]
    public async Task A_group_holds_a_role_for_all_its_members_and_the_highest_role_counts()
    {
        await Groups(service => service.CreateAsync("operations", "the team", _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        var group = Assert.Single(await Groups(service => service.ListAsync(_admin)));
        await Groups(service => service.AddMemberAsync(group.Key, _teamMember.UserKey!.Value, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        await With(service => service.AssignAsync("shop", null, group.Key, VaultRole.SecretsUser, _admin));

        using (var value = await With(service => service.ReadAsync("shop", "token", _teamMember)))
        {
            Assert.Equal("generated-value", Encoding.UTF8.GetString(value.Reveal()));
        }

        // Its own lower role does not pull it down, and a higher one lifts it.
        await With(service => service.AssignAsync("shop", _teamMember.UserKey, null, VaultRole.Reader, _admin));
        Assert.Equal(VaultRole.SecretsUser, await With(service => service.RoleAsync("shop", _teamMember)));
        await With(service => service.AssignAsync("shop", _teamMember.UserKey, null, VaultRole.SecretsOfficer, _admin));
        Assert.Equal(VaultRole.SecretsOfficer, await With(service => service.RoleAsync("shop", _teamMember)));
        await With(service => service.UnassignAsync("shop", _teamMember.UserKey, null, _admin));

        // Out of the group, out of the vault, at once.
        await Groups(service => service.RemoveMemberAsync(group.Key, _teamMember.UserKey!.Value, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        Assert.Equal("vault.not_found", await CodeOf(service => service.ReadAsync("shop", "token", _teamMember)));

        // Only administrators manage groups; deleting one takes its roles with it.
        Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => Groups(service => service.ListAsync(_officer)))).Code);
        await Groups(service => service.DeleteAsync(group.Key, _admin).ContinueWith(_ => 0, TaskScheduler.Default));
        Assert.DoesNotContain(await With(service => service.ListAccessAsync("shop", _admin)), entry => entry.GroupKey is not null);
    }

    [Fact]
    public async Task Linking_takes_an_officer_of_both_vaults_and_names_in_vaults_you_cannot_see_are_only_counted()
    {
        await With(service => service.CreateVaultAsync("other", null, _root));
        await With(service => service.AssignAsync("other", _user.UserKey, null, VaultRole.SecretsOfficer, _root));

        // A reader of the source may not link, however much it holds in the target; nor a vault that is not theirs.
        Assert.Equal("access.denied", await CodeOf(service => service.LinkAsync("shop", "token", "other", null, _user)));
        Assert.Equal("vault.not_found", await CodeOf(service => service.LinkAsync("shop", "token", "other", null, _vaultAdmin)));

        // An officer of both may, as it may move the secret there; it is a security event.
        await With(service => service.AssignAsync("other", _officer.UserKey, null, VaultRole.SecretsOfficer, _root));
        await With(service => service.LinkAsync("shop", "token", "other", "shared-token", _officer));
        Assert.Equal(AuditSeverity.Security, (await With(service => service.AuditAsync(20, _root))).First(row => row.Code == "secret.link.created").Severity);

        // The reader of "shop" has no role in "other": it learns that a link exists, not where.
        var asReader = Assert.Single(await With(service => service.ListAsync("shop", _reader)));
        Assert.True(asReader.IsLinked);
        Assert.Equal((0, 1), (asReader.LinkedWith!.Count, asReader.LinkedElsewhere));
        Assert.Empty(await With(service => service.LinkedNamesAsync("shop", "token", _reader)));
        var asOfficer = Assert.Single(await With(service => service.ListAsync("shop", _officer)));
        Assert.Equal(["other/shared-token"], asOfficer.LinkedWith);
        Assert.Equal(0, asOfficer.LinkedElsewhere);

        // Deleting everywhere needs the right to delete in every one of those vaults.
        await With(service => service.UnassignAsync("other", _officer.UserKey, null, _root));
        Assert.Equal("access.denied", await CodeOf(service => service.DeleteEverywhereAsync("shop", "token", ["shop/token", "other/shared-token"], _officer)));
        await With(service => service.DeleteAsync("shop", "token", _officer));
        using var still = await With(service => service.ReadAsync("other", "shared-token", _user));
        Assert.Equal("generated-value", Encoding.UTF8.GetString(still.Reveal()));
    }

    [Fact]
    public async Task Copying_needs_to_read_the_source_and_write_the_target_and_deleting_an_account_removes_its_roles()
    {
        await With(service => service.CreateVaultAsync("other", null, _root));
        await With(service => service.AssignAsync("other", _reader.UserKey, null, VaultRole.SecretsOfficer, _root));

        // A Reader of the source cannot copy the value out of it, whatever it holds in the target.
        Assert.Equal("access.denied", await CodeOf(service => service.CopyAsync("shop", "token", "other", null, _reader)));
        await With(service => service.AssignAsync("other", _user.UserKey, null, VaultRole.SecretsOfficer, _root));
        await With(service => service.CopyAsync("shop", "token", "other", null, _user));
        Assert.Single(await With(service => service.ListAsync("other", _user)));

        await using (var context = NewContext())
        {
            var accounts = new AccountService(new EfUserStore(context), new PlatformPasswordHasher(), TimeProvider.System);
            Assert.Equal(AccountOutcome.Done, await accounts.DeleteAsync(new AccountActor(_root.UserKey!.Value, UserRole.SuperAdmin), _user.UserKey!.Value, default));
        }

        Assert.DoesNotContain(await With(service => service.ListAccessAsync("shop", _root)), entry => entry.Name == "user");
    }
}
