using System.IO.Compression;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Accounts;
using SecretHive.Infrastructure.Backup;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;
using SecretHive.Infrastructure.Sqlite;
using SecretHive.Infrastructure.SqlServer;

namespace SecretHive.Unit.Tests;

/// <summary>
/// The restore drill: fill a server, back it up, destroy nothing but bring up a clean database elsewhere with only
/// the backup and the master key, and find everything there. From either database product into either.
/// </summary>
public sealed class BackupRestoreTests : IAsyncLifetime
{
    private const string Sqlite = "Sqlite";
    private const string SqlServer = "SqlServer";
    private static readonly Caller Root = Caller.System("test");
    private static readonly Caller Inside = new("inside", "192.0.2.7", Unrestricted: true);
    private static readonly string? SqlServerBase = Environment.GetEnvironmentVariable(SqlServerSecretStoreTests.Variable);

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-backup-").FullName;
    private readonly List<Func<SecretHiveDbContext>> _databases = [];
    private MasterKey _master = null!;
    private KeyRing _keyRing = null!;

    public ValueTask InitializeAsync()
    {
        MasterKey.Create(Path.Combine(_directory, "master.key"));
        _master = MasterKey.Load(Path.Combine(_directory, "master.key"));
        _keyRing = new KeyRing(_master);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var open in _databases)
        {
            await using var context = open();
            await context.Database.EnsureDeletedAsync();
        }

        Directory.Delete(_directory, recursive: true);
    }

    /// <summary>A fresh, migrated, empty database of the given kind.</summary>
    private async Task<Func<SecretHiveDbContext>> NewDatabaseAsync(string kind, string? migration = null)
    {
        var name = "secrethive_drill_" + Guid.NewGuid().ToString("N")[..12];
        Func<SecretHiveDbContext> open = () =>
        {
            var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
            if (kind == SqlServer)
            {
                builder.UseSecretHiveSqlServer(SqlServerBase!.TrimEnd(';') + ";Database=" + name);
            }
            else
            {
                builder.UseSecretHiveSqlite($"Data Source={Path.Combine(_directory, name + ".db")};Pooling=False");
            }

            return new SecretHiveDbContext(builder.Options);
        };
        _databases.Add(open);
        await using var context = open();
        await context.GetService<Microsoft.EntityFrameworkCore.Migrations.IMigrator>().MigrateAsync(migration);
        return open;
    }

    private SecretService Secrets(SecretHiveDbContext context, KeyRing? ring = null) =>
        new(new EfSecretStore(context), ring ?? _keyRing, TimeProvider.System, new EfAccessStore(context), new EfUserStore(context));

    private BackupArchive Archive(SecretHiveDbContext context, MasterKey? key = null) => new(context, BackupSeal.From(key ?? _master), TimeProvider.System);

    private static string Text(SecretBytes bytes) => Encoding.UTF8.GetString(bytes.Reveal());

    private static async Task<Dictionary<string, int>> CountsAsync(SecretHiveDbContext context) => new()
    {
        ["Vaults"] = await context.Vaults.CountAsync(),
        ["Folders"] = await context.Folders.CountAsync(),
        ["FolderAssignments"] = await context.FolderAssignments.CountAsync(),
        ["Pins"] = await context.Pins.CountAsync(),
        ["Entries"] = await context.Entries.CountAsync(),
        ["EntryFields"] = await context.EntryFields.CountAsync(),
        ["Values"] = await context.Values.CountAsync(),
        ["Versions"] = await context.Versions.CountAsync(),
        ["VersionItems"] = await context.VersionItems.CountAsync(),
        ["Certificates"] = await context.Certificates.CountAsync(),
        ["Audit"] = await context.Audit.CountAsync(),
        ["Users"] = await context.Users.CountAsync(),
        ["Groups"] = await context.Groups.CountAsync(),
        ["GroupMembers"] = await context.GroupMembers.CountAsync(),
        ["VaultAssignments"] = await context.VaultAssignments.CountAsync(),
        ["ApiKeys"] = await context.ApiKeys.CountAsync(),
        ["OidcProviders"] = await context.OidcProviders.CountAsync(),
        ["ExternalLogins"] = await context.ExternalLogins.CountAsync(),
        ["GroupProviderLinks"] = await context.GroupProviderLinks.CountAsync(),
        ["Settings"] = await context.Settings.CountAsync(),
        ["NetworkGroups"] = await context.NetworkGroups.CountAsync(),
        ["AllowedNetworks"] = await context.AllowedNetworks.CountAsync(),
    };

    /// <summary>One of everything the server stores. Returns the key made for the service identity.</summary>
    private async Task<string> FillAsync(Func<SecretHiveDbContext> open, TestCertificate site)
    {
        await using var context = open();
        var secrets = Secrets(context);
        var users = new EfUserStore(context);
        var access = new EfAccessStore(context);
        var audit = new AuditWriter(new EfSecretStore(context), TimeProvider.System);
        var accounts = new AccountService(users, new PlatformPasswordHasher(), TimeProvider.System);
        var protector = new MasterKeySecretProtector(_master);

        await secrets.CreateVaultAsync("shop", "the shop", Root);
        await secrets.CreateVaultAsync("billing", null, Root);
        await secrets.SetAsync(new SetSecret("shop", "token", "generated-one"u8.ToArray()), Root);
        await secrets.SetAsync(
            new SetSecret("shop", "token", "generated-two"u8.ToArray(), Description: "the shop's token", Fields: [new FieldInput("owner", "team-a"u8.ToArray()), new FieldInput("pin", "generated-pin"u8.ToArray(), Sensitive: true)]),
            Root);
        await secrets.LinkAsync("shop", "token", "billing", "shop-token", Root);
        await secrets.SetAsync(new SetSecret("billing", "old", "generated-binned"u8.ToArray()), Root);
        await secrets.DeleteAsync("billing", "old", Root);
        await secrets.ImportCertificateAsync(new ImportCertificate("shop", "site", [site.CertificatePart, site.PfxPart, TestCertificate.PasswordPart()]), Root);
        await secrets.SetRetentionDaysAsync(30, Root);

        var admin = new AccountActor(-1, UserRole.SuperAdmin);
        var (_, alice) = await accounts.CreateAsync(admin, "alice", "Alice", "alice@example.org", UserRole.User, "generated-password-123", default);
        var (_, job) = await accounts.CreateServiceAsync(admin, "stack-web-1-shop", "the shop stack", default);
        var groups = new GroupService(access, users, audit, TimeProvider.System);
        await groups.CreateAsync("shop-team", "people of the shop", Root);
        var team = (await access.ListGroupsAsync(default)).Single().Key;
        await groups.AddMemberAsync(team, alice!.Key, Root);
        await secrets.AssignAsync("shop", null, team, VaultRole.SecretsUser, Root);
        await secrets.AssignAsync("shop", job!.Key, null, VaultRole.Reader, Root);

        // Folders three deep, the vault in the innermost; the parent of each made after its child would come first
        // in a table read by id, which a restore has to cope with.
        await secrets.CreateFolderAsync("zz-top", null, "everything", Root);
        await secrets.CreateFolderAsync("mm-middle", "zz-top", null, Root);
        await secrets.CreateFolderAsync("aa-inner", "mm-middle", null, Root);
        await secrets.MoveVaultToFolderAsync("shop", "aa-inner", Root);
        var (_, bob) = await accounts.CreateAsync(admin, "bob", "Bob", "bob@example.org", UserRole.User, "generated-password-456", default);
        await secrets.AssignFolderAsync("zz-top", bob!.Key, null, VaultRole.SecretsOfficer, Root);
        await secrets.SetPinAsync("shop", "token", true, new Caller("bob", UserKey: bob.Key));

        var providers = new ProviderService(new EfOidcProviderStore(context), access, protector, audit, TimeProvider.System);
        var provider = await providers.CreateAsync(new ProviderSettings("Provider", "idp", "https://auth.example.org/o/secrethive", "client-1", "generated-client-secret", GroupsClaim: "groups"), Root);
        await providers.LinkGroupAsync(team, provider, "Shop Operators", Root);
        await new EfExternalLoginStore(context).AddAsync(new ExternalLogin { UserKey = alice.Key, ProviderKey = provider, Subject = "sub-alice", LinkedUtc = DateTime.UtcNow }, default);
        await access.SyncProviderMembershipsAsync(job.Key, provider, new HashSet<int> { team }, default);

        var keys = new KeyService(new EfKeyStore(context), users, new EfSecretStore(context), audit, TimeProvider.System, new EfAccessStore(context));
        var (made, key) = await keys.CreateAsync(Root, job.Key, "deploy", 30, "shop", VaultRole.Reader);
        await new NetworkService(access, audit, TimeProvider.System).CreateAsync("lan", "the LAN", "192.0.2.0/24", Root);
        var lan = (await access.ListNetworkGroupsAsync(default)).Single().Key;
        await secrets.AllowNetworkAsync("billing", lan, null, Root);
        await keys.AllowNetworkAsync(Root, made.Key, null, "192.0.2.1");
        return key;
    }

    public static TheoryData<string, string> Directions() => new()
    {
        { Sqlite, Sqlite },
        { Sqlite, SqlServer },
        { SqlServer, Sqlite },
        { SqlServer, SqlServer },
    };

    [Theory]
    [MemberData(nameof(Directions))]
    public async Task A_backup_and_the_master_key_bring_everything_back_on_a_clean_database(string from, string to)
    {
        Assert.SkipWhen((from == SqlServer || to == SqlServer) && string.IsNullOrWhiteSpace(SqlServerBase), $"Set {SqlServerSecretStoreTests.Variable} to run the SQL Server tests.");
        var site = new TestCertificate("shop.example.test");
        var source = await NewDatabaseAsync(from);
        var key = await FillAsync(source, site);

        var file = Path.Combine(_directory, "drill.shbak");
        BackupFacts written;
        Dictionary<string, int> before;
        await using (var context = source())
        await using (var output = File.Create(file))
        {
            written = await Archive(context).WriteAsync(output, "test", TestContext.Current.CancellationToken);
            before = await CountsAsync(context);
        }

        Assert.Equal(before.Where(pair => pair.Value > 0).OrderBy(pair => pair.Key), written.Rows.Where(pair => pair.Value > 0).OrderBy(pair => pair.Key));
        Assert.All(before, pair => Assert.True(pair.Value > 0, $"the drill stores nothing in {pair.Key}, so it would not notice that table missing from a backup"));

        // Every table the server has is one the drill fills and counts: a table added later fails here until it is.
        await using (var context = source())
        {
            Assert.Equal(context.Model.GetEntityTypes().Select(type => type.GetTableName()).Order(), before.Keys.Order());
        }

        // The file holds no value and no key in the clear, and not the master key.
        using (var plain = new MemoryStream())
        {
            await using (var gzip = new GZipStream(File.OpenRead(file), CompressionMode.Decompress))
            {
                await gzip.CopyToAsync(plain, TestContext.Current.CancellationToken);
            }

            var text = Encoding.Latin1.GetString(plain.ToArray());
            foreach (var secret in new[] { "generated-one", "generated-two", "generated-pin", "generated-binned", "generated-client-secret", "generated-password-123", key, Convert.ToBase64String(site.Pfx)[..60], Convert.ToBase64String(File.ReadAllBytes(Path.Combine(_directory, "master.key")))[..20] })
            {
                Assert.DoesNotContain(secret, text, StringComparison.Ordinal);
            }

            Assert.Contains("team-a", text, StringComparison.Ordinal); // an ordinary field is a plain column, in the backup as in the database
        }

        // A clean database, the backup, and the same master key: nothing else.
        var target = await NewDatabaseAsync(to);
        await using (var context = target())
        {
            var facts = await Archive(context).RestoreAsync(() => File.OpenRead(file), TestContext.Current.CancellationToken);
            Assert.Equal(written.Total, facts.Total);
        }

        await using (var context = target())
        {
            Assert.Equal(before, await CountsAsync(context));
            var secrets = Secrets(context);
            // The folder tree came back whole: the role on the top folder reaches the vault three levels down.
            var bobKey = (await context.Users.AsNoTracking().FirstAsync(user => user.UserName == "bob")).Key;
            Assert.Equal(VaultRole.SecretsOfficer, await secrets.RoleAsync("shop", new Caller("bob", UserKey: bobKey)));
            Assert.Equal(["zz-top", "mm-middle", "aa-inner"], Assert.Single(await secrets.ListMyVaultsAsync(new Caller("bob", UserKey: bobKey)), vault => vault.Name == "shop").Folders);


            using (var value = await secrets.ReadAsync("shop", "token", Root))
            {
                Assert.Equal("generated-two", Text(value));
            }

            // The vault's network limit came along: the same caller is let in from inside it and refused from outside.
            Assert.Equal("access.network.refused", (await Assert.ThrowsAsync<DomainException>(() => secrets.ReadAsync("billing", "shop-token", Inside with { Address = "198.51.100.9" }))).Code);
            using (var linked = await secrets.ReadAsync("billing", "shop-token", Inside))
            {
                Assert.Equal("generated-two", Text(linked));
            }

            using (var pin = await secrets.ReadAsync("shop", "token", Root, "field:pin"))
            {
                Assert.Equal("generated-pin", Text(pin));
            }

            using (var pfx = await secrets.ReadPartAsync("shop", "site", CertificatePartKind.Pfx, Root))
            {
                Assert.Equal(site.Pfx, pfx.Content.Bytes.Reveal().ToArray());
            }

            var token = (await secrets.ListAsync("shop", Root)).Single(item => item.Name == "token");
            Assert.Equal(("the shop's token", "team-a", 2), (token.Description, token.Fields["owner"], token.Version));
            Assert.Equal(site.Thumbprint, (await secrets.ListAsync("shop", Root)).Single(item => item.Name == "site").Certificate!.Thumbprint);
            Assert.Equal("old", Assert.Single(await secrets.ListAsync("billing", Root, bin: true)).Name);
            Assert.Equal(30, await secrets.GetRetentionDaysAsync());

            // Accounts sign in with the password they had, keys still open what they opened, roles are who they were.
            var users = new EfUserStore(context);
            var accounts = new AccountService(users, new PlatformPasswordHasher(), TimeProvider.System);
            Assert.Equal(SignInStatus.Success, (await accounts.SignInAsync("alice", "generated-password-123", default)).Status);
            var alice = (await users.FindByUserNameAsync("alice", default))!;
            Assert.Equal(VaultRole.SecretsUser, await secrets.RoleAsync("shop", new Caller("alice", UserKey: alice.Key)));
            var keys = new KeyService(new EfKeyStore(context), users, new EfSecretStore(context), new AuditWriter(new EfSecretStore(context), TimeProvider.System), TimeProvider.System, new EfAccessStore(context));
            Assert.NotNull(await keys.AuthenticateAsync(key, "192.0.2.1", default));

            // The provider's client secret comes back readable: it is under the master key, not under anything left on the old host.
            var provider = Assert.Single(await new EfOidcProviderStore(context).ListAsync(default));
            Assert.Equal("generated-client-secret", new MasterKeySecretProtector(_master).Unprotect(provider.ProtectedClientSecret));

            // The audit trail came along whole, and new rows continue after it instead of colliding with it.
            var trail = await secrets.AuditAsync(500, Root);
            Assert.Contains(trail, row => row.Code == "secret.link.created");
            Assert.Contains(trail, row => row.Code == "provider.created");
            await secrets.SetAsync(new SetSecret("shop", "after-restore", "generated-new"u8.ToArray()), Root);
            await new GroupService(new EfAccessStore(context), users, new AuditWriter(new EfSecretStore(context), TimeProvider.System), TimeProvider.System).CreateAsync("made-after", null, Root);
            Assert.Equal(before["Groups"] + 1, await context.Groups.CountAsync(TestContext.Current.CancellationToken));
        }

        // A restore never merges: the database now holds data, so a second one is refused and changes nothing.
        await using (var context = target())
        {
            var refused = await Assert.ThrowsAsync<DomainException>(() => Archive(context).RestoreAsync(() => File.OpenRead(file), TestContext.Current.CancellationToken));
            Assert.Equal("restore.not_empty", refused.Code);
        }
    }

    [Fact]
    public async Task Audit_rows_keep_their_vault_by_id_through_a_backup_and_a_backup_from_before_gets_it_on_restore()
    {
        var source = await NewDatabaseAsync(Sqlite);
        await FillAsync(source, new TestCertificate("shop.example.test"));
        Dictionary<long, (Guid?, Guid?)> Ids(SecretHiveDbContext context) => context.Audit.AsNoTracking().Where(row => row.Vault != null).ToDictionary(row => row.Id, row => (row.VaultId, row.EntryId));
        using var whole = new MemoryStream();
        Dictionary<long, (Guid?, Guid?)> written;
        await using (var context = source())
        {
            written = Ids(context);
            Assert.NotEmpty(written);
            Assert.All(written.Values, ids => Assert.NotNull(ids.Item1));
            Assert.Contains(written.Values, ids => ids.Item2 is not null);
            await Archive(context).WriteAsync(whole, "test", TestContext.Current.CancellationToken);
        }

        // The same ids come back.
        var target = await NewDatabaseAsync(Sqlite);
        await using (var context = target())
        {
            await Archive(context).RestoreAsync(() => new MemoryStream(whole.ToArray()), TestContext.Current.CancellationToken);
            Assert.Equal(written, Ids(context));
        }

        // A backup made before the column existed: the audit rows without it, sealed as that release sealed them.
        var lines = Unzip(whole.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var old = new List<string>();
        foreach (var line in lines[..^1])
        {
            var node = System.Text.Json.Nodes.JsonNode.Parse(line)!;
            if ((string?)node["t"] == "Audit")
            {
                node["r"]!.AsObject().Remove("VaultId");
                node["r"]!.AsObject().Remove("EntryId");
            }

            old.Add(node.ToJsonString());
        }

        using var mac = System.Security.Cryptography.IncrementalHash.CreateHMAC(System.Security.Cryptography.HashAlgorithmName.SHA256, _master.Derive("secrethive/backup-seal/v1"));
        foreach (var line in old)
        {
            mac.AppendData(Encoding.UTF8.GetBytes(line + "\n"));
        }

        var trailer = System.Text.Json.JsonSerializer.Serialize(new { end = true, rows = old.Count - 1, mac = Convert.ToHexString(mac.GetHashAndReset()) });
        Assert.DoesNotContain(old, line => line.StartsWith("{\"t\":\"Audit\"", StringComparison.Ordinal) && (line.Contains("\"VaultId\"", StringComparison.Ordinal) || line.Contains("\"EntryId\"", StringComparison.Ordinal)));
        var oldFile = Zip(string.Join('\n', old) + "\n" + trailer + "\n");

        var fromOld = await NewDatabaseAsync(Sqlite);
        await using (var context = fromOld())
        {
            await Archive(context).RestoreAsync(() => new MemoryStream(oldFile), TestContext.Current.CancellationToken);

            // Every vault comes back; a secret comes back for each row that names a version, the others are found by
            // their vault and name, as they were before 0.20.
            var restored = Ids(context);
            Assert.Equal(written.ToDictionary(row => row.Key, row => row.Value.Item1), restored.ToDictionary(row => row.Key, row => row.Value.Item1));
            var withVersion = context.Audit.AsNoTracking().Where(row => row.VersionId != null && row.Vault != null).Select(row => row.Id).ToHashSet();
            Assert.NotEmpty(withVersion);
            Assert.All(withVersion, id => Assert.Equal(written[id].Item2, restored[id].Item2));
        }
    }

    [Theory]
    [InlineData(Sqlite)]
    [InlineData(SqlServer)]
    public async Task The_backfill_gives_the_rows_that_name_a_version_the_id_of_their_secret(string kind)
    {
        Assert.SkipWhen(kind == SqlServer && string.IsNullOrWhiteSpace(SqlServerBase), $"Set {SqlServerSecretStoreTests.Variable} to run the SQL Server tests.");
        var open = await NewDatabaseAsync(kind);
        await FillAsync(open, new TestCertificate("shop.example.test"));
        await using var context = open();
        var ct = TestContext.Current.CancellationToken;
        var written = await context.Audit.AsNoTracking().Where(row => row.EntryId != null && row.VersionId != null).ToDictionaryAsync(row => row.Id, row => row.EntryId, ct);
        Assert.NotEmpty(written);

        // As a database from before 0.20 has them: no secret ids at all. The same statement the migration runs.
        await context.Database.ExecuteSqlRawAsync("UPDATE Audit SET EntryId = NULL", ct);
        await context.Database.ExecuteSqlRawAsync(AuditEntries.Backfill, ct);
        var back = await context.Audit.AsNoTracking().Where(row => written.Keys.Contains(row.Id)).ToDictionaryAsync(row => row.Id, row => row.EntryId, ct);
        Assert.Equal(written, back);
    }

    [Theory]
    [InlineData(Sqlite)]
    [InlineData(SqlServer)]
    public async Task The_migration_gives_the_rows_written_before_it_the_id_of_their_vault_where_it_still_exists(string kind)
    {
        Assert.SkipWhen(kind == SqlServer && string.IsNullOrWhiteSpace(SqlServerBase), $"Set {SqlServerSecretStoreTests.Variable} to run the SQL Server tests.");

        // A database as 0.17 left it: rows about a vault by name only, typed in another case, one about a vault that
        // was deleted since, one about no vault.
        var open = await NewDatabaseAsync(kind, "KeysWithoutEnd");
        var shop = Guid.NewGuid();
        await using (var context = open())
        {
            var ct = TestContext.Current.CancellationToken;
            await context.Database.ExecuteSqlRawAsync("INSERT INTO Vaults (Id, Name, NameKey, PurgeProtection, CreatedUtc) VALUES ({0}, {1}, {2}, {3}, {4})", [shop, "Shop", "shop", false, DateTime.UtcNow], ct);
            foreach (var vault in new[] { "Shop", "gone" })
            {
                await context.Database.ExecuteSqlRawAsync("INSERT INTO Audit (AtUtc, Code, Severity, Principal, Vault) VALUES ({0}, {1}, {2}, {3}, {4})", [DateTime.UtcNow, "secret.value.read", "Info", "before", vault], ct);
            }

            await context.Database.ExecuteSqlRawAsync("INSERT INTO Audit (AtUtc, Code, Severity, Principal, Vault) VALUES ({0}, {1}, {2}, {3}, NULL)", [DateTime.UtcNow, "auth.signin", "Info", "before"], ct);
        }

        await using (var context = open())
        {
            await context.Database.MigrateAsync(TestContext.Current.CancellationToken);
            var rows = await context.Audit.AsNoTracking().Where(row => row.Principal == "before").ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(shop, rows.Single(row => row.Vault == "Shop").VaultId);
            Assert.Null(rows.Single(row => row.Vault == "gone").VaultId);
            Assert.Null(rows.Single(row => row.Vault == null).VaultId);
        }
    }

    private static string Unzip(byte[] file)
    {
        using var plain = new MemoryStream();
        using (var gzip = new GZipStream(new MemoryStream(file), CompressionMode.Decompress))
        {
            gzip.CopyTo(plain);
        }

        return Encoding.UTF8.GetString(plain.ToArray());
    }

    private static byte[] Zip(string text)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest))
        {
            gzip.Write(Encoding.UTF8.GetBytes(text));
        }

        return output.ToArray();
    }

    [Fact]
    public async Task A_backup_that_was_changed_cut_short_or_made_under_another_key_restores_nothing()
    {
        var source = await NewDatabaseAsync(Sqlite);
        await FillAsync(source, new TestCertificate("shop.example.test"));
        using var whole = new MemoryStream();
        await using (var context = source())
        {
            await Archive(context).WriteAsync(whole, "test", TestContext.Current.CancellationToken);
        }

        byte[] Recompress(Func<string, string> change)
        {
            using var plain = new MemoryStream();
            using (var gzip = new GZipStream(new MemoryStream(whole.ToArray()), CompressionMode.Decompress))
            {
                gzip.CopyTo(plain);
            }

            using var output = new MemoryStream();
            using (var gzip = new GZipStream(output, CompressionLevel.Fastest))
            {
                gzip.Write(Encoding.UTF8.GetBytes(change(Encoding.UTF8.GetString(plain.ToArray()))));
            }

            return output.ToArray();
        }

        var target = await NewDatabaseAsync(Sqlite);
        async Task<string> Refusal(byte[] file, MasterKey? key = null)
        {
            await using var context = target();
            var code = (await Assert.ThrowsAsync<DomainException>(() => Archive(context, key).RestoreAsync(() => new MemoryStream(file), TestContext.Current.CancellationToken))).Code;
            Assert.Equal(0, (await CountsAsync(context)).Values.Sum());
            return code;
        }

        // One role raised by hand in the file; a row removed; the end cut off; a row appended after the seal.
        Assert.Equal("backup.damaged", await Refusal(Recompress(text => text.Replace("\"Role\":0", "\"Role\":2", StringComparison.Ordinal))));
        Assert.Equal("backup.damaged", await Refusal(Recompress(text => string.Join('\n', text.Split('\n').Where((_, index) => index != 3)))));
        Assert.Equal("backup.damaged", await Refusal(Recompress(text => text[..(text.Length / 2)])));
        Assert.Equal("backup.damaged", await Refusal(Recompress(text => text + "{\"t\":\"Vaults\",\"r\":{}}\n")));
        Assert.Equal("backup.damaged", await Refusal(whole.ToArray()[..(int)(whole.Length / 2)]));
        Assert.Equal("backup.not_a_backup", await Refusal("not a backup at all"u8.ToArray()));
        Assert.Equal("backup.not_a_backup", await Refusal([]));

        // The right file under the wrong master key is said to be exactly that.
        MasterKey.Create(Path.Combine(_directory, "other.key"));
        using var other = MasterKey.Load(Path.Combine(_directory, "other.key"));
        Assert.Equal("backup.wrong_key", await Refusal(whole.ToArray(), other));

        // And the untouched file still restores.
        await using (var context = target())
        {
            await Archive(context).RestoreAsync(() => new MemoryStream(whole.ToArray()), TestContext.Current.CancellationToken);
            Assert.True(await context.Vaults.AnyAsync(TestContext.Current.CancellationToken));
        }
    }

    [Fact]
    public async Task Backups_are_files_that_were_read_back_kept_to_a_number_and_handled_by_super_admins_only()
    {
        var source = await NewDatabaseAsync(Sqlite);
        await FillAsync(source, new TestCertificate("shop.example.test"));
        var folder = Path.Combine(_directory, "backups");
        var clock = new SteppingClock();
        var status = new BackupStatus();
        await using var context = source();
        var service = new BackupService(new BackupArchive(context, BackupSeal.From(_master), clock), new BackupOptions(folder, Keep: 2), status, new AuditWriter(new EfSecretStore(context), clock), clock);

        Assert.Null(status.LastVerifiedUtc);
        Assert.Null(await service.VerifyNewestAsync(TestContext.Current.CancellationToken));
        var first = await service.CreateAsync(Root, TestContext.Current.CancellationToken);
        var second = await service.CreateAsync(Root, TestContext.Current.CancellationToken);
        var third = await service.CreateAsync(Root, TestContext.Current.CancellationToken);

        // The newest two are kept, nothing half-written is left, and the newest one sets the age a monitor reads.
        Assert.Equal([third.Name, second.Name], service.List(Root).Select(file => file.Name));
        Assert.Equal([second.Name, third.Name], Directory.GetFiles(folder).Select(Path.GetFileName).Order());
        Assert.DoesNotContain(first.Name, Directory.GetFiles(folder).Select(Path.GetFileName));
        Assert.Equal(third.CreatedUtc, status.LastVerifiedUtc);

        // A server that starts finds out from the files how old its last good backup is; a damaged newest one does not count.
        var restarted = new BackupStatus();
        var again = new BackupService(new BackupArchive(context, BackupSeal.From(_master), clock), new BackupOptions(folder, Keep: 2), restarted, new AuditWriter(new EfSecretStore(context), clock), clock);
        Assert.NotNull(await again.VerifyNewestAsync(TestContext.Current.CancellationToken));
        Assert.Equal(third.CreatedUtc, restarted.LastVerifiedUtc);
        var bytes = await File.ReadAllBytesAsync(Path.Combine(folder, third.Name), TestContext.Current.CancellationToken);
        await File.WriteAllBytesAsync(Path.Combine(folder, third.Name), bytes[..(bytes.Length - 40)], TestContext.Current.CancellationToken);
        var damaged = new BackupStatus();
        var third2 = new BackupService(new BackupArchive(context, BackupSeal.From(_master), clock), new BackupOptions(folder, Keep: 2), damaged, new AuditWriter(new EfSecretStore(context), clock), clock);
        Assert.Null(await third2.VerifyNewestAsync(TestContext.Current.CancellationToken));
        Assert.Null(damaged.LastVerifiedUtc);
        Assert.NotNull(damaged.LastError);

        // Only a super admin, and never a key; and only names this service wrote ever reach the file system.
        foreach (var caller in new[] { new Caller("an-admin", UserKey: 2, Role: UserRole.Admin), new Caller("root", UserKey: 1, Role: UserRole.SuperAdmin, KeyId: 7), new Caller("someone", UserKey: 3) })
        {
            Assert.Equal("access.denied", Assert.Throws<DomainException>(() => service.List(caller)).Code);
            Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => service.CreateAsync(caller))).Code);
            Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => service.OpenAsync(second.Name, caller))).Code);
        }

        foreach (var name in new[] { "../master.key", "..\\master.key", "secrethive-20260101-000000.shbak/../../master.key", "master.key", "" })
        {
            Assert.Equal("backup.not_found", (await Assert.ThrowsAsync<DomainException>(() => service.OpenAsync(name, Root))).Code);
        }

        await using (var opened = await service.OpenAsync(second.Name, Root, TestContext.Current.CancellationToken))
        {
            Assert.True(opened.Length > 0);
        }

        var trail = await Secrets(context).AuditAsync(500, Root);
        Assert.Equal(3, trail.Count(row => row.Code == "backup.created"));
        Assert.Contains(trail, row => row.Code == "backup.downloaded" && row.Detail == second.Name);
    }

    /// <summary>A clock that moves a minute every time it is read, so each backup gets a name of its own.</summary>
    private sealed class SteppingClock : TimeProvider
    {
        private DateTimeOffset now = new(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => now = now.AddMinutes(1);
    }
}
