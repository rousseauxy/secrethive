using System.Text;
using Microsoft.EntityFrameworkCore;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;
using SecretHive.Infrastructure.Sqlite;
using SecretHive.Infrastructure.SqlServer;

namespace SecretHive.Unit.Tests;

/// <summary>
/// The use cases against a real database, written once and run on both providers. Every step uses a fresh context,
/// as a request would, so nothing passes because it was still in memory.
/// </summary>
public abstract class SecretStoreTests : IAsyncLifetime
{
    // Unrestricted, as the bootstrap token is: these tests are about what the use cases do, not about who may ask.
    // Who may ask is in VaultAccessTests.
    private static readonly Caller Alice = new("alice", "100.64.0.4", "ui", Unrestricted: true);

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-db-").FullName;
    private KeyRing _keyRing = null!;
    private TimeProvider _clock = TimeProvider.System;

    /// <summary>Null when this provider is available here; otherwise why its tests are skipped.</summary>
    protected virtual string? Unavailable => null;

    protected string Root => _directory;

    protected abstract SecretHiveDbContext NewContext();

    protected virtual Task DropAsync() => Task.CompletedTask;

    public async ValueTask InitializeAsync()
    {
        Assert.SkipWhen(Unavailable is not null, Unavailable ?? "");
        var keyPath = Path.Combine(_directory, "master.key");
        MasterKey.Create(keyPath);
        _keyRing = new KeyRing(MasterKey.Load(keyPath));
        await using var context = NewContext();
        await context.Database.MigrateAsync();
    }

    public async ValueTask DisposeAsync()
    {
        if (Unavailable is null)
        {
            await DropAsync();
            _keyRing.Dispose();
        }

        Directory.Delete(_directory, recursive: true);
        GC.SuppressFinalize(this);
    }

    private async Task<T> With<T>(Func<SecretService, Task<T>> act)
    {
        await using var context = NewContext();
        return await act(new SecretService(new EfSecretStore(context), _keyRing, _clock, new EfAccessStore(context), new EfUserStore(context)));
    }

    private Task With(Func<SecretService, Task> act) => With(async service =>
    {
        await act(service);
        return 0;
    });

    private async Task<List<AuditEvent>> AuditAsync()
    {
        await using var context = NewContext();
        return await context.Audit.OrderBy(row => row.Id).ToListAsync();
    }

    private static ReadOnlyMemory<byte> Bytes(string text) => Encoding.UTF8.GetBytes(text);

    private static string Text(SecretBytes bytes) => Encoding.UTF8.GetString(bytes.Reveal());

    [Fact]
    public async Task The_migrations_describe_the_model()
    {
        await using var context = NewContext();

        Assert.False(context.Database.HasPendingModelChanges());
        Assert.Empty(await context.Database.GetPendingMigrationsAsync());
    }

    [Fact]
    public async Task A_secret_can_be_set_and_read_and_every_step_is_on_record()
    {
        await With(service => service.CreateVaultAsync("shop-prod", "generated-vault-description", Alice));
        var number = await With(service => service.SetAsync(new SetSecret("shop-prod", "sql-app-connection", Bytes("generated-value"), Description: "generated-description"), Alice));

        using var value = await With(service => service.ReadAsync("Shop-Prod", "SQL-App-Connection", Alice));

        Assert.Equal(1, number);
        Assert.Equal("generated-value", Text(value));
        var audit = await AuditAsync();
        Assert.Equal(["vault.created", "secret.created", "secret.value.read"], audit.Select(row => row.Code));
        var read = audit[2];
        Assert.Equal(("alice", "100.64.0.4", "ui", "shop-prod", "sql-app-connection", "value"), (read.Principal, read.Address, read.Via, read.Vault, read.Secret, read.Slot));
        Assert.NotNull(read.VersionId);
        Assert.Equal(DateTimeKind.Utc, read.AtUtc.Kind);
    }

    [Fact]
    public async Task Values_and_sensitive_fields_are_ciphertext_and_everything_else_can_be_queried()
    {
        await With(service => service.CreateVaultAsync("shop-prod", "billing vault", Alice));
        await With(service => service.SetAsync(
            new SetSecret(
                "shop-prod",
                "api-login",
                Bytes("generated-value"),
                Description: "used by the billing export",
                Fields:
                [
                    new FieldInput("owner", Bytes("team-a")),
                    new FieldInput("keyvault-name", Bytes("shop-appreg")),
                    new FieldInput("username", Bytes("generated-hidden-user"), Sensitive: true),
                    new FieldInput("pin", Bytes("generated-pin"), Sensitive: true),
                ]),
            Alice));
        await With(service => service.SetAsync(new SetSecret("shop-prod", "other", Bytes("generated-other"), Fields: [new FieldInput("owner", Bytes("team-b"))]), Alice));

        await using var context = NewContext();

        // What is secret: ciphertext, whatever the column.
        var stored = new List<byte[]>();
        stored.AddRange(await context.Versions.Select(row => row.DataKey).ToListAsync());
        stored.AddRange(await context.VersionItems.Select(row => row.Content).ToListAsync());
        Assert.Equal(6, stored.Count);
        Assert.All(stored, column => Assert.DoesNotContain("generated", Encoding.Latin1.GetString(column)));

        // What is not: plain columns a report can filter on. These run as SQL in the database, not in memory.
        var ownedByTeamA = await context.EntryFields.Where(field => field.Name == "owner" && field.Value == "team-a")
            .Join(context.Entries, field => field.EntryId, entry => entry.Id, (field, entry) => entry.Name).ToListAsync();
        var syncedAs = await context.EntryFields.Where(field => field.Name == "keyvault-name" && field.Value == "shop-appreg").CountAsync();
        var describedAsBilling = await context.Entries.Where(entry => entry.Description!.Contains("billing")).Select(entry => entry.Name).ToListAsync();
        Assert.Equal(["api-login"], ownedByTeamA);
        Assert.Equal(1, syncedAs);
        Assert.Equal(["api-login"], describedAsBilling);
        Assert.Equal("billing vault", (await context.Vaults.SingleAsync()).Description);

        // A reserved field marked sensitive is treated like any sensitive field: gone from the plain columns.
        Assert.DoesNotContain("username", await context.EntryFields.Select(field => field.Name).ToListAsync());
        Assert.Equal(["field:pin", "field:username", "value", "value"], await context.VersionItems.Select(row => row.Slot).OrderBy(slot => slot).ToListAsync());
    }

    [Fact]
    public async Task A_listing_shows_fields_and_versions_and_reads_no_value()
    {
        await With(service => service.CreateVaultAsync("shop-prod", null, Alice));
        await With(service => service.SetAsync(
            new SetSecret(
                "shop-prod",
                "app-registration",
                Bytes("generated-client-secret"),
                Fields:
                [
                    new FieldInput("username", Bytes("generated-client-id")),
                    new FieldInput("keyvault-name", Bytes("shop-appreg")),
                    new FieldInput("url", Bytes("https://example.test/app"), FieldType.Url),
                    new FieldInput("recovery-code", Bytes("generated-recovery"), Sensitive: true),
                ]),
            Alice));
        var before = (await AuditAsync()).Count;

        var listing = await With(service => service.ListAsync("shop-prod", Alice));

        var secret = Assert.Single(listing);
        Assert.Equal(("app-registration", 1, true), (secret.Name, secret.Version, secret.Enabled));
        Assert.Equal("generated-client-id", secret.Fields["username"]);
        Assert.Equal("shop-appreg", secret.Fields["keyvault-name"]);
        Assert.Equal(["recovery-code"], secret.SensitiveFields);
        Assert.DoesNotContain("recovery-code", secret.Fields.Keys);
        Assert.Equal(before, (await AuditAsync()).Count);

        // The sensitive field is read like the value: by name, and on record.
        using var code = await With(service => service.ReadAsync("shop-prod", "app-registration", Alice, "field:recovery-code"));
        Assert.Equal("generated-recovery", Text(code));
        Assert.Equal("field:recovery-code", (await AuditAsync())[^1].Slot);
    }

    [Fact]
    public async Task Setting_again_makes_a_new_version_and_replaces_the_fields()
    {
        await With(service => service.CreateVaultAsync("shop-prod", null, Alice));
        await With(service => service.SetAsync(new SetSecret("shop-prod", "token", Bytes("generated-one"), Fields: [new FieldInput("owner", Bytes("team-a")), new FieldInput("region", Bytes("west"))]), Alice));
        var first = Assert.Single(await With(service => service.ListAsync("shop-prod", Alice)));

        var number = await With(service => service.SetAsync(new SetSecret("shop-prod", "token", Bytes("generated-two"), Fields: [new FieldInput("owner", Bytes("team-b"))]), Alice));

        var second = Assert.Single(await With(service => service.ListAsync("shop-prod", Alice)));
        using var value = await With(service => service.ReadAsync("shop-prod", "token", Alice));
        Assert.Equal(2, number);
        Assert.Equal("generated-two", Text(value));
        Assert.NotEqual(first.VersionId, second.VersionId);
        Assert.Equal(first.EntryId, second.EntryId);
        Assert.Equal(new Dictionary<string, string> { ["owner"] = "team-b" }, second.Fields);

        // The old version is still stored: versions are immutable, and a rotation is never an overwrite.
        await using var context = NewContext();
        Assert.Equal(2, await context.Versions.CountAsync());
        Assert.Equal("secret.version.set", (await AuditAsync())[^2].Code);
    }

    [Fact]
    public async Task A_deleted_secret_goes_to_the_bin_frees_its_name_and_can_come_back()
    {
        await With(service => service.CreateVaultAsync("shop-prod", null, Alice));
        await With(service => service.SetAsync(new SetSecret("shop-prod", "token", Bytes("generated-old")), Alice));

        await With(service => service.DeleteAsync("shop-prod", "token", Alice));

        Assert.Empty(await With(service => service.ListAsync("shop-prod", Alice)));
        Assert.Equal("secret.not_found", (await Assert.ThrowsAsync<DomainException>(() => With(service => service.ReadAsync("shop-prod", "token", Alice)))).Code);
        var binned = Assert.Single(await With(service => service.ListAsync("shop-prod", Alice, bin: true)));
        Assert.Equal(("token", "alice"), (binned.Name, binned.DeletedBy));
        Assert.NotNull(binned.DeletedUtc);

        // The name is free again, and a second deletion of the same name is fine too.
        await With(service => service.SetAsync(new SetSecret("shop-prod", "token", Bytes("generated-new")), Alice));
        Assert.Equal("secret.name.taken", (await Assert.ThrowsAsync<DomainException>(() => With(service => service.RestoreAsync("shop-prod", binned.EntryId, Alice)))).Code);

        await With(service => service.RestoreAsync("shop-prod", binned.EntryId, Alice, "token-restored"));

        using var restored = await With(service => service.ReadAsync("shop-prod", "token-restored", Alice));
        using var current = await With(service => service.ReadAsync("shop-prod", "token", Alice));
        Assert.Equal("generated-old", Text(restored));
        Assert.Equal("generated-new", Text(current));
        Assert.Empty(await With(service => service.ListAsync("shop-prod", Alice, bin: true)));

        await With(service => service.DeleteAsync("shop-prod", "token", Alice));
        await With(service => service.DeleteAsync("shop-prod", "token-restored", Alice));
        Assert.Equal(2, (await With(service => service.ListAsync("shop-prod", Alice, bin: true))).Count);
    }

    [Fact]
    public async Task A_certificate_keeps_its_forms_together_and_only_its_private_parts_are_audited_reads()
    {
        var site = new TestCertificate("shop.example.test");
        await With(service => service.CreateVaultAsync("edge", null, Alice));

        var number = await With(service => service.ImportCertificateAsync(
            new ImportCertificate("edge", "shop-site", [site.CertificatePart, site.PfxPart, TestCertificate.PasswordPart()], "generated-description"),
            Alice));

        var listed = Assert.Single(await With(service => service.ListAsync("edge", Alice)));
        Assert.Equal((1, ValueKind.Certificate, "generated-description"), (number, listed.Kind, listed.Description));
        Assert.Equal(site.Thumbprint, listed.Certificate!.Thumbprint);
        Assert.Equal(["shop.example.test", "www.shop.example.test"], listed.Certificate.AlternativeNames);
        Assert.Equal(
            [("certificate", "site.cer", false), ("pfx", "site.pfx", true), ("pfx-password", "", true)],
            listed.Parts!.Select(part => (part.Kind, part.FileName ?? "", part.Private)));

        // The public half: no audit row.
        var before = (await AuditAsync()).Count;
        using (var certificate = await With(service => service.ReadPartAsync("edge", "shop-site", CertificatePartKind.Certificate, Alice)))
        {
            Assert.Equal(site.Der, certificate.Content.Bytes.Reveal().ToArray());
            Assert.Equal("site.cer", certificate.FileName);
        }

        Assert.Equal(before, (await AuditAsync()).Count);

        // The private half: the same bytes that went in, and on record.
        using (var pfx = await With(service => service.ReadPartAsync("edge", "shop-site", CertificatePartKind.Pfx, Alice)))
        using (var password = await With(service => service.ReadPartAsync("edge", "shop-site", CertificatePartKind.PfxPassword, Alice)))
        {
            Assert.Equal(site.Pfx, pfx.Content.Bytes.Reveal().ToArray());
            Assert.Equal(TestCertificate.Password, Text(password.Content.Bytes));
        }

        Assert.Equal(["part:pfx", "part:pfx-password"], (await AuditAsync()).Skip(before).Select(row => row.Slot));
        Assert.Equal("secret.slot.not_found", (await Assert.ThrowsAsync<DomainException>(() => With(service => service.ReadPartAsync("edge", "shop-site", CertificatePartKind.Key, Alice)))).Code);

        // The expiry is the certificate's own, readable where a query can find it; the parts are not readable.
        await using var context = NewContext();
        Assert.InRange((await context.Values.SingleAsync()).ExpiresUtc!.Value, site.NotAfterUtc.UtcDateTime.AddMinutes(-1), site.NotAfterUtc.UtcDateTime.AddMinutes(1));
        Assert.All(await context.VersionItems.Select(row => row.Content).ToListAsync(), content => Assert.DoesNotContain(TestCertificate.Password, Encoding.Latin1.GetString(content)));
        Assert.Equal("generated-description", (await context.Entries.SingleAsync()).Description);
    }

    [Fact]
    public async Task A_renewal_is_a_new_version_and_a_certificate_is_not_a_secret()
    {
        var site = new TestCertificate("shop.example.test", validDays: 30);
        var renewed = new TestCertificate("shop.example.test", validDays: 400);
        await With(service => service.CreateVaultAsync("edge", null, Alice));
        await With(service => service.ImportCertificateAsync(new ImportCertificate("edge", "shop-site", [site.ChainPart, site.KeyPart]), Alice));
        await With(service => service.SetAsync(new SetSecret("edge", "token", Bytes("generated-token")), Alice));

        var number = await With(service => service.ImportCertificateAsync(new ImportCertificate("edge", "shop-site", [renewed.ChainPart, renewed.KeyPart]), Alice));

        var listed = (await With(service => service.ListAsync("edge", Alice))).Single(item => item.Name == "shop-site");
        Assert.Equal((2, renewed.Thumbprint), (number, listed.Certificate!.Thumbprint));
        await using (var context = NewContext())
        {
            // Both versions stay: a rotation that proves possession with the old certificate needs old and new at once.
            Assert.Equal(2, await context.Certificates.CountAsync());
        }

        async Task<string> Code(Func<SecretService, Task> act) => (await Assert.ThrowsAsync<DomainException>(() => With(act))).Code;
        Assert.Equal("secret.kind.mismatch", await Code(service => service.SetAsync(new SetSecret("edge", "shop-site", Bytes("generated")), Alice)));
        Assert.Equal("secret.kind.mismatch", await Code(service => service.ImportCertificateAsync(new ImportCertificate("edge", "token", [site.CertificatePart]), Alice)));
        Assert.Equal("certificate.key.mismatch", await Code(service => service.ImportCertificateAsync(new ImportCertificate("edge", "shop-site", [site.ChainPart, renewed.KeyPart]), Alice)));
        Assert.Equal(2, (await With(service => service.ListAsync("edge", Alice))).Single(item => item.Name == "shop-site").Version);
    }

    private async Task<string> CodeOf(Func<SecretService, Task> act) => (await Assert.ThrowsAsync<DomainException>(() => With(act))).Code;

    [Fact]
    public async Task Earlier_versions_are_kept_listed_read_on_record_and_can_be_made_current_again()
    {
        await With(service => service.CreateVaultAsync("app-a", null, Alice));
        await With(service => service.CreateVaultAsync("app-b", null, Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "token", Bytes("generated-one"), Description: "the token", Fields: [new FieldInput("pin", Bytes("generated-pin-one"), Sensitive: true)]), Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "token", Bytes("generated-two"), Fields: [new FieldInput("pin", Bytes("generated-pin-two"), Sensitive: true)], KeepDetails: true), Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "token", Bytes("generated-three"), KeepDetails: true), Alice));
        await With(service => service.LinkAsync("app-a", "token", "app-b", "their-token", Alice));

        // The history names what each version holds and who made it, and holds no value.
        var history = await With(service => service.ListVersionsAsync("app-a", "token", Alice));
        Assert.Equal([3, 2, 1], history.Select(version => version.Number));
        Assert.Equal([true, false, false], history.Select(version => version.Current));
        Assert.Equal(["value"], history[0].Slots);
        Assert.Equal(["field:pin", "value"], history[2].Slots);
        Assert.All(history, version => Assert.Equal("alice", version.CreatedBy));

        // An earlier version is read like the current one, and the row says which version it was.
        using (var first = await With(service => service.ReadAsync("app-a", "token", Alice, number: 1)))
        using (var pin = await With(service => service.ReadAsync("app-a", "token", Alice, "field:pin", 2)))
        using (var current = await With(service => service.ReadAsync("app-a", "token", Alice)))
        {
            Assert.Equal(("generated-one", "generated-pin-two", "generated-three"), (Text(first), Text(pin), Text(current)));
        }

        var reads = (await AuditAsync()).Where(row => row.Code == "secret.value.read").ToList();
        Assert.Contains(reads, row => row.Detail == "version 1, not the current one" && row.Slot == "value" && row.VersionId == history[2].Id);
        Assert.Contains(reads, row => row.Detail == "version 2, not the current one" && row.Slot == "field:pin");
        Assert.Contains(reads, row => row.Detail is null && row.VersionId == history[0].Id);
        Assert.Equal("secret.version.not_found", await CodeOf(service => service.ReadAsync("app-a", "token", Alice, number: 9)));
        Assert.Equal("secret.slot.not_found", await CodeOf(service => service.ReadAsync("app-a", "token", Alice, "field:pin", 3)));

        // Going back makes a new version with what the old one held, the sensitive field included; nothing is lost.
        Assert.Equal("secret.version.current", await CodeOf(service => service.RestoreVersionAsync("app-a", "token", 3, Alice)));
        Assert.Equal("secret.version.not_found", await CodeOf(service => service.RestoreVersionAsync("app-a", "token", 9, Alice)));
        Assert.Equal(4, await With(service => service.RestoreVersionAsync("app-a", "token", 1, Alice)));
        Assert.Equal("generated-one", await ReadText("app-a", "token"));
        using (var pin = await With(service => service.ReadAsync("app-a", "token", Alice, "field:pin")))
        {
            Assert.Equal("generated-pin-one", Text(pin));
        }

        // The linked name in the other vault follows, as with any new version; what was current in between is still there.
        Assert.Equal("generated-one", await ReadText("app-b", "their-token"));
        using (var between = await With(service => service.ReadAsync("app-b", "their-token", Alice, number: 3)))
        {
            Assert.Equal("generated-three", Text(between));
        }

        var after = await With(service => service.ListVersionsAsync("app-b", "their-token", Alice));
        Assert.Equal([4, 3, 2, 1], after.Select(version => version.Number));
        Assert.Equal("the token", (await With(service => service.ListAsync("app-a", Alice))).Single().Description);
        var restored = Assert.Single(await AuditAsync(), row => row.Code == "secret.version.restored");
        Assert.Equal((AuditSeverity.Notice, "version 4 holds what version 1 held"), (restored.Severity, restored.Detail));
    }

    [Fact]
    public async Task An_earlier_certificate_is_still_whole_and_going_back_to_it_brings_its_dates_back()
    {
        var old = new TestCertificate("shop.example.test", validDays: 30);
        var renewed = new TestCertificate("shop.example.test", validDays: 300);
        await With(service => service.CreateVaultAsync("edge", null, Alice));
        await With(service => service.ImportCertificateAsync(new ImportCertificate("edge", "site", [old.CertificatePart, old.PfxPart, TestCertificate.PasswordPart()]), Alice));
        await With(service => service.ImportCertificateAsync(new ImportCertificate("edge", "site", [renewed.CertificatePart, renewed.PfxPart, TestCertificate.PasswordPart()]), Alice));

        var history = await With(service => service.ListVersionsAsync("edge", "site", Alice));
        Assert.Equal([renewed.Thumbprint, old.Thumbprint], history.Select(version => version.CertificateThumbprint));
        using (var part = await With(service => service.ReadPartAsync("edge", "site", CertificatePartKind.Pfx, Alice, 1)))
        {
            Assert.Equal(("site.pfx", true), (part.FileName, part.Content.Bytes.Reveal().SequenceEqual(old.Pfx)));
        }

        Assert.Equal(3, await With(service => service.RestoreVersionAsync("edge", "site", 1, Alice)));
        var listed = Assert.Single(await With(service => service.ListAsync("edge", Alice)));
        Assert.Equal((3, old.Thumbprint), (listed.Version, listed.Certificate!.Thumbprint));
        using var current = await With(service => service.ReadPartAsync("edge", "site", CertificatePartKind.Pfx, Alice));
        Assert.True(current.Content.Bytes.Reveal().SequenceEqual(old.Pfx));
    }

    private async Task<string> ReadText(string vault, string name)
    {
        using var value = await With(service => service.ReadAsync(vault, name, Alice));
        return Text(value);
    }

    private async Task TwoVaultsWithALinkedToken()
    {
        await With(service => service.CreateVaultAsync("app-a", null, Alice));
        await With(service => service.CreateVaultAsync("app-b", null, Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "github-token", Bytes("generated-one")), Alice));
        await With(service => service.LinkAsync("app-a", "github-token", "app-b", "shop-token", Alice));
    }

    [Fact]
    public async Task A_link_is_two_equal_names_for_one_value()
    {
        await TwoVaultsWithALinkedToken();

        Assert.Equal("generated-one", await ReadText("app-b", "shop-token"));

        // Rotated through either name, both have it, as the same version.
        var number = await With(service => service.SetAsync(new SetSecret("app-b", "shop-token", Bytes("generated-two")), Alice));
        Assert.Equal(2, number);
        Assert.Equal("generated-two", await ReadText("app-a", "github-token"));
        var a = Assert.Single(await With(service => service.ListAsync("app-a", Alice)));
        var b = Assert.Single(await With(service => service.ListAsync("app-b", Alice)));
        Assert.Equal(a.VersionId, b.VersionId);
        Assert.Equal(["app-b/shop-token"], a.LinkedWith);
        Assert.Equal(["app-a/github-token"], b.LinkedWith);
        Assert.Equal(["app-b/shop-token"], await With(service => service.LinkedNamesAsync("app-a", "github-token", Alice)));

        var link = (await AuditAsync()).Single(row => row.Code == "secret.link.created");
        Assert.Equal((AuditSeverity.Security, "app-b", "shop-token", "app-a/github-token"), (link.Severity, link.Vault, link.Secret, link.Detail));
        Assert.Equal("link.same_vault", await CodeOf(service => service.LinkAsync("app-a", "github-token", "app-a", "again", Alice)));
        Assert.Equal("secret.name.taken", await CodeOf(service => service.LinkAsync("app-a", "github-token", "app-b", "shop-token", Alice)));
    }

    [Fact]
    public async Task Linked_names_share_their_ordinary_fields_and_each_keeps_its_own_description()
    {
        await With(service => service.CreateVaultAsync("app-a", null, Alice));
        await With(service => service.CreateVaultAsync("app-b", null, Alice));
        await With(service => service.CreateVaultAsync("app-c", null, Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "web-1", Bytes("generated-ssh-password"), Description: "the deploy user",
            Fields: [new FieldInput("username", Bytes("deploy")), new FieldInput("url", Bytes("https://web-1.example.org"), FieldType.Url)]), Alice));

        // A link starts with the description and the fields.
        await With(service => service.LinkAsync("app-a", "web-1", "app-b", "web-1", Alice));
        var b = Assert.Single(await With(service => service.ListAsync("app-b", Alice)));
        Assert.Equal("the deploy user", b.Description);
        Assert.Equal("deploy", b.Fields["username"]);
        Assert.Equal("https://web-1.example.org", b.Fields["url"]);

        // Details changed through either name: the fields reach the other, the description stays where it was set.
        await With(service => service.UpdateDetailsAsync("app-b", "web-1", "SSH to web-1, for Termix", [new FieldInput("username", Bytes("root"))], Alice));
        var a = Assert.Single(await With(service => service.ListAsync("app-a", Alice)));
        Assert.Equal("the deploy user", a.Description);
        Assert.Equal(new Dictionary<string, string> { ["username"] = "root" }, a.Fields);
        Assert.Equal("SSH to web-1, for Termix", Assert.Single(await With(service => service.ListAsync("app-b", Alice))).Description);

        // A new version that names a field: the same for every name.
        await With(service => service.SetAsync(new SetSecret("app-a", "web-1", Bytes("generated-ssh-password-2"), Fields: [new FieldInput("url", Bytes("https://web-1.example.org/ssh"), FieldType.Url)], Merge: true), Alice));
        b = Assert.Single(await With(service => service.ListAsync("app-b", Alice)));
        Assert.Equal(("root", "https://web-1.example.org/ssh"), (b.Fields["username"], b.Fields["url"]));

        // A name in a bin is kept in step too, so restoring it brings back the fields as they are now.
        await With(service => service.LinkAsync("app-a", "web-1", "app-c", "web-1", Alice));
        await With(service => service.DeleteAsync("app-c", "web-1", Alice));
        await With(service => service.UpdateDetailsAsync("app-a", "web-1", "the deploy user", [new FieldInput("username", Bytes("deploy-2"))], Alice));
        var binned = Assert.Single(await With(service => service.ListAsync("app-c", Alice, bin: true)));
        await With(service => service.RestoreAsync("app-c", binned.EntryId, Alice));
        Assert.Equal("deploy-2", Assert.Single(await With(service => service.ListAsync("app-c", Alice))).Fields["username"]);

        // Unlinked, a name is on its own: what changes on the others no longer reaches it.
        await With(service => service.UnlinkAsync("app-b", "web-1", Alice));
        await With(service => service.UpdateDetailsAsync("app-a", "web-1", null, [new FieldInput("username", Bytes("deploy-3"))], Alice));
        Assert.Equal("deploy-2", Assert.Single(await With(service => service.ListAsync("app-b", Alice))).Fields["username"]);
        Assert.Equal("deploy-3", Assert.Single(await With(service => service.ListAsync("app-c", Alice))).Fields["username"]);
    }

    [Fact]
    public async Task Links_made_before_shared_fields_are_made_to_agree_once_with_the_oldest_name_winning_on_record()
    {
        await TwoVaultsWithALinkedToken();
        await With(service => service.UpdateDetailsAsync("app-a", "github-token", null, [new FieldInput("username", Bytes("generated-user-a"))], Alice));

        // As a link made before 0.29 can be: each name with fields of its own.
        await using (var context = NewContext())
        {
            var later = await context.Entries.Include(entry => entry.Fields).SingleAsync(entry => entry.Name == "shop-token");
            later.CreatedUtc = DateTime.UtcNow.AddMinutes(5);
            context.EntryFields.RemoveRange(later.Fields);
            later.Fields.Add(new EntryField { Id = Guid.NewGuid(), EntryId = later.Id, Name = "username", Type = FieldType.Text, Value = "generated-user-b" });
            later.Fields.Add(new EntryField { Id = Guid.NewGuid(), EntryId = later.Id, Name = "team", Type = FieldType.Text, Value = "generated-team" });
            await context.SaveChangesAsync();
        }

        Assert.Equal(1, await With(service => service.AlignLinkedFieldsAsync(Caller.System("startup"))));
        var a = Assert.Single(await With(service => service.ListAsync("app-a", Alice))).Fields;
        var b = Assert.Single(await With(service => service.ListAsync("app-b", Alice))).Fields;
        Assert.Equal(a, b);
        Assert.Equal(("generated-user-a", "generated-team"), (a["username"], a["team"]));

        var row = (await AuditAsync()).Single(row => row.Code == "secret.fields.aligned");
        Assert.Equal(AuditSeverity.Info, row.Severity);
        Assert.Contains("username: kept from app-a/github-token, replaced on app-b/shop-token", row.Detail, StringComparison.Ordinal);
        Assert.Contains("team: kept from app-b/shop-token, added on app-a/github-token", row.Detail, StringComparison.Ordinal);
        Assert.DoesNotContain("generated-", row.Detail, StringComparison.Ordinal);

        // Once they agree, a start finds nothing to do.
        Assert.Equal(0, await With(service => service.AlignLinkedFieldsAsync(Caller.System("startup"))));
    }

    [Fact]
    public async Task Deleting_a_linked_name_removes_that_name_only_and_restoring_it_links_it_again()
    {
        await TwoVaultsWithALinkedToken();

        await With(service => service.DeleteAsync("app-b", "shop-token", Alice));

        Assert.Equal("generated-one", await ReadText("app-a", "github-token"));
        Assert.Empty(Assert.Single(await With(service => service.ListAsync("app-a", Alice))).LinkedWith!);
        var binned = Assert.Single(await With(service => service.ListAsync("app-b", Alice, bin: true)));

        await With(service => service.RestoreAsync("app-b", binned.EntryId, Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "github-token", Bytes("generated-two")), Alice));

        Assert.Equal("generated-two", await ReadText("app-b", "shop-token"));
    }

    [Fact]
    public async Task Unlink_leaves_both_names_each_with_a_value_of_its_own()
    {
        await TwoVaultsWithALinkedToken();

        await With(service => service.UnlinkAsync("app-b", "shop-token", Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "github-token", Bytes("generated-two")), Alice));

        Assert.Equal("generated-two", await ReadText("app-a", "github-token"));
        Assert.Equal("generated-one", await ReadText("app-b", "shop-token"));
        var b = Assert.Single(await With(service => service.ListAsync("app-b", Alice)));
        Assert.Equal(("app-a/github-token/1", 1), (b.CopiedFrom, b.Version));
        Assert.Empty(b.LinkedWith!);
        Assert.Equal("secret.not_linked", await CodeOf(service => service.UnlinkAsync("app-b", "shop-token", Alice)));
    }

    [Fact]
    public async Task Delete_everywhere_needs_the_exact_list_of_names_it_removes()
    {
        await TwoVaultsWithALinkedToken();

        Assert.Equal("secret.links.changed", await CodeOf(service => service.DeleteEverywhereAsync("app-a", "github-token", ["app-a/github-token"], Alice)));
        Assert.Equal("generated-one", await ReadText("app-b", "shop-token"));

        await With(service => service.DeleteEverywhereAsync("app-a", "github-token", ["app-b/shop-token", "APP-A/github-token"], Alice));

        Assert.Empty(await With(service => service.ListAsync("app-a", Alice)));
        Assert.Empty(await With(service => service.ListAsync("app-b", Alice)));
        Assert.Equal(["app-a/github-token", "app-b/shop-token"], (await With(service => service.ListAllBinsAsync(Alice))).Select(item => $"{item.Vault}/{item.Name}"));
        var deleted = (await AuditAsync()).Where(row => row.Code == "secret.deleted").ToList();
        Assert.Equal(2, deleted.Count);
        Assert.All(deleted, row => Assert.Equal("app-a/github-token app-b/shop-token", row.Detail));
    }

    [Fact]
    public async Task A_copy_is_independent_says_where_it_came_from_and_is_a_read_of_the_source()
    {
        var site = new TestCertificate("shop.example.test");
        await With(service => service.CreateVaultAsync("app-a", null, Alice));
        await With(service => service.CreateVaultAsync("app-b", null, Alice));
        await With(service => service.SetAsync(
            new SetSecret("app-a", "login", Bytes("generated-one"), Description: "the login", Fields: [new FieldInput("owner", Bytes("team-a")), new FieldInput("pin", Bytes("generated-pin"), Sensitive: true)]),
            Alice));
        await With(service => service.ImportCertificateAsync(new ImportCertificate("app-a", "site", [site.ChainPart, site.KeyPart]), Alice));

        await With(service => service.CopyAsync("app-a", "login", "app-b", null, Alice));
        await With(service => service.CopyAsync("app-a", "site", "app-b", "site-copy", Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "login", Bytes("generated-two")), Alice));

        Assert.Equal("generated-one", await ReadText("app-b", "login"));
        using (var pin = await With(service => service.ReadAsync("app-b", "login", Alice, "field:pin")))
        {
            Assert.Equal("generated-pin", Text(pin));
        }

        var copies = await With(service => service.ListAsync("app-b", Alice));
        var login = copies.Single(item => item.Name == "login");
        Assert.Equal(("app-a/login/1", "the login", "team-a"), (login.CopiedFrom, login.Description, login.Fields["owner"]));
        Assert.Empty(login.LinkedWith!);
        var certificate = copies.Single(item => item.Name == "site-copy");
        Assert.Equal((ValueKind.Certificate, site.Thumbprint), (certificate.Kind, certificate.Certificate!.Thumbprint));
        using (var key = await With(service => service.ReadPartAsync("app-b", "site-copy", CertificatePartKind.Key, Alice)))
        {
            Assert.Equal(site.Key, key.Content.Bytes.Reveal().ToArray());
        }

        var audit = await AuditAsync();
        Assert.Contains(audit, row => row.Code == "secret.value.read" && row.Vault == "app-a" && row.Secret == "login" && row.Slot == "copy");
        Assert.Contains(audit, row => row.Code == "secret.copied" && row.Vault == "app-b" && row.Secret == "login" && row.Detail == "app-a/login");
    }

    [Fact]
    public async Task A_move_takes_the_name_its_history_and_its_links_to_the_other_vault()
    {
        await TwoVaultsWithALinkedToken();
        await With(service => service.CreateVaultAsync("app-c", null, Alice));
        await With(service => service.SetAsync(new SetSecret("app-a", "github-token", Bytes("generated-two")), Alice));
        await With(service => service.SetPurgeProtectionAsync("app-a", true, Alice));

        await With(service => service.MoveAsync("app-a", "github-token", "app-c", "moved-token", Alice));

        Assert.Empty(await With(service => service.ListAsync("app-a", Alice)));
        var moved = Assert.Single(await With(service => service.ListAsync("app-c", Alice)));
        Assert.Equal(("moved-token", 2), (moved.Name, moved.Version));
        Assert.Equal(["app-b/shop-token"], moved.LinkedWith);
        Assert.Equal("generated-two", await ReadText("app-c", "moved-token"));
        Assert.Equal("secret.not_found", await CodeOf(service => service.ReadAsync("app-a", "github-token", Alice)));

        // Leaving a protected vault for an unprotected one is a security event, not a quiet move.
        var audit = (await AuditAsync()).Single(row => row.Code == "secret.moved");
        Assert.Equal((AuditSeverity.Security, "app-c", "moved-token", "app-a/github-token"), (audit.Severity, audit.Vault, audit.Secret, audit.Detail));
        Assert.Equal("secret.name.taken", await CodeOf(service => service.MoveAsync("app-c", "moved-token", "app-b", "shop-token", Alice)));
        Assert.Equal("move.same_vault", await CodeOf(service => service.MoveAsync("app-c", "moved-token", "app-c", "other", Alice)));
    }

    [Fact]
    public async Task A_vault_is_deleted_only_when_it_holds_nothing_and_only_by_a_super_admin()
    {
        await TwoVaultsWithALinkedToken();

        // Not while it holds a secret, and not while its bin does: deleting a vault never destroys a value.
        Assert.Equal("vault.not_empty", await CodeOf(service => service.DeleteVaultAsync("app-a", Caller.System("setup"))));
        await With(service => service.DeleteAsync("app-a", "github-token", Alice));
        Assert.Equal("vault.not_empty", await CodeOf(service => service.DeleteVaultAsync("app-a", Caller.System("setup"))));
        var binned = Assert.Single(await With(service => service.ListAsync("app-a", Alice, bin: true)));
        await With(service => service.PurgeAsync("app-a", binned.EntryId, Alice));

        // Running a vault is not enough, and neither is being an administrator of the server.
        Assert.Equal("access.denied", await CodeOf(service => service.DeleteVaultAsync("app-a", new Caller("an-admin", Via: "ui", Role: UserRole.Admin))));
        Assert.Equal("access.denied", await CodeOf(service => service.DeleteVaultAsync("app-a", new Caller("a-key-of-a-super-admin", Role: UserRole.SuperAdmin, KeyId: 7))));
        Assert.Equal("vault.not_found", await CodeOf(service => service.DeleteVaultAsync("no-such-vault", Caller.System("setup"))));

        await With(service => service.DeleteVaultAsync("app-a", Caller.System("setup")));
        Assert.DoesNotContain(await With(service => service.ListVaultsAsync(Caller.System("setup"))), vault => vault.Name == "app-a");
        Assert.Contains(await AuditAsync(), row => row.Code == "vault.deleted" && row.Severity == AuditSeverity.Security && row.Vault == "app-a");

        // The other vault, and the value the two shared, are untouched; the name is free again.
        Assert.Equal("generated-one", await ReadText("app-b", "shop-token"));
        await using (var context = NewContext())
        {
            Assert.Equal(0, await context.VaultAssignments.CountAsync(row => !context.Vaults.Any(vault => vault.Id == row.VaultId)));
        }

        await With(service => service.CreateVaultAsync("app-a", null, Caller.System("setup")));
    }

    [Fact]
    public async Task Purge_is_the_only_thing_that_destroys_and_the_value_goes_with_its_last_name()
    {
        await TwoVaultsWithALinkedToken();
        await With(service => service.DeleteAsync("app-a", "github-token", Alice));
        await With(service => service.DeleteAsync("app-b", "shop-token", Alice));
        var a = Assert.Single(await With(service => service.ListAsync("app-a", Alice, bin: true)));
        var b = Assert.Single(await With(service => service.ListAsync("app-b", Alice, bin: true)));

        await With(service => service.SetPurgeProtectionAsync("app-a", true, Alice));
        Assert.Equal("vault.purge_protected", await CodeOf(service => service.PurgeAsync("app-a", a.EntryId, Alice)));
        await With(service => service.SetPurgeProtectionAsync("app-a", false, Alice));

        await With(service => service.PurgeAsync("app-a", a.EntryId, Alice));

        // One name is gone for good; the other can still be restored, because the value outlives it.
        await With(service => service.RestoreAsync("app-b", b.EntryId, Alice));
        Assert.Equal("generated-one", await ReadText("app-b", "shop-token"));
        Assert.Equal("secret.not_in_bin", await CodeOf(service => service.PurgeAsync("app-a", a.EntryId, Alice)));

        await With(service => service.DeleteAsync("app-b", "shop-token", Alice));
        await With(service => service.PurgeAsync("app-b", b.EntryId, Alice));

        await using var context = NewContext();
        Assert.Equal((0, 0, 0, 0), (await context.Entries.CountAsync(), await context.Values.CountAsync(), await context.Versions.CountAsync(), await context.VersionItems.CountAsync()));
        Assert.Equal(2, (await AuditAsync()).Count(row => row.Code == "secret.purged" && row.Severity == AuditSeverity.Security));
        Assert.Contains(await AuditAsync(), row => row.Code == "vault.purge_protection.disabled" && row.Severity == AuditSeverity.Security);
    }

    [Fact]
    public async Task Bins_are_never_emptied_until_retention_is_switched_on()
    {
        await TwoVaultsWithALinkedToken();
        await With(service => service.SetAsync(new SetSecret("app-a", "keep", Bytes("generated-keep")), Alice));
        await With(service => service.DeleteAsync("app-a", "github-token", Alice));
        await With(service => service.DeleteAsync("app-b", "shop-token", Alice));

        // Off by default, however long ago the delete was.
        _clock = new ShiftedClock(TimeSpan.FromDays(4000));
        Assert.Null(await With(service => service.GetRetentionDaysAsync()));
        Assert.Equal(0, await With(service => service.PurgeExpiredAsync()));
        Assert.Equal(2, (await With(service => service.ListAllBinsAsync(Alice))).Count);

        _clock = TimeProvider.System;
        Assert.Equal("retention.days.invalid", await CodeOf(service => service.SetRetentionDaysAsync(0, Alice)));
        await With(service => service.SetRetentionDaysAsync(30, Alice));
        Assert.Equal(30, await With(service => service.GetRetentionDaysAsync()));
        Assert.Equal(0, await With(service => service.PurgeExpiredAsync()));

        _clock = new ShiftedClock(TimeSpan.FromDays(31));
        Assert.Equal(2, await With(service => service.PurgeExpiredAsync()));

        Assert.Empty(await With(service => service.ListAllBinsAsync(Alice)));
        Assert.Equal("generated-keep", await ReadText("app-a", "keep"));
        var audit = await AuditAsync();
        Assert.Contains(audit, row => row.Code == "bin.retention.enabled" && row.Severity == AuditSeverity.Security && row.Detail == "30");
        Assert.Equal(2, audit.Count(row => row.Code == "secret.purged" && row.Principal == "retention"));
        await using var context = NewContext();
        Assert.Equal(1, await context.Values.CountAsync());

        _clock = TimeProvider.System;
        await With(service => service.SetRetentionDaysAsync(null, Alice));
        Assert.Null(await With(service => service.GetRetentionDaysAsync()));
    }

    [Fact]
    public async Task Details_change_without_a_version_and_a_new_version_can_keep_what_it_does_not_touch()
    {
        await With(service => service.CreateVaultAsync("shop-prod", null, Alice));
        await With(service => service.SetAsync(
            new SetSecret("shop-prod", "login", Bytes("generated-one"), Description: "first", Fields: [new FieldInput("owner", Bytes("team-a")), new FieldInput("pin", Bytes("generated-pin"), Sensitive: true)]),
            Alice));
        var before = (await AuditAsync()).Count;

        await With(service => service.UpdateDetailsAsync("shop-prod", "login", "second", [new FieldInput("owner", Bytes("team-b")), new FieldInput("application-id", Bytes("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"), FieldType.Uuid)], Alice));

        var changed = Assert.Single(await With(service => service.ListAsync("shop-prod", Alice)));
        Assert.Equal((1, "second", "team-b", 2), (changed.Version, changed.Description, changed.Fields["owner"], changed.Fields.Count));
        Assert.Equal(["pin"], changed.SensitiveFields);
        Assert.Equal("field.sensitive.needs_version", await CodeOf(service => service.UpdateDetailsAsync("shop-prod", "login", null, [new FieldInput("pin", Bytes("x"), Sensitive: true)], Alice)));

        // A rotation of the value alone: the details and the sensitive field come along, and nobody read the field.
        await With(service => service.SetAsync(new SetSecret("shop-prod", "login", Bytes("generated-two"), KeepDetails: true, KeepSensitiveFields: ["pin"]), Alice));

        var rotated = Assert.Single(await With(service => service.ListAsync("shop-prod", Alice)));
        Assert.Equal((2, "second", "team-b"), (rotated.Version, rotated.Description, rotated.Fields["owner"]));
        Assert.Equal(["pin"], rotated.SensitiveFields);
        Assert.Equal(["secret.details.changed", "secret.version.set"], (await AuditAsync()).Skip(before).Select(row => row.Code));
        Assert.Equal("generated-two", await ReadText("shop-prod", "login"));
        using var pin = await With(service => service.ReadAsync("shop-prod", "login", Alice, "field:pin"));
        Assert.Equal("generated-pin", Text(pin));
    }

    [Fact]
    public async Task The_audit_trail_can_be_read_for_one_vault_and_for_one_secret()
    {
        await TwoVaultsWithALinkedToken();
        await With(service => service.SetAsync(new SetSecret("app-a", "other", Bytes("generated-other")), Alice));
        await ReadText("app-a", "github-token");
        await ReadText("app-b", "shop-token");

        var a = await With(service => service.AuditAsync(100, Alice, "APP-A"));
        var b = await With(service => service.AuditAsync(100, Alice, "app-b"));
        var token = await With(service => service.AuditAsync(100, Alice, "app-a", "GitHub-Token"));
        var all = await With(service => service.AuditAsync(100, Alice));

        Assert.Equal(["secret.value.read", "secret.created", "secret.created", "vault.created"], a.Select(row => row.Code));
        Assert.Equal(["secret.value.read", "secret.link.created", "vault.created"], b.Select(row => row.Code));
        Assert.Equal(["secret.value.read", "secret.created"], token.Select(row => row.Code));
        Assert.Equal(a.Count + b.Count, all.Count);
        Assert.Single(await With(service => service.AuditAsync(1, Alice, "app-a")));
    }

    [Fact]
    public async Task Names_are_unique_whatever_their_case_and_bad_input_is_refused_with_a_code()
    {
        await With(service => service.CreateVaultAsync("shop-prod", null, Alice));

        async Task<string> Code(Func<SecretService, Task> act) => (await Assert.ThrowsAsync<DomainException>(() => With(act))).Code;

        Assert.Equal("vault.exists", await Code(service => service.CreateVaultAsync("SHOP-PROD", null, Alice)));
        Assert.Equal("vault.not_found", await Code(service => service.SetAsync(new SetSecret("absent", "token", Bytes("generated")), Alice)));
        Assert.Equal("secret.name.invalid", await Code(service => service.SetAsync(new SetSecret("shop-prod", "Connection__String", Bytes("generated")), Alice)));
        Assert.Equal("secret.value.empty", await Code(service => service.SetAsync(new SetSecret("shop-prod", "token", ReadOnlyMemory<byte>.Empty), Alice)));
        Assert.Equal("secret.value.json", await Code(service => service.SetAsync(new SetSecret("shop-prod", "token", Bytes("generated"), "application/json"), Alice)));
        Assert.Equal("field.reserved.sensitive", await Code(service => service.SetAsync(new SetSecret("shop-prod", "token", Bytes("generated"), Fields: [new FieldInput("owner", Bytes("u"), Sensitive: true)]), Alice)));
        Assert.Equal("secret.slot.not_found", await Code(async service =>
        {
            await service.SetAsync(new SetSecret("shop-prod", "token", Bytes("generated")), Alice);
            await service.ReadAsync("shop-prod", "token", Alice, "field:absent");
        }));

        // Nothing of the refused attempts was stored.
        Assert.Single(await With(service => service.ListAsync("shop-prod", Alice)));
    }
}

/// <summary>The real clock, moved: for what only happens after days have passed.</summary>
internal sealed class ShiftedClock(TimeSpan offset) : TimeProvider
{
    public override DateTimeOffset GetUtcNow() => base.GetUtcNow() + offset;
}

public sealed class SqliteSecretStoreTests : SecretStoreTests
{
    protected override SecretHiveDbContext NewContext()
    {
        var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
        builder.UseSecretHiveSqlite($"Data Source={Path.Combine(Root, "secrethive.db")};Pooling=False");
        return new SecretHiveDbContext(builder.Options);
    }
}

public sealed class SqlServerSecretStoreTests : SecretStoreTests
{
    /// <summary>A SQL Server connection string without a database name. Each test gets a database of its own.</summary>
    public const string Variable = "SECRETHIVE_TEST_SQLSERVER";

    private readonly string _database = "secrethive_test_" + Guid.NewGuid().ToString("N")[..12];

    protected override string? Unavailable =>
        string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(Variable)) ? $"Set {Variable} to run the SQL Server tests." : null;

    protected override SecretHiveDbContext NewContext()
    {
        var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
        builder.UseSecretHiveSqlServer(Environment.GetEnvironmentVariable(Variable)!.TrimEnd(';') + ";Database=" + _database);
        return new SecretHiveDbContext(builder.Options);
    }

    protected override async Task DropAsync()
    {
        await using var context = NewContext();
        await context.Database.EnsureDeletedAsync();
    }
}
