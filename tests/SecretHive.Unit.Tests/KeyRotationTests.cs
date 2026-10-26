using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Backup;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Unit.Tests;

/// <summary>
/// Moving to a new master key, through the server as it is started: with the new key and the old one named as
/// retired, then with the new key alone. And what happens with a key the database was never written under.
/// </summary>
public sealed class KeyRotationTests : IDisposable
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-rotation-").FullName;
    private readonly string _old;
    private readonly string _new;

    public KeyRotationTests()
    {
        _old = Path.Combine(_directory, "old.key");
        _new = Path.Combine(_directory, "new.key");
        MasterKey.Create(_old);
        MasterKey.Create(_new);
        File.WriteAllText(Path.Combine(_directory, "admin.token"), Token);
    }

    public void Dispose()
    {
        Directory.Delete(_directory, recursive: true);
    }

    private WebApplicationFactory<SecretHive.Web.ServerMarker> Server(string masterKeyFile, string? retired = null) =>
        new WebApplicationFactory<SecretHive.Web.ServerMarker>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("SecretHive:MasterKeyFile", masterKeyFile);
            builder.UseSetting("SecretHive:RetiredMasterKeyFiles", retired ?? "");
            builder.UseSetting("SecretHive:Auth:BootstrapAdminTokenFile", Path.Combine(_directory, "admin.token"));
            builder.UseSetting("SecretHive:DataDirectory", _directory);
            builder.UseSetting("SecretHive:Tls:Enabled", "false");
            builder.UseSetting("SecretHive:Database:Provider", "Sqlite");
            builder.UseSetting("SecretHive:Database:ConnectionString", $"Data Source={Path.Combine(_directory, "secrethive.db")};Pooling=False");
            builder.UseSetting("Logging:LogLevel:Default", "Warning");
        });

    private static HttpClient Admin(WebApplicationFactory<SecretHive.Web.ServerMarker> server)
    {
        var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return client;
    }

    private static async Task<string?> Value(HttpClient client, string path) =>
        JsonDocument.Parse(await client.GetStringAsync(path)).RootElement.GetProperty("value").GetString();

    private static async Task<T> With<T>(WebApplicationFactory<SecretHive.Web.ServerMarker> server, Func<IServiceProvider, Task<T>> act)
    {
        await using var scope = server.Services.CreateAsyncScope();
        return await act(scope.ServiceProvider);
    }

    [Fact]
    public async Task Started_with_the_new_key_and_the_old_one_retired_the_server_moves_everything_and_then_needs_only_the_new_key()
    {
        string oldId, newId, backupName;
        using (var oldKey = MasterKey.Load(_old))
        using (var newKey = MasterKey.Load(_new))
        {
            (oldId, newId) = (oldKey.Id, newKey.Id);
        }

        // Under the old key: a secret with two versions and a sensitive field, a sign-in provider, and a backup.
        using (var server = Server(_old))
        using (var admin = Admin(server))
        {
            await admin.PutAsJsonAsync("/api/v1/vaults/shop", new { });
            await admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-one" });
            await admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-two", fields = new[] { new { name = "pin", value = "generated-pin", sensitive = true } } });
            await admin.PutAsJsonAsync("/api/v1/providers/idp", new { authority = "https://auth.example.org/o/secrethive", clientId = "client-1", clientSecret = "generated-client-secret", enabled = false });
            backupName = JsonDocument.Parse(await (await admin.PostAsync("/api/v1/backups", null)).Content.ReadAsStringAsync()).RootElement.GetProperty("name").GetString()!;
            Assert.Equal([oldId], await With(server, services => services.GetRequiredService<SecretHiveDbContext>().Versions.Select(version => version.DataKeyId).Distinct().ToListAsync()));
        }


        // The new key alone cannot read any of it. The server says so and does not start, rather than serve a vault that opens nothing.
        using (var blind = Server(_new))
        {
            var refusal = Assert.ThrowsAny<Exception>(() => blind.CreateClient()).ToString();
            Assert.Contains(oldId, refusal, StringComparison.Ordinal);
            Assert.Contains("RetiredMasterKeyFiles", refusal, StringComparison.Ordinal);
        }


        // The rotation: new key current, old key retired. It happens at start.
        using (var server = Server(_new, _old))
        using (var admin = Admin(server))
        {
            Assert.Equal("generated-two", await Value(admin, "/api/v1/vaults/shop/secrets/token/value"));
            Assert.Equal("generated-pin", await Value(admin, "/api/v1/vaults/shop/secrets/token/fields/pin"));
            Assert.Equal([newId], await With(server, services => services.GetRequiredService<SecretHiveDbContext>().Versions.Select(version => version.DataKeyId).Distinct().ToListAsync()));
            Assert.Equal(newId, JsonDocument.Parse(await admin.GetStringAsync("/health")).RootElement.GetProperty("masterKey").GetString());

            var rotated = Assert.Single(await With(server, services => services.GetRequiredService<SecretHiveDbContext>().Audit.Where(row => row.Code == "keyring.rotated").ToListAsync()));
            Assert.Equal((AuditSeverity.Security, $"from={oldId} to={newId} versions=2"), (rotated.Severity, rotated.Detail));

            // The backup from before the rotation still verifies while the old key is named.
            await using var before = File.OpenRead(Path.Combine(_directory, "backups", backupName));
            Assert.Equal(oldId, (await With(server, services => services.GetRequiredService<BackupArchive>().VerifyAsync(before))).MasterKeyId);
        }


        // From now on the old key is needed for nothing: the new key alone reads the values and the provider's secret.
        using (var server = Server(_new))
        using (var admin = Admin(server))
        {
            Assert.Equal("generated-two", await Value(admin, "/api/v1/vaults/shop/secrets/token/value"));
            Assert.Contains("\"hasClientSecret\":true", await admin.GetStringAsync("/api/v1/providers"), StringComparison.Ordinal);
            Assert.Single(await With(server, services => services.GetRequiredService<SecretHiveDbContext>().Audit.Where(row => row.Code == "keyring.rotated").ToListAsync()));

            // The old backup is now sealed under a key this server does not have, and is refused as exactly that.
            await using var before = File.OpenRead(Path.Combine(_directory, "backups", backupName));
            var refused = await Assert.ThrowsAsync<DomainException>(() => With(server, services => services.GetRequiredService<BackupArchive>().VerifyAsync(before)));
            Assert.Equal("backup.wrong_key", refused.Code);

            // A new value and a new backup are under the new key.
            Assert.True((await admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-three" })).IsSuccessStatusCode);
            Assert.Equal(HttpStatusCode.OK, (await admin.PostAsync("/api/v1/backups", null)).StatusCode);
        }


        // And the old key alone is now the wrong key.
        using var stale = Server(_old);
        Assert.Contains(newId, Assert.ThrowsAny<Exception>(() => stale.CreateClient()).ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Whoever_is_signed_in_stays_signed_in_through_a_rotation_and_after_the_old_key_is_gone()
    {
        static string Field(string html) => System.Text.RegularExpressions.Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"").Groups[1].Value;
        string cookie;

        // Signed in under the old key. The first administrator has to choose a password first.
        using (var server = Server(_old))
        using (var browser = server.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false }))
        {
            async Task<HttpResponseMessage> Post(string path, string handler, params (string Name, string Value)[] fields)
            {
                var values = fields.ToDictionary(field => field.Name, field => field.Value);
                values["_handler"] = handler;
                values["__RequestVerificationToken"] = Field(await browser.GetStringAsync(path));
                return await browser.PostAsync(path, new FormUrlEncodedContent(values));
            }

            await Post("/login", "signin", ("UserName", "admin"), ("Password", Token));
            var changed = await Post("/account/password", "password", ("Current", Token), ("New", "generated-chosen-password"), ("Again", "generated-chosen-password"));
            var signedIn = changed.Headers.TryGetValues("Set-Cookie", out var set) ? set.FirstOrDefault(value => value.StartsWith("secrethive=", StringComparison.Ordinal)) : null;
            if (signedIn is null)
            {
                signedIn = (await Post("/login", "signin", ("UserName", "admin"), ("Password", "generated-chosen-password"))).Headers.GetValues("Set-Cookie").First(value => value.StartsWith("secrethive=", StringComparison.Ordinal));
            }

            cookie = signedIn.Split(';')[0];
        }

        async Task<HttpStatusCode> Home(WebApplicationFactory<SecretHive.Web.ServerMarker> server)
        {
            using var browser = server.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = false });
            using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/vaults");
            request.Headers.Add("Cookie", cookie);
            return (await browser.SendAsync(request)).StatusCode;
        }

        using (var rotating = Server(_new, _old))
        {
            Assert.Equal(HttpStatusCode.OK, await Home(rotating));
        }

        // The session key files themselves are now under the new key: none names the old one any more.
        string oldId;
        using (var oldKey = MasterKey.Load(_old))
        {
            oldId = oldKey.Id;
        }

        Assert.All(Directory.GetFiles(Path.Combine(_directory, "session-keys"), "*.xml"), file => Assert.DoesNotContain(oldId, File.ReadAllText(file), StringComparison.Ordinal));

        using var after = Server(_new);
        Assert.Equal(HttpStatusCode.OK, await Home(after));
    }

    [Fact]
    public async Task A_rotation_never_reads_a_value_and_running_it_again_changes_nothing()
    {
        using var oldKey = MasterKey.Load(_old);
        using var newKey = MasterKey.Load(_new);
        SecretHiveDbContext Open()
        {
            var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
            SecretHive.Infrastructure.Sqlite.SqliteProvider.UseSecretHiveSqlite(builder, $"Data Source={Path.Combine(_directory, "unit.db")};Pooling=False");
            return new SecretHiveDbContext(builder.Options);
        }

        var root = Caller.System("test");
        using (var ring = new KeyRing(oldKey))
        {
            await using var db = Open();
            await db.Database.MigrateAsync(TestContext.Current.CancellationToken);
            var secrets = new SecretService(new EfSecretStore(db), ring, TimeProvider.System, new EfAccessStore(db), new EfUserStore(db));
            await secrets.CreateVaultAsync("shop", null, root);
            for (var i = 0; i < 7; i++)
            {
                await secrets.SetAsync(new SetSecret("shop", "token-" + i, System.Text.Encoding.UTF8.GetBytes("generated-" + i)), root);
            }
        }

        List<byte[]> items;
        await using (var db = Open())
        {
            items = await db.VersionItems.OrderBy(item => item.Id).Select(item => item.Content).ToListAsync(TestContext.Current.CancellationToken);
        }

        using (var both = new KeyRing(newKey, [oldKey]))
        {
            await using var db = Open();
            var result = await new KeyRotation(new EfSecretStore(db), both, TimeProvider.System).RunAsync(TestContext.Current.CancellationToken);
            Assert.Equal((7, 0), (result.Moved, result.Unreadable.Count));
            var again = await new KeyRotation(new EfSecretStore(db), both, TimeProvider.System).RunAsync(TestContext.Current.CancellationToken);
            Assert.Equal(0, again.Moved);
        }

        await using (var db = Open())
        {
            // The encrypted values are byte for byte what they were: only the small key record of each version changed.
            Assert.Equal(items, await db.VersionItems.OrderBy(item => item.Id).Select(item => item.Content).ToListAsync(TestContext.Current.CancellationToken));
            Assert.Single(await db.Audit.Where(row => row.Code == "keyring.rotated").ToListAsync(TestContext.Current.CancellationToken));

            using var onlyNew = new KeyRing(newKey);
            var secrets = new SecretService(new EfSecretStore(db), onlyNew, TimeProvider.System, new EfAccessStore(db), new EfUserStore(db));
            using var value = await secrets.ReadAsync("shop", "token-3", root);
            Assert.Equal("generated-3", System.Text.Encoding.UTF8.GetString(value.Reveal()));

            // With a key that never had anything to do with this database: nothing moves, and it is said which key is missing.
            MasterKey.Create(Path.Combine(_directory, "third.key"));
            using var third = MasterKey.Load(Path.Combine(_directory, "third.key"));
            using var wrong = new KeyRing(third);
            var lost = await new KeyRotation(new EfSecretStore(db), wrong, TimeProvider.System).RunAsync(TestContext.Current.CancellationToken);
            Assert.Equal((0, newKey.Id), (lost.Moved, Assert.Single(lost.Unreadable)));
        }
    }
}
