using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Cli.Commands;
using SecretHive.Cli.Server;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Unit.Tests;

/// <summary>
/// The command line against a real server: pulling a stack's secrets into its bundle, rendering straight from the
/// server, falling back to the bundle when the server does not answer, and not falling back when it says no.
/// </summary>
public sealed class ServerProviderTests : IAsyncLifetime
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";
    private const string Manifest = """
        version: 1
        stack: shop
        vault: shop-prod
        targets:
          app:
            path: ${appdata}/shop/secrets
            owner: "999:999"
            restart: [shop]
            keys:
              Api__Token: api-token
              Api__Pin: api-token#pin
              Queue__Password: mail/queue-password
              Site__Pfx: site#pfx
        """;

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-cli-server-").FullName;
    private WebApplicationFactory<SecretHive.Web.ServerMarker> _factory = null!;
    private HttpClient _admin = null!;
    private Stack _stack = null!;
    private TestCertificate _site = null!;
    private string _key = "";
    private int _jobKey;
    private bool _down;

    public async ValueTask InitializeAsync()
    {
        MasterKey.Create(Path.Combine(_directory, "master.key"));
        System.IO.File.WriteAllText(Path.Combine(_directory, "admin.token"), Token);
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

        // On the server: two vaults, a secret with a sensitive field, another secret, and a certificate.
        _site = new TestCertificate("shop.example.test");
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/mail", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/api-token", new { value = "generated-token-1" });
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/api-token", new { value = "generated-token-2", fields = new[] { new { name = "pin", value = "generated-pin", sensitive = true } } });
        await _admin.PutAsJsonAsync("/api/v1/vaults/mail/secrets/queue-password", new { value = "generated-queue" });
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/certificates/site", new
        {
            parts = new object[]
            {
                new { kind = "certificate", fileName = "site.cer", content = Convert.ToBase64String(_site.Der) },
                new { kind = "pfx", fileName = "site.pfx", content = Convert.ToBase64String(_site.Pfx) },
                new { kind = "pfx-password", text = TestCertificate.Password },
            },
        });

        // The host's own identity, set up the way a script would: a name, a role in each vault, and a key.
        var identity = await _admin.PutAsJsonAsync("/api/v1/service-identities/stack-web-1-shop", new { description = "the shop stack on web-1" });
        Assert.Equal(HttpStatusCode.Created, identity.StatusCode);
        _jobKey = System.Text.Json.JsonDocument.Parse(await identity.Content.ReadAsStringAsync()).RootElement.GetProperty("key").GetInt32();
        Assert.Equal(HttpStatusCode.OK, (await _admin.PutAsJsonAsync("/api/v1/service-identities/stack-web-1-shop", new { })).StatusCode);
        foreach (var vault in new[] { "shop-prod", "mail" })
        {
            Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync($"/api/v1/vaults/{vault}/access", new { user = "stack-web-1-shop", role = "SecretsUser" })).StatusCode);
        }

        var made = await _admin.PostAsJsonAsync("/api/v1/service-identities/stack-web-1-shop/keys", new { label = "deploy on web-1", days = 30 });
        Assert.Equal(HttpStatusCode.OK, made.StatusCode);
        _key = System.Text.Json.JsonDocument.Parse(await made.Content.ReadAsStringAsync()).RootElement.GetProperty("key").GetString()!;

        _stack = new Stack(Manifest);
        File.WriteAllText(Path.Combine(_stack.Root, "server.key"), _key + "\n");
        _stack.Server = (address, keyFile) => new HttpSecretServer(address, keyFile, _down ? new Silent() : _factory.Server.CreateHandler());
        Providers("[api, bundle]");
    }

    public async ValueTask DisposeAsync()
    {
        _stack.Dispose();
        _admin.Dispose();
        await _factory.DisposeAsync();
        Directory.Delete(_directory, recursive: true);
    }

    private void Providers(string providers, string server = "http://localhost") =>
        System.IO.File.WriteAllText(Path.Combine(_stack.Repository, "secrethive.host.yml"), $"""
            version: 1
            host: web-1
            appdata: '{_stack.AppData}'
            bundle_key: '{Path.Combine(_stack.Root, "host.key")}'
            providers: {providers}
            server: {server}
            server_key: '{Path.Combine(_stack.Root, "server.key")}'
            """);

    private int Run(params string[] args)
    {
        _stack.Output.Clear();
        return _stack.Run(args);
    }

    /// <summary>Runs a command and expects an exit code; what the command said is in the failure when it differs.</summary>
    private void Expect(int expected, params string[] args)
    {
        var code = Run(args);
        Assert.True(expected == code, $"exit {code}, expected {expected}: {_stack.Output}");
    }

    private string Written(string key) => Encoding.UTF8.GetString(_stack.Files.Read(Path.Combine(_stack.Target(), key)));

    private async Task<int> ReadsOnRecord()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Audit.CountAsync(row => row.Principal == "stack-web-1-shop" && (row.Code == "secret.value.read" || row.Code == "certificate.part.read"));
    }

    private void NothingSecretWasPrinted()
    {
        var output = _stack.Output.ToString();
        foreach (var secret in new[] { "generated-token-1", "generated-token-2", "generated-token-3", "generated-pin", "generated-queue", _key, TestCertificate.Password })
        {
            Assert.DoesNotContain(secret, output, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Pull_seals_what_the_server_has_for_this_host_and_reads_again_only_what_changed()
    {
        Expect(App.Changed, "bundle", "pull", "shop", "--host", "web-1");
        var output = _stack.Output.ToString();
        Assert.Contains("pulled     shop-prod/api-token  version 2", output);
        Assert.Contains("pulled     shop-prod/api-token#pin  version 2", output);
        Assert.Contains("pulled     mail/queue-password  version 1", output);
        Assert.Contains("pulled     shop-prod/site#pfx  version 1", output);
        NothingSecretWasPrinted();
        Assert.Equal(4, await ReadsOnRecord());

        // The bundle is ciphertext for this host: it holds names and versions, no value and not the key.
        var bundle = System.IO.File.ReadAllText(_stack.BundlePath);
        Assert.Contains("shop-prod/api-token", bundle);
        Assert.DoesNotContain("generated-", bundle, StringComparison.Ordinal);
        Assert.DoesNotContain(_key, bundle, StringComparison.Ordinal);

        // In step: a second pull reads no value at all.
        Expect(App.Ok, "bundle", "pull", "shop", "--host", "web-1");
        Assert.Equal(4, _stack.Output.ToString().Split('\n').Count(line => line.StartsWith("unchanged  ", StringComparison.Ordinal)));
        Assert.Equal(4, await ReadsOnRecord());

        // A new version on the server: exactly the references of that secret are read again.
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/api-token", new { value = "generated-token-3", fields = new[] { new { name = "pin", value = "generated-pin", sensitive = true } } });
        Expect(App.Changed, "bundle", "pull", "shop", "--host", "web-1");
        Assert.Contains("pulled     shop-prod/api-token  version 3", _stack.Output.ToString());
        Assert.Contains("unchanged  mail/queue-password", _stack.Output.ToString());
        Assert.Equal(6, await ReadsOnRecord());

        // Rendered from the bundle alone, with the server out of the picture, the files hold what the server had.
        Providers("[bundle]", server: "");
        System.IO.File.WriteAllText(Path.Combine(_stack.Repository, "secrethive.host.yml"), System.IO.File.ReadAllText(Path.Combine(_stack.Repository, "secrethive.host.yml")).Replace("server: \n", "", StringComparison.Ordinal).Replace($"server_key: '{Path.Combine(_stack.Root, "server.key")}'", "", StringComparison.Ordinal));
        Expect(App.Changed, "render", "shop", "--host", "web-1");
        Assert.Equal(("generated-token-3", "generated-pin", "generated-queue"), (Written("Api__Token"), Written("Api__Pin"), Written("Queue__Password")));
        Assert.Equal(_site.Pfx, _stack.Files.Read(Path.Combine(_stack.Target(), "Site__Pfx")));
        NothingSecretWasPrinted();
    }

    [Fact]
    public async Task Render_reads_the_server_first_and_the_bundle_only_when_the_server_does_not_answer()
    {
        // Straight from the server, with no bundle at all: each value is a read on record under the host's identity.
        Expect(App.Changed, "render", "shop", "--host", "web-1");
        Assert.Equal(("generated-token-2", "generated-pin", "generated-queue"), (Written("Api__Token"), Written("Api__Pin"), Written("Queue__Password")));
        Assert.DoesNotContain("fallback", _stack.Output.ToString(), StringComparison.Ordinal);
        Assert.Equal(4, await ReadsOnRecord());
        NothingSecretWasPrinted();

        // The bundle is the fallback, and status says when it is behind what the server has.
        Expect(App.Drift, "status", "shop", "--host", "web-1");
        Assert.Contains("stale    bundle  shop-prod/api-token  holds nothing, the server has version 2", _stack.Output.ToString());
        Expect(App.Changed, "bundle", "pull", "shop", "--host", "web-1");
        Expect(App.Ok, "status", "shop", "--host", "web-1");
        Assert.Contains("in-step  shop", _stack.Output.ToString());

        // A new value on the server: status sees the files and the bundle are both behind, render brings the files along.
        await _admin.PutAsJsonAsync("/api/v1/vaults/mail/secrets/queue-password", new { value = "generated-queue-2" });
        Expect(App.Drift, "status", "shop", "--host", "web-1");
        Assert.Contains("differs  app  Queue__Password", _stack.Output.ToString());
        Assert.Contains("stale    bundle  mail/queue-password  holds 1, the server has version 2", _stack.Output.ToString());
        Expect(App.Changed, "render", "shop", "--host", "web-1");
        Assert.Equal("generated-queue-2", Written("Queue__Password"));
        Assert.Contains("restart  shop", _stack.Output.ToString());

        // The server stops answering. The deploy goes on from the bundle, says so, and the bundle is one pull behind.
        _down = true;
        Expect(App.Changed, "render", "shop", "--host", "web-1");
        Assert.Contains("fallback bundle  shop:", _stack.Output.ToString());
        Assert.Equal("generated-queue", Written("Queue__Password"));
        Expect(App.Refused, "bundle", "pull", "shop", "--host", "web-1");
        Assert.Contains("the server is not reachable", _stack.Output.ToString());

        // A host with no bundle to fall back on is refused instead, and nothing is touched.
        Providers("[api]");
        Expect(App.Refused, "render", "shop", "--host", "web-1");
        Assert.Contains("no bundle to fall back on", _stack.Output.ToString());
        Assert.Equal("generated-queue", Written("Queue__Password"));
        NothingSecretWasPrinted();
    }

    [Fact]
    public async Task A_reference_pinned_to_a_version_gets_that_version_from_the_server()
    {
        System.IO.File.WriteAllText(Path.Combine(_stack.Repository, "shop", "secrethive.yml"), """
            version: 1
            stack: shop
            vault: shop-prod
            targets:
              app:
                path: ${appdata}/shop/secrets
                owner: "999:999"
                restart: [shop]
                keys:
                  Api__Token: shop-prod/api-token/1
            """);

        Expect(App.Changed, "render", "shop", "--host", "web-1");
        Assert.Equal("generated-token-1", Written("Api__Token"));

        // The server moving on does not move a pin: the file stays what version 1 held, and the bundle seals that version.
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/api-token", new { value = "generated-token-3" });
        Expect(App.Ok, "render", "shop", "--host", "web-1");
        Expect(App.Changed, "bundle", "pull", "shop", "--host", "web-1");
        Assert.Contains("pulled     shop-prod/api-token  version 1", _stack.Output.ToString());
        Expect(App.Ok, "bundle", "pull", "shop", "--host", "web-1");

        // The read of an earlier version is on record as one.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            Assert.Contains(await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Audit.ToListAsync(), row => row.Principal == "stack-web-1-shop" && row.Detail == "version 1, not the current one");
        }

        // A version the secret never reached is refused by name, not answered with something else.
        System.IO.File.WriteAllText(Path.Combine(_stack.Repository, "shop", "secrethive.yml"), System.IO.File.ReadAllText(Path.Combine(_stack.Repository, "shop", "secrethive.yml")).Replace("api-token/1", "api-token/9", StringComparison.Ordinal));
        Expect(App.Refused, "render", "shop", "--host", "web-1");
        Assert.Contains("is pinned to a version the server does not have (its current version is 3)", _stack.Output.ToString());
        NothingSecretWasPrinted();
    }

    [Fact]
    public async Task A_refusal_is_an_answer_and_the_bundle_is_not_used_to_get_around_it()
    {
        Expect(App.Changed, "bundle", "pull", "shop", "--host", "web-1");
        Expect(App.Changed, "render", "shop", "--host", "web-1");

        // The role is taken down to Reader: the host may see what exists and read nothing. Not a reason to use the bundle.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            await scope.ServiceProvider.GetRequiredService<SecretService>().AssignAsync("mail", _jobKey, null, VaultRole.Reader, Caller.System("setup"));
        }

        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/api-token", new { value = "generated-token-3", fields = new[] { new { name = "pin", value = "generated-pin", sensitive = true } } });
        Expect(App.Refused, "render", "shop", "--host", "web-1");
        Assert.Contains("app Queue__Password: mail/queue-password: the server refuses (403)", _stack.Output.ToString());
        Assert.Contains("Secrets User", _stack.Output.ToString());
        Assert.DoesNotContain("fallback", _stack.Output.ToString(), StringComparison.Ordinal);
        Assert.Equal("generated-token-2", Written("Api__Token")); // nothing was written: a render is all or nothing

        // A secret the manifest names and the server does not have.
        await _admin.DeleteAsync("/api/v1/vaults/mail/secrets/queue-password");
        Expect(App.Refused, "bundle", "pull", "shop", "--host", "web-1");
        Assert.Contains("mail/queue-password is not on the server", _stack.Output.ToString());

        // The key is revoked: the server no longer knows this host, and the bundle it pulled earlier does not stand in.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var keys = scope.ServiceProvider.GetRequiredService<KeyService>();
            var key = (await keys.ListAsync(Caller.System("setup"), _jobKey)).Single();
            await keys.RevokeAsync(Caller.System("setup"), key.Key);
        }

        Expect(App.Refused, "render", "shop", "--host", "web-1");
        Assert.Contains("the server does not accept the key in", _stack.Output.ToString());
        Assert.DoesNotContain("fallback", _stack.Output.ToString(), StringComparison.Ordinal);
        NothingSecretWasPrinted();
    }

    [Fact]
    public async Task Setting_a_host_up_through_the_api_is_for_administrators_and_a_key_asked_to_be_limited_is_never_left_unlimited()
    {
        // The host's own key manages nothing, least of all identities and keys.
        using var asHost = _factory.CreateClient();
        asHost.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _key);
        Assert.Equal(HttpStatusCode.Forbidden, (await asHost.PutAsJsonAsync("/api/v1/service-identities/another", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await asHost.PostAsJsonAsync("/api/v1/service-identities/stack-web-1-shop/keys", new { label = "more" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await asHost.PutAsJsonAsync("/api/v1/vaults/mail/access", new { user = "stack-web-1-shop", role = "VaultAdmin" })).StatusCode);

        // A person's account is not turned into a service identity by naming it.
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.PutAsJsonAsync("/api/v1/service-identities/admin", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PostAsJsonAsync("/api/v1/service-identities/admin/keys", new { label = "x" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/vaults/mail/access", new { user = "nobody-by-this-name", role = "Reader" })).StatusCode);

        // A second key, limited to a network: it works from nowhere else, and the first key is untouched.
        var limited = await _admin.PostAsJsonAsync("/api/v1/service-identities/stack-web-1-shop/keys", new { label = "from the lan", networks = new[] { "192.0.2.0/24" } });
        Assert.Equal(HttpStatusCode.OK, limited.StatusCode);
        var limitedKey = System.Text.Json.JsonDocument.Parse(await limited.Content.ReadAsStringAsync()).RootElement.GetProperty("key").GetString()!;
        using var elsewhere = _factory.CreateClient();
        elsewhere.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", limitedKey);
        Assert.Equal(HttpStatusCode.Unauthorized, (await elsewhere.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await asHost.GetAsync("/api/v1/vaults")).StatusCode);

        // Two keys work at once and no more. One asked for with a network that is not one is not made at all.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var keys = scope.ServiceProvider.GetRequiredService<KeyService>();
            var second = (await keys.ListAsync(Caller.System("setup"), _jobKey)).Single(key => key.Label == "from the lan");
            await keys.RevokeAsync(Caller.System("setup"), second.Key);
        }

        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PostAsJsonAsync("/api/v1/service-identities/stack-web-1-shop/keys", new { label = "broken", networks = new[] { "the lan" } })).StatusCode);
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var all = await scope.ServiceProvider.GetRequiredService<KeyService>().ListAsync(Caller.System("setup"), _jobKey);
            Assert.Single(all, key => key.IsActive(DateTime.UtcNow));
        }
    }

    private const string MovingManifest = """
        version: 1
        stack: shop
        vault: shop-new
        targets:
          app:
            path: ${appdata}/shop/secrets
            owner: "999:999"
            restart: [shop]
            keys:
              Db__Password: db-password
              Db__User: db-password#user
              Queue__Password: mail/queue-password
        """;

    /// <summary>
    /// A stack that lives in its bundle only, on a host whose profile names the server without reading from it, and
    /// a key that may write to the stack's vault: the situation on the day a stack is moved onto the server.
    /// </summary>
    private async Task<(Stack Stack, string OfficerKeyFile)> AStackToMoveAsync()
    {
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-new", new { });
        await _admin.PutAsJsonAsync("/api/v1/service-identities/mover", new { description = "moves stacks onto the server" });
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop-new/access", new { user = "mover", role = "SecretsOfficer" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/mail/access", new { user = "mover", role = "SecretsUser" })).StatusCode);
        var made = await _admin.PostAsJsonAsync("/api/v1/service-identities/mover/keys", new { label = "one move", days = 1 });
        var key = System.Text.Json.JsonDocument.Parse(await made.Content.ReadAsStringAsync()).RootElement.GetProperty("key").GetString()!;

        var stack = new Stack(MovingManifest) { Server = _stack.Server };
        var keyFile = Path.Combine(stack.Root, "officer.key");
        System.IO.File.WriteAllText(keyFile, key + "\n");
        System.IO.File.AppendAllText(Path.Combine(stack.Repository, "secrethive.host.yml"), "\nserver: http://localhost\n");
        stack.Set("db-password", "generated-db-1");
        stack.Set("db-password#user", "generated-user");
        stack.Set("mail/queue-password", "generated-queue");
        stack.Output.Clear();
        return (stack, keyFile);
    }

    private async Task<string?> OnTheServer(string path)
    {
        var response = await _admin.GetAsync(new Uri($"/api/v1/vaults/{path}", UriKind.Relative));
        return response.StatusCode == HttpStatusCode.NotFound
            ? null
            : System.Text.Json.JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement.GetProperty("value").GetString();
    }

    [Fact]
    public async Task Push_makes_on_the_server_what_it_lacks_and_leaves_the_bundle_as_the_fallback_in_step()
    {
        var (stack, officer) = await AStackToMoveAsync();
        using var cleanup = stack;

        // The host's own key only reads, so the key that writes has to be named.
        Assert.Equal(App.Refused, stack.Run("bundle", "push", "shop", "--host", "web-1"));
        Assert.Contains("--server-key", stack.Output.ToString());

        // A dry run says what would happen and writes nothing, here or there.
        var before = System.IO.File.ReadAllText(stack.BundlePath);
        stack.Output.Clear();
        Assert.Equal(App.Ok, stack.Run("bundle", "push", "shop", "--host", "web-1", "--dry-run", "--server-key", officer));
        Assert.Contains("create     shop-new/db-password  fields: user", stack.Output.ToString());
        Assert.Contains("same       mail/queue-password  version 1", stack.Output.ToString());
        Assert.Null(await OnTheServer("shop-new/secrets/db-password/value"));
        Assert.Equal(before, System.IO.File.ReadAllText(stack.BundlePath));

        stack.Output.Clear();
        Assert.Equal(App.Changed, stack.Run("bundle", "push", "shop", "--host", "web-1", "--server-key", officer));
        Assert.Contains("created    shop-new/db-password  version 1  fields: user", stack.Output.ToString());
        Assert.Equal("generated-db-1", await OnTheServer("shop-new/secrets/db-password/value"));
        Assert.Equal("generated-user", await OnTheServer("shop-new/secrets/db-password/fields/user"));
        Assert.Equal("generated-queue", await OnTheServer("mail/secrets/queue-password/value"));
        foreach (var secret in new[] { "generated-db-1", "generated-user", "generated-queue" })
        {
            Assert.DoesNotContain(secret, stack.Output.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(secret, System.IO.File.ReadAllText(stack.BundlePath), StringComparison.Ordinal);
        }

        // It is on record who made it, and the field went in as a sensitive one.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>();
            Assert.True(await db.Audit.AnyAsync(row => row.Principal == "mover" && row.Vault == "shop-new"));
        }

        // A second push finds everything there, and makes nothing twice.
        stack.Output.Clear();
        Assert.Equal(App.Ok, stack.Run("bundle", "push", "shop", "--host", "web-1", "--server-key", officer));
        Assert.Equal(3, stack.Output.ToString().Split('\n').Count(line => line.StartsWith("same       ", StringComparison.Ordinal)));
        Assert.Equal("generated-db-1", await OnTheServer("shop-new/secrets/db-password/value"));

        // The host is switched to the server: the bundle already carries the server's versions, so nothing is pulled.
        System.IO.File.WriteAllText(Path.Combine(stack.Repository, "secrethive.host.yml"), $"""
            version: 1
            host: web-1
            appdata: '{stack.AppData}'
            bundle_key: '{Path.Combine(stack.Root, "host.key")}'
            providers: [api, bundle]
            server: http://localhost
            server_key: '{officer}'
            """);
        stack.Output.Clear();
        Assert.Equal(App.Ok, stack.Run("bundle", "pull", "shop", "--host", "web-1"));
        Assert.Equal(3, stack.Output.ToString().Split('\n').Count(line => line.StartsWith("unchanged  ", StringComparison.Ordinal)));
        Assert.Equal(App.Changed, stack.Run("render", "shop", "--host", "web-1"));
        Assert.Equal("generated-db-1", Encoding.UTF8.GetString(stack.Files.Read(Path.Combine(stack.Target(), "Db__Password"))));
    }

    [Fact]
    public async Task Push_never_overwrites_and_writes_nothing_when_anything_is_in_doubt()
    {
        var (stack, officer) = await AStackToMoveAsync();
        using var cleanup = stack;

        // The server and the bundle disagree about one value: that is for a person to settle, and nothing else is made either.
        stack.Set("mail/queue-password", "generated-other");
        stack.Output.Clear();
        Assert.Equal(App.Refused, stack.Run("bundle", "push", "shop", "--host", "web-1", "--server-key", officer));
        Assert.Contains("mail/queue-password: the server holds something else (its version 1)", stack.Output.ToString());
        Assert.Contains("nothing was written", stack.Output.ToString());
        Assert.Null(await OnTheServer("shop-new/secrets/db-password/value"));
        Assert.Equal("generated-queue", await OnTheServer("mail/secrets/queue-password/value"));
        Assert.DoesNotContain("generated-", stack.Output.ToString(), StringComparison.Ordinal);
        stack.Set("mail/queue-password", "generated-queue");

        // A key whose owner has no role in the vault cannot even tell that it exists.
        stack.Output.Clear();
        Assert.Equal(App.Refused, stack.Run("bundle", "push", "shop", "--host", "web-1", "--server-key", Path.Combine(_stack.Root, "server.key")));
        Assert.Contains("shop-new: there is no vault 'shop-new' as far as this key can tell", stack.Output.ToString());

        // A key that may read and not write: the server refuses the write, and says which role is needed.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop-new/access", new { user = "stack-web-1-shop", role = "SecretsUser" })).StatusCode);
        stack.Output.Clear();
        Assert.Equal(App.Refused, stack.Run("bundle", "push", "shop", "--host", "web-1", "--server-key", Path.Combine(_stack.Root, "server.key")));
        Assert.Contains("shop-new/db-password: the server refuses (403)", stack.Output.ToString());
        Assert.Contains("stopped after 0 of 1", stack.Output.ToString());
        Assert.Null(await OnTheServer("shop-new/secrets/db-password/value"));

        // A reference the bundle does not hold.
        Assert.Equal(App.Ok, stack.Run("bundle", "prune", "shop", "--host", "web-1"));
        System.IO.File.WriteAllText(Path.Combine(stack.Repository, "shop", "secrethive.yml"), MovingManifest + "\n      Extra__Key: not-sealed\n");
        stack.Output.Clear();
        Assert.Equal(App.Refused, stack.Run("bundle", "push", "shop", "--host", "web-1", "--server-key", officer));
        Assert.Contains("shop-new/not-sealed: is not in the bundle", stack.Output.ToString());
        Assert.Null(await OnTheServer("shop-new/secrets/db-password/value"));
    }

    [Fact]
    public async Task Push_makes_a_certificate_on_the_server_from_the_parts_the_bundle_holds()
    {
        // The stack reads three parts of the certificate; a pull seals them for this host.
        System.IO.File.WriteAllText(Path.Combine(_stack.Repository, "shop", "secrethive.yml"), """
            version: 1
            stack: shop
            vault: shop-prod
            targets:
              app:
                path: ${appdata}/shop/secrets
                owner: "999:999"
                restart: [shop]
                keys:
                  Site__Pfx: site#pfx
                  Site__PfxPassword: site#pfx-password
                  Site__Cer: site#certificate
            """);
        Expect(App.Changed, "bundle", "pull", "shop", "--host", "web-1");

        // The certificate leaves the server, and a key that may write to the vault is named for the push.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/vaults/shop-prod/secrets/site")).StatusCode);
        await _admin.PutAsJsonAsync("/api/v1/service-identities/mover", new { description = "moves stacks onto the server" });
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/access", new { user = "mover", role = "SecretsOfficer" })).StatusCode);
        var made = await _admin.PostAsJsonAsync("/api/v1/service-identities/mover/keys", new { label = "one move", days = 1 });
        var officer = Path.Combine(_stack.Root, "officer.key");
        System.IO.File.WriteAllText(officer, System.Text.Json.JsonDocument.Parse(await made.Content.ReadAsStringAsync()).RootElement.GetProperty("key").GetString() + "\n");

        Expect(App.Ok, "bundle", "push", "shop", "--host", "web-1", "--dry-run", "--server-key", officer);
        Assert.Contains("create     shop-prod/site  parts: certificate, pfx, pfx-password", _stack.Output.ToString());
        Expect(App.Changed, "bundle", "push", "shop", "--host", "web-1", "--server-key", officer);
        Assert.Contains("created    shop-prod/site  version 1  parts: certificate, pfx, pfx-password", _stack.Output.ToString());

        // What the server made is the same certificate, read from the parts, with the parts under their file names.
        var listing = await _admin.GetStringAsync("/api/v1/vaults/shop-prod/secrets");
        var listed = System.Text.Json.JsonDocument.Parse(listing).RootElement.EnumerateArray().Single(entry => entry.GetProperty("name").GetString() == "site");
        Assert.Equal("Certificate", listed.GetProperty("kind").GetString());
        Assert.Equal(_site.Thumbprint, listed.GetProperty("certificate").GetProperty("thumbprint").GetString());
        Assert.Contains("site.pfx", listing, StringComparison.Ordinal);
        var pfx = await _admin.GetAsync("/api/v1/vaults/shop-prod/certificates/site/parts/pfx");
        Assert.Equal(_site.Pfx, await pfx.Content.ReadAsByteArrayAsync());

        // Pushed again: every part compares equal and nothing is made twice.
        Expect(App.Ok, "bundle", "push", "shop", "--host", "web-1", "--server-key", officer);
        Assert.Equal(3, _stack.Output.ToString().Split('\n').Count(line => line.StartsWith("same       shop-prod/site#", StringComparison.Ordinal)));
        NothingSecretWasPrinted();

        // A reference that is not a part of a certificate is refused by name, and nothing is made.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/vaults/shop-prod/secrets/site")).StatusCode);
        System.IO.File.AppendAllText(Path.Combine(_stack.Repository, "shop", "secrethive.yml"), "\n      Site__Seal: site#seal\n");
        _stack.Set("site#seal", "generated-seal");
        Expect(App.Refused, "bundle", "push", "shop", "--host", "web-1", "--server-key", officer);
        Assert.Contains("shop-prod/site: shop-prod/site#seal is not a part of a certificate", _stack.Output.ToString());
        Assert.DoesNotContain("\"name\":\"site\"", await _admin.GetStringAsync("/api/v1/vaults/shop-prod/secrets"), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("[api, bundle]", "http://vault.example.org", "'server' must be an https address")]
    [InlineData("[bundle, api]", "https://vault.example.org", "'providers' is [bundle], [api, bundle] or [api]")]
    [InlineData("[api, files]", "https://vault.example.org", "'providers' is [bundle], [api, bundle] or [api]")]
    public void A_profile_that_does_not_say_clearly_where_values_come_from_is_refused(string providers, string server, string message)
    {
        Providers(providers, server);
        Expect(App.Refused, "render", "shop", "--host", "web-1", "--dry-run");
        Assert.Contains(message, _stack.Output.ToString());
    }

    [Fact]
    public void A_key_file_that_holds_something_else_is_refused_without_repeating_it()
    {
        System.IO.File.WriteAllText(Path.Combine(_stack.Root, "server.key"), "generated-not-a-key with spaces");
        Expect(App.Refused, "bundle", "pull", "shop", "--host", "web-1");
        Assert.Contains("this is not a SecretHive key", _stack.Output.ToString());
        Assert.DoesNotContain("generated-not-a-key", _stack.Output.ToString(), StringComparison.Ordinal);
    }

    /// <summary>A server that is not there.</summary>
    private sealed class Silent : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            throw new HttpRequestException("connection refused", new System.Net.Sockets.SocketException());
    }
}
