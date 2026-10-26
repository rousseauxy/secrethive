using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Infrastructure.Encryption;

namespace SecretHive.Unit.Tests;

/// <summary>The server as a client sees it: over HTTP, with its own start-up, sign-in, database and key ring.</summary>
public sealed class ApiTests : IDisposable
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-api-").FullName;
    private readonly WebApplicationFactory<SecretHive.Web.ServerMarker> _factory;
    private readonly HttpClient _admin;

    public ApiTests()
    {
        MasterKey.Create(Path.Combine(_directory, "master.key"));
        File.WriteAllText(Path.Combine(_directory, "admin.token"), Token);
        _factory = Server(_directory);
        _admin = _factory.CreateClient();
        _admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
    }

    private static WebApplicationFactory<SecretHive.Web.ServerMarker> Server(string directory, Action<IWebHostBuilder>? configure = null) =>
        new WebApplicationFactory<SecretHive.Web.ServerMarker>().WithWebHostBuilder(builder =>
        {
            builder.UseSetting("SecretHive:MasterKeyFile", Path.Combine(directory, "master.key"));
            builder.UseSetting("SecretHive:Auth:BootstrapAdminTokenFile", Path.Combine(directory, "admin.token"));
            builder.UseSetting("SecretHive:DataDirectory", directory);
            // The test host has no sockets and so no TLS; the image job in CI is where HTTPS is exercised for real.
            builder.UseSetting("SecretHive:Tls:Enabled", "false");
            builder.UseSetting("SecretHive:Database:Provider", "Sqlite");
            builder.UseSetting("SecretHive:Database:ConnectionString", $"Data Source={Path.Combine(directory, "secrethive.db")};Pooling=False");
            builder.UseSetting("Logging:LogLevel:Default", "Warning");
            configure?.Invoke(builder);
        });

    private static async Task<JsonElement> Json(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    [Fact]
    public async Task Health_is_open_and_everything_else_needs_the_token()
    {
        using var anonymous = _factory.CreateClient();
        using var wrong = _factory.CreateClient();
        wrong.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "generated-wrong-token-0123456789abcdef00");

        var health = await anonymous.GetAsync("/health");

        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.True((await Json(health)).GetProperty("database").GetBoolean());
        Assert.Equal(("nosniff", "DENY", "no-referrer"), (health.Headers.GetValues("X-Content-Type-Options").Single(), health.Headers.GetValues("X-Frame-Options").Single(), health.Headers.GetValues("Referrer-Policy").Single()));
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await wrong.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/vaults/shop-prod/secrets/token/value")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/api/v1/vaults")).StatusCode);
    }

    [Fact]
    public async Task A_secret_goes_in_is_listed_without_its_value_is_read_on_record_and_survives_the_bin()
    {
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod", new { description = "generated-vault-description" })).StatusCode);
        var put = await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/app-registration", new
        {
            value = "generated-client-secret",
            description = "generated-description",
            fields = new object[]
            {
                new { name = "username", value = "generated-client-id" },
                new { name = "url", value = "https://example.test/app", type = "Url" },
                new { name = "recovery-code", value = "generated-recovery", sensitive = true },
            },
        });
        Assert.Equal(1, (await Json(put)).GetProperty("version").GetInt32());

        // The listing: fields and versions, and neither the value nor the sensitive field.
        var listing = await _admin.GetStringAsync("/api/v1/vaults/shop-prod/secrets");
        Assert.Contains("generated-client-id", listing);
        Assert.Contains("\"sensitiveFields\":[\"recovery-code\"]", listing);
        Assert.DoesNotContain("generated-client-secret", listing);
        Assert.DoesNotContain("generated-recovery", listing);

        // The two audited reads.
        var value = await _admin.GetAsync("/api/v1/vaults/shop-prod/secrets/app-registration/value");
        Assert.Equal("generated-client-secret", (await Json(value)).GetProperty("value").GetString());
        Assert.Equal("no-store", value.Headers.CacheControl?.ToString());
        var field = await _admin.GetAsync("/api/v1/vaults/shop-prod/secrets/app-registration/fields/recovery-code");
        Assert.Equal("generated-recovery", (await Json(field)).GetProperty("value").GetString());

        // The bin.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync("/api/v1/vaults/shop-prod/secrets/app-registration")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync("/api/v1/vaults/shop-prod/secrets/app-registration/value")).StatusCode);
        var binned = (await Json(await _admin.GetAsync("/api/v1/vaults/shop-prod/bin")))[0];
        var restore = await _admin.PostAsJsonAsync($"/api/v1/vaults/shop-prod/bin/{binned.GetProperty("entryId").GetGuid()}/restore", new { });
        Assert.Equal(HttpStatusCode.NoContent, restore.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/api/v1/vaults/shop-prod/secrets/app-registration/value")).StatusCode);

        // The trail, newest first: who, what, which slot. Never a value.
        var audit = await _admin.GetStringAsync("/api/v1/audit");
        var codes = JsonDocument.Parse(audit).RootElement.EnumerateArray().Select(row => row.GetProperty("code").GetString()).ToList();
        Assert.Equal(
            ["secret.value.read", "secret.restored", "secret.deleted", "secret.value.read", "secret.value.read", "secret.created", "vault.created"],
            codes);
        Assert.Contains("\"slot\":\"field:recovery-code\"", audit);
        Assert.Contains("\"principal\":\"bootstrap-token\"", audit);
        var ofVault = JsonDocument.Parse(await _admin.GetStringAsync("/api/v1/vaults/shop-prod/audit")).RootElement;
        var ofSecret = JsonDocument.Parse(await _admin.GetStringAsync("/api/v1/vaults/shop-prod/audit?secret=app-registration&take=2")).RootElement;
        Assert.Equal(7, ofVault.GetArrayLength());
        Assert.Equal(2, ofSecret.GetArrayLength());
        Assert.Empty(JsonDocument.Parse(await _admin.GetStringAsync("/api/v1/vaults/other/audit")).RootElement.EnumerateArray());
        Assert.DoesNotContain("generated-", audit);
    }

    [Fact]
    public async Task A_broken_rule_is_a_problem_document_with_a_stable_code_and_no_echo_of_the_input()
    {
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop-prod", new { });

        async Task<(HttpStatusCode Status, string? Code, string Body)> Problem(Task<HttpResponseMessage> request)
        {
            var response = await request;
            var body = await response.Content.ReadAsStringAsync();
            return (response.StatusCode, JsonDocument.Parse(body).RootElement.GetProperty("code").GetString(), body);
        }

        var duplicate = await Problem(_admin.PutAsJsonAsync("/api/v1/vaults/SHOP-PROD", new { }));
        var noVault = await Problem(_admin.GetAsync("/api/v1/vaults/absent/secrets"));
        var noSecret = await Problem(_admin.GetAsync("/api/v1/vaults/shop-prod/secrets/absent/value"));
        var badName = await Problem(_admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/Connection__String", new { value = "generated-value" }));
        var badJson = await Problem(_admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/settings", new { value = "generated-not-json", contentType = "application/json" }));
        var empty = await Problem(_admin.PutAsJsonAsync("/api/v1/vaults/shop-prod/secrets/token", new { value = "" }));

        Assert.Equal((HttpStatusCode.Conflict, "vault.exists"), (duplicate.Status, duplicate.Code));
        Assert.Equal((HttpStatusCode.NotFound, "vault.not_found"), (noVault.Status, noVault.Code));
        Assert.Equal((HttpStatusCode.NotFound, "secret.not_found"), (noSecret.Status, noSecret.Code));
        Assert.Equal((HttpStatusCode.BadRequest, "secret.name.invalid"), (badName.Status, badName.Code));
        Assert.Equal((HttpStatusCode.BadRequest, "secret.value.json"), (badJson.Status, badJson.Code));
        Assert.Equal((HttpStatusCode.BadRequest, "secret.value.empty"), (empty.Status, empty.Code));
        Assert.DoesNotContain("generated", badName.Body + badJson.Body);
    }

    [Fact]
    public async Task A_certificate_is_uploaded_in_parts_and_each_part_comes_back_as_the_file_it_was()
    {
        var site = new TestCertificate("shop.example.test");
        await _admin.PutAsJsonAsync("/api/v1/vaults/edge", new { });

        var put = await _admin.PutAsJsonAsync("/api/v1/vaults/edge/certificates/shop-site", new
        {
            description = "generated-description",
            parts = new object[]
            {
                new { kind = "certificate", fileName = "site.cer", content = Convert.ToBase64String(site.Der) },
                new { kind = "pfx", fileName = "site.pfx", content = Convert.ToBase64String(site.Pfx) },
                new { kind = "pfx-password", text = TestCertificate.Password },
            },
        });
        Assert.Equal(HttpStatusCode.OK, put.StatusCode);

        var listing = await _admin.GetStringAsync("/api/v1/vaults/edge/secrets");
        Assert.Contains("\"kind\":\"Certificate\"", listing);
        Assert.Contains(site.Thumbprint, listing);
        Assert.DoesNotContain(TestCertificate.Password, listing);

        var certificate = await _admin.GetAsync("/api/v1/vaults/edge/certificates/shop-site/parts/certificate");
        Assert.Equal(site.Der, await certificate.Content.ReadAsByteArrayAsync());
        Assert.Equal("site.cer", certificate.Content.Headers.ContentDisposition?.FileName);
        var pfx = await _admin.GetAsync("/api/v1/vaults/edge/certificates/shop-site/parts/pfx");
        Assert.Equal(site.Pfx, await pfx.Content.ReadAsByteArrayAsync());
        Assert.Equal("no-store", pfx.Headers.CacheControl?.ToString());

        // Only the private part is on record.
        var audit = await _admin.GetStringAsync("/api/v1/audit");
        Assert.Contains("\"slot\":\"part:pfx\"", audit);
        Assert.DoesNotContain("part:certificate", audit);

        var wrongPassword = await _admin.PutAsJsonAsync("/api/v1/vaults/edge/certificates/other-site", new
        {
            parts = new object[] { new { kind = "pfx", content = Convert.ToBase64String(site.Pfx) }, new { kind = "pfx-password", text = "generated-wrong" } },
        });
        Assert.Equal(HttpStatusCode.BadRequest, wrongPassword.StatusCode);
        Assert.Contains("certificate.pfx.unreadable", await wrongPassword.Content.ReadAsStringAsync());
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync("/api/v1/vaults/edge/certificates/shop-site/parts/password")).StatusCode);
    }

    [Fact]
    public async Task Linking_deleting_everywhere_purging_and_retention_work_over_http()
    {
        await _admin.PutAsJsonAsync("/api/v1/vaults/app-a", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/app-b", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/app-a/secrets/token", new { value = "generated-one" });

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PostAsJsonAsync("/api/v1/vaults/app-a/secrets/token/link", new { vault = "app-b", name = "shared-token" })).StatusCode);
        Assert.Equal("[\"app-b/shared-token\"]", await _admin.GetStringAsync("/api/v1/vaults/app-a/secrets/token/links"));
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PostAsJsonAsync("/api/v1/vaults/app-a/secrets/token/copy", new { vault = "app-b", name = "token-copy" })).StatusCode);

        // The list is the confirmation: the wrong one deletes nothing.
        var wrong = await _admin.PostAsJsonAsync("/api/v1/vaults/app-a/secrets/token/delete-everywhere", new { expected = new[] { "app-a/token" } });
        Assert.Equal(HttpStatusCode.Conflict, wrong.StatusCode);
        Assert.Contains("secret.links.changed", await wrong.Content.ReadAsStringAsync());
        var right = await _admin.PostAsJsonAsync("/api/v1/vaults/app-a/secrets/token/delete-everywhere", new { expected = new[] { "app-a/token", "app-b/shared-token" } });
        Assert.Equal(HttpStatusCode.NoContent, right.StatusCode);

        var bins = await Json(await _admin.GetAsync("/api/v1/bin"));
        Assert.Equal(["app-a/token", "app-b/shared-token"], bins.EnumerateArray().Select(item => $"{item.GetProperty("vault").GetString()}/{item.GetProperty("name").GetString()}"));
        var first = bins[0].GetProperty("entryId").GetGuid();

        await _admin.PutAsJsonAsync("/api/v1/vaults/app-a/purge-protection", new { enabled = true });
        Assert.Equal(HttpStatusCode.Conflict, (await _admin.DeleteAsync($"/api/v1/vaults/app-a/bin/{first}")).StatusCode);
        await _admin.PutAsJsonAsync("/api/v1/vaults/app-a/purge-protection", new { enabled = false });
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.DeleteAsync($"/api/v1/vaults/app-a/bin/{first}")).StatusCode);

        Assert.Equal("{\"days\":null}", await _admin.GetStringAsync("/api/v1/settings/bin-retention"));
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/settings/bin-retention", new { days = 30 })).StatusCode);
        Assert.Equal("{\"days\":30}", await _admin.GetStringAsync("/api/v1/settings/bin-retention"));

        // The copy never was part of the link.
        Assert.Equal("generated-one", (await Json(await _admin.GetAsync("/api/v1/vaults/app-b/secrets/token-copy/value"))).GetProperty("value").GetString());
    }

    /// <summary>Makes every request to the test host arrive from one address, as a proxy's would.</summary>
    private sealed class ArrivesFrom(string address) : Microsoft.AspNetCore.Hosting.IStartupFilter
    {
        public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) => app =>
        {
            app.Use(following => context =>
            {
                context.Connection.RemoteIpAddress = IPAddress.Parse(address);
                return following(context);
            });
            next(app);
        };
    }

    [Fact]
    public void A_generated_value_has_its_length_its_kinds_of_character_and_nothing_a_file_or_a_shell_would_read_twice()
    {
        var made = Enumerable.Range(0, 200).Select(_ => SecretHive.Web.Components.Shared.PasswordGenerator.Make(32, withSymbols: true)).ToList();
        Assert.All(made, value =>
        {
            Assert.Equal(32, value.Length);
            Assert.Contains(value, char.IsAsciiLetter);
            Assert.Contains(value, char.IsAsciiDigit);
            Assert.Contains(value, character => SecretHive.Web.Components.Shared.PasswordGenerator.Symbols.Contains(character, StringComparison.Ordinal));
            Assert.DoesNotContain(value, character => "$\"'`\\# ".Contains(character, StringComparison.Ordinal));
        });
        Assert.Equal(made.Count, made.Distinct(StringComparer.Ordinal).Count());

        var plain = SecretHive.Web.Components.Shared.PasswordGenerator.Make(12, withSymbols: false);
        Assert.Equal(12, plain.Length);
        Assert.All(plain, character => Assert.True(char.IsAsciiLetterOrDigit(character)));
    }

    [Theory]
    [InlineData("https", true)]
    [InlineData("wss", true)]  // a WebSocket through Traefik: HTTPS, not a reason to redirect (it fell back to long polling)
    [InlineData("http", false)]
    [InlineData("ws", false)]
    public async Task A_trusted_proxys_scheme_counts_and_a_websockets_scheme_is_read_as_the_one_it_runs_on(string forwarded, bool https)
    {
        var directory = Directory.CreateTempSubdirectory("secrethive-scheme-").FullName;
        try
        {
            MasterKey.Create(Path.Combine(directory, "master.key"));
            File.WriteAllText(Path.Combine(directory, "admin.token"), Token);
            using var factory = Server(directory, builder =>
            {
                builder.UseSetting("SecretHive:Proxy:Trusted", "192.0.2.10");
                builder.ConfigureServices(services => services.Add(Microsoft.Extensions.DependencyInjection.ServiceDescriptor.Singleton<Microsoft.AspNetCore.Hosting.IStartupFilter>(new ArrivesFrom("192.0.2.10"))));
            });
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Add("X-Forwarded-Proto", forwarded);

            // The answer carries HSTS exactly when the request counts as HTTPS: the same test the redirect makes.
            var answer = await client.GetAsync("/health");
            Assert.Equal(https, answer.Headers.Contains("Strict-Transport-Security"));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Theory]
    [InlineData("192.0.2.10", "203.0.113.7")] // the named proxy is believed about the visitor
    [InlineData("192.0.2.99", "192.0.2.99")]  // anyone else is not: the header is ignored
    public async Task The_visitors_address_is_taken_from_a_configured_header_only_when_a_trusted_proxy_sends_it(string arrivesFrom, string recorded)
    {
        var directory = Directory.CreateTempSubdirectory("secrethive-proxy-").FullName;
        try
        {
            MasterKey.Create(Path.Combine(directory, "master.key"));
            File.WriteAllText(Path.Combine(directory, "admin.token"), Token);
            using var factory = Server(directory, builder =>
            {
                builder.UseSetting("SecretHive:Proxy:Trusted", "192.0.2.10");
                builder.UseSetting("SecretHive:Proxy:ClientAddressHeader", "CF-Connecting-IP");
                builder.ConfigureServices(services => services.Add(Microsoft.Extensions.DependencyInjection.ServiceDescriptor.Singleton<Microsoft.AspNetCore.Hosting.IStartupFilter>(new ArrivesFrom(arrivesFrom))));
            });
            using var client = factory.CreateClient();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            client.DefaultRequestHeaders.Add("CF-Connecting-IP", "203.0.113.7");
            client.DefaultRequestHeaders.Add("X-Forwarded-For", "198.51.100.1");

            Assert.Equal(HttpStatusCode.Created, (await client.PutAsJsonAsync("/api/v1/vaults/app-a", new { })).StatusCode);
            var audit = await Json(await client.GetAsync("/api/v1/audit"));
            Assert.Contains(audit.EnumerateArray(), row => row.GetProperty("code").GetString() == "vault.created" && row.GetProperty("address").GetString() == recorded);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Backups_are_made_listed_and_downloaded_by_the_bootstrap_token_and_health_reports_their_age()
    {
        Assert.Equal(JsonValueKind.Null, (await Json(await _factory.CreateClient().GetAsync("/health"))).GetProperty("backup").GetProperty("lastVerifiedUtc").ValueKind);
        await _admin.PutAsJsonAsync("/api/v1/vaults/app-a", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/app-a/secrets/token", new { value = "generated-one" });

        var made = await Json(await _admin.PostAsync("/api/v1/backups", null));
        var name = made.GetProperty("name").GetString()!;
        Assert.Matches(@"^secrethive-\d{8}-\d{6}\.shbak$", name);
        Assert.Equal(name, (await Json(await _admin.GetAsync("/api/v1/backups")))[0].GetProperty("name").GetString());

        var file = await _admin.GetByteArrayAsync("/api/v1/backups/" + name);
        Assert.Equal([0x1f, 0x8b], file[..2]); // gzip
        Assert.DoesNotContain("generated-one", System.Text.Encoding.Latin1.GetString(file));
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync("/api/v1/backups/secrethive-20000101-000000.shbak")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.GetAsync("/api/v1/backups/..%2Fmaster.key")).StatusCode);

        using var anonymous = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/backups")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsync("/api/v1/backups", null)).StatusCode);

        var health = (await Json(await anonymous.GetAsync("/health"))).GetProperty("backup");
        Assert.Equal(JsonValueKind.String, health.GetProperty("lastVerifiedUtc").ValueKind);
        Assert.InRange(health.GetProperty("ageHours").GetDouble(), 0, 1);
        var audit = await Json(await _admin.GetAsync("/api/v1/audit"));
        Assert.Contains(audit.EnumerateArray(), row => row.GetProperty("code").GetString() == "backup.created");
        Assert.Contains(audit.EnumerateArray(), row => row.GetProperty("code").GetString() == "backup.downloaded");
    }

    private static string Antiforgery(string html) =>
        System.Text.RegularExpressions.Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\"").Groups[1].Value;

    [Fact]
    public async Task People_sign_in_with_an_account_must_choose_a_password_first_and_a_session_cannot_change_things_through_the_api()
    {
        const string chosen = "generated-chosen-password";
        using var browser = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        // Not signed in: every page sends you to the sign-in form, which itself is open.
        var home = await browser.GetAsync("/");
        Assert.Equal(HttpStatusCode.Redirect, home.StatusCode);
        Assert.StartsWith("/login", home.Headers.Location!.PathAndQuery);
        var form = await browser.GetAsync("/login");
        Assert.Equal(HttpStatusCode.OK, form.StatusCode);

        async Task<HttpResponseMessage> Post(string path, string handler, params (string Name, string Value)[] fields)
        {
            var page = await (await browser.GetAsync(path)).Content.ReadAsStringAsync();
            var values = fields.ToDictionary(field => field.Name, field => field.Value);
            values["_handler"] = handler;
            values["__RequestVerificationToken"] = Antiforgery(page);
            return await browser.PostAsync(path, new FormUrlEncodedContent(values));
        }

        // The bootstrap token no longer signs anyone in by itself, a known default does not exist, and a wrong
        // password says no more than "does not match".
        var refused = await Post("/login", "signin", ("UserName", "admin"), ("Password", "admin"));
        Assert.Equal(HttpStatusCode.OK, refused.StatusCode);
        Assert.Contains("do not match an account", await refused.Content.ReadAsStringAsync());

        // The first administrator: the bootstrap token is its first password, and it has to be replaced.
        var accepted = await Post("/login", "signin", ("UserName", "admin"), ("Password", Token));
        Assert.Equal(HttpStatusCode.Redirect, accepted.StatusCode);
        Assert.Equal("/account/password", accepted.Headers.Location.Path());
        var cookie = accepted.Headers.GetValues("Set-Cookie").Single(value => value.StartsWith("secrethive=", StringComparison.Ordinal));
        Assert.Contains("httponly", cookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);

        // Until it is, nothing else opens: not a page, not the API.
        var blocked = await browser.GetAsync("/");
        Assert.Equal("/account/password", blocked.Headers.Location.Path());
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync("/api/v1/backups/secrethive-20260101-000000.shbak")).StatusCode); // an extension does not make it a stylesheet

        var tooShort = await Post("/account/password", "password", ("Current", Token), ("New", "short"), ("Again", "short"));
        Assert.Contains("at least 12 characters", await tooShort.Content.ReadAsStringAsync());
        var changed = await Post("/account/password", "password", ("Current", Token), ("New", chosen), ("Again", chosen));
        Assert.Equal(HttpStatusCode.Redirect, changed.StatusCode);
        Assert.Equal("/", changed.Headers.Location.Path());

        // Signed in: the pages open, the API can be read, and nothing can be changed through it with a cookie.
        var opened = await browser.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, opened.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await browser.PutAsJsonAsync("/api/v1/vaults/from-a-browser", new { })).StatusCode);
        Assert.DoesNotContain("from-a-browser", await _admin.GetStringAsync("/api/v1/vaults"));

        // The trail has the sign-ins, by name, and neither password.
        var audit = await _admin.GetStringAsync("/api/v1/audit");
        Assert.Contains("auth.signin.failed", audit);
        Assert.Contains("\"code\":\"auth.signin\"", audit);
        Assert.Contains("auth.password.changed", audit);
        Assert.DoesNotContain(chosen, audit);
        Assert.DoesNotContain(Token, audit);

        // The keys that sign that cookie are on disk only in encrypted form, tied to the master key.
        var keys = Directory.GetFiles(Path.Combine(_directory, "session-keys"), "*.xml");
        Assert.NotEmpty(keys);
        Assert.All(keys, key =>
        {
            var xml = File.ReadAllText(key);
            Assert.Contains("<encryptedKey masterKeyId=", xml);
            Assert.DoesNotContain("<masterKey", xml);
        });

        // Sign-out is a POST with the page's token: a plain request to it does nothing.
        Assert.Contains((await browser.GetAsync("/logout")).StatusCode, new[] { HttpStatusCode.MethodNotAllowed, HttpStatusCode.NotFound });
        var out1 = await browser.PostAsync("/logout", new FormUrlEncodedContent(new Dictionary<string, string>()));
        Assert.Equal(HttpStatusCode.Redirect, out1.StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/")).StatusCode);
    }

    [Fact]
    public async Task A_new_version_through_the_api_keeps_what_it_does_not_name()
    {
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new
        {
            value = "generated-one",
            description = "generated-description",
            fields = new object[] { new { name = "owner", value = "operations" }, new { name = "url", value = "https://example.test/", type = "Url" }, new { name = "pin", value = "generated-pin", sensitive = true } },
        });

        async Task<JsonElement> Listed() => (await Json(await _admin.GetAsync("/api/v1/vaults/shop/secrets")))[0];
        async Task<string?> Read(string what) => (await Json(await _admin.GetAsync($"/api/v1/vaults/shop/secrets/token/{what}"))).GetProperty("value").GetString();

        // Only a value: everything else stays, the sensitive field without anyone reading it.
        Assert.Equal(2, (await Json(await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-two" }))).GetProperty("version").GetInt32());
        var listed = await Listed();
        Assert.Equal(("generated-description", "operations", "https://example.test/", "pin"), (listed.GetProperty("description").GetString(), listed.GetProperty("fields").GetProperty("owner").GetString(), listed.GetProperty("fields").GetProperty("url").GetString(), listed.GetProperty("sensitiveFields")[0].GetString()));
        Assert.Equal(("generated-two", "generated-pin"), (await Read("value"), await Read("fields/pin")));

        // One field named: that one changes. One sent empty: that one goes. A new sensitive one joins the old.
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new
        {
            value = "generated-three",
            fields = new object[] { new { name = "owner", value = "developers" }, new { name = "url", value = "", type = "Url" }, new { name = "code", value = "generated-code", sensitive = true } },
        });
        listed = await Listed();
        Assert.Equal("developers", listed.GetProperty("fields").GetProperty("owner").GetString());
        Assert.False(listed.GetProperty("fields").TryGetProperty("url", out _));
        Assert.Equal(["code", "pin"], listed.GetProperty("sensitiveFields").EnumerateArray().Select(field => field.GetString()));
        Assert.Equal("generated-description", listed.GetProperty("description").GetString());
        Assert.Equal(("generated-pin", "generated-code"), (await Read("fields/pin"), await Read("fields/code")));

        // A sensitive field sent empty is taken away too.
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-four", fields = new object[] { new { name = "pin", value = "", sensitive = true } } });
        Assert.Equal(["code"], (await Listed()).GetProperty("sensitiveFields").EnumerateArray().Select(field => field.GetString()));

        // Asked to replace: the new version is exactly what was sent.
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-five", replaceDetails = true });
        listed = await Listed();
        Assert.Equal(0, listed.GetProperty("sensitiveFields").GetArrayLength());
        Assert.Empty(listed.GetProperty("fields").EnumerateObject());
        Assert.Equal(JsonValueKind.Null, listed.GetProperty("description").ValueKind);

        // Carrying a sensitive field over is not a read: only the reads asked for above are on record.
        var audit = await _admin.GetStringAsync("/api/v1/audit?take=100");
        Assert.Equal(4, System.Text.RegularExpressions.Regex.Count(audit, "secret.value.read"));

        // Found across vaults over the API, with the words in the body.
        var found = await Json(await _admin.PostAsJsonAsync("/api/v1/search", new { query = "shop tok" }));
        Assert.Equal("token", Assert.Single(found.EnumerateArray()).GetProperty("name").GetString());
        Assert.Equal(0, (await Json(await _admin.PostAsJsonAsync("/api/v1/search", new { query = "generated-five" }))).GetArrayLength());

        // And the server says which release it is, to whoever is signed in.
        Assert.True((await Json(await _admin.GetAsync("/api/v1/server"))).TryGetProperty("version", out _));
        using var anonymous = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/server")).StatusCode);
    }

    [Fact]
    public async Task How_a_request_arrived_is_taken_from_its_sign_in_and_not_from_a_header()
    {
        _admin.DefaultRequestHeaders.Add("X-SecretHive-Via", "ui");
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { })).StatusCode);
        var row = (await Json(await _admin.GetAsync("/api/v1/audit?take=1")))[0];
        Assert.Equal(("vault.created", "api"), (row.GetProperty("code").GetString(), row.GetProperty("via").GetString()));
    }

    [Fact]
    public void A_redirect_to_https_only_goes_to_a_name_the_server_answers_for()
    {
        var hosts = new SecretHive.Web.Security.KnownHosts(["vault.lan", "192.0.2.10"], "https://vault.example.org", "box");
        Assert.True(hosts.Covers("vault.lan"));
        Assert.True(hosts.Covers("VAULT.EXAMPLE.ORG"));
        Assert.True(hosts.Covers("192.0.2.10"));
        Assert.True(hosts.Covers("localhost"));
        Assert.False(hosts.Covers("box"));
        Assert.False(hosts.Covers("evil.example"));
        Assert.False(hosts.Covers(null));

        // With no name configured the certificate is for the machine's own name, and so is the redirect.
        var unnamed = new SecretHive.Web.Security.KnownHosts([], null, "box");
        Assert.True(unnamed.Covers("box"));
        Assert.False(unnamed.Covers("vault.lan"));
    }

    [Fact]
    public async Task The_bootstrap_token_can_be_taken_away_once_a_super_admin_has_a_password_of_their_own()
    {
        var directory = Directory.CreateTempSubdirectory("secrethive-no-token-").FullName;
        MasterKey.Create(Path.Combine(directory, "master.key"));
        File.WriteAllText(Path.Combine(directory, "admin.token"), Token);

        // First start, with the token: the first administrator exists, with the token as a password to replace.
        using (var first = Server(directory))
        using (var client = first.CreateClient())
        {
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            Assert.Equal(HttpStatusCode.Created, (await client.PutAsJsonAsync("/api/v1/vaults/shop", new { })).StatusCode);
        }

        // Taken away too early, nobody could get in: the administrator's only password is the token itself.
        File.Delete(Path.Combine(directory, "admin.token"));
        using (var tooEarly = Server(directory))
        {
            Assert.Contains("no super admin who can sign in", Assert.ThrowsAny<Exception>(() => tooEarly.CreateClient()).ToString(), StringComparison.Ordinal);
        }

        // With a password of their own, the server runs without the token, and the token opens nothing.
        File.WriteAllText(Path.Combine(directory, "admin.token"), Token);
        using (var second = Server(directory))
        {
            using var _ = second.CreateClient();
            await using var scope = second.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<SecretHive.Application.Ports.IUserStore>();
            var admin = (await users.FindByUserNameAsync("admin", default))!;
            Assert.Equal(SecretHive.Application.Accounts.AccountOutcome.Done, await scope.ServiceProvider.GetRequiredService<SecretHive.Application.Accounts.AccountService>().ChangeOwnPasswordAsync(admin.Key, Token, "generated-chosen-password", default));
        }

        File.Delete(Path.Combine(directory, "admin.token"));
        using (var third = Server(directory))
        using (var client = third.CreateClient())
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health")).StatusCode);
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/vaults")).StatusCode);
            Assert.False(third.Services.GetRequiredService<SecretHive.Web.Security.ServerInfo>().BootstrapToken);
        }

        Directory.Delete(directory, recursive: true);
    }

    [Fact]
    public void The_server_does_not_start_without_a_master_key_or_with_a_weak_sign_in()
    {
        var noKey = Directory.CreateTempSubdirectory("secrethive-api-").FullName;
        File.WriteAllText(Path.Combine(noKey, "admin.token"), Token);
        var weakToken = Directory.CreateTempSubdirectory("secrethive-api-").FullName;
        MasterKey.Create(Path.Combine(weakToken, "master.key"));
        File.WriteAllText(Path.Combine(weakToken, "admin.token"), "short\n");

        using var first = Server(noKey);
        using var second = Server(weakToken);

        Assert.Contains("master key", Assert.ThrowsAny<Exception>(() => first.CreateClient()).ToString(), StringComparison.OrdinalIgnoreCase);
        Assert.Contains("at least 32 characters", Assert.ThrowsAny<Exception>(() => second.CreateClient()).ToString(), StringComparison.Ordinal);
        Directory.Delete(noKey, recursive: true);
        Directory.Delete(weakToken, recursive: true);
    }

    public void Dispose()
    {
        _admin.Dispose();
        _factory.Dispose();
        Directory.Delete(_directory, recursive: true);
    }
}
