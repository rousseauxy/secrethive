using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Unit.Tests;

/// <summary>
/// A job signing in with the token its platform gave it, against <see cref="FakeOidcProvider"/> as that platform:
/// a real signature, checked against keys fetched from the issuer. The shape used is a CI system's: the token names
/// the repository, and a group here is linked to each repository that may read.
/// </summary>
public sealed class ProviderTokenTests : IAsyncLifetime
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";
    private const string Audience = "https://secrethive.example.test";
    private static readonly Caller Root = Caller.System("test");

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-tokens-").FullName;
    private WebApplicationFactory<SecretHive.Web.ServerMarker> _factory = null!;
    private FakeOidcProvider _ci = null!;
    private HttpClient _admin = null!;

    public async ValueTask InitializeAsync()
    {
        _ci = await FakeOidcProvider.StartAsync();
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
            builder.UseSetting("Logging:LogLevel:Default", "Error");
        });
        _admin = _factory.CreateClient();
        _admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);

        await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/billing", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/deploy-token", new { value = "generated-shop-value" });
        await _admin.PutAsJsonAsync("/api/v1/vaults/billing/secrets/deploy-token", new { value = "generated-billing-value" });

        // The CI system: trusted for tokens only (nobody signs in with it), tokens must be for this server and come
        // from the organisation's own repositories; the repository is what a token is matched to groups by.
        var made = await _admin.PutAsJsonAsync("/api/v1/providers/ci", new
        {
            displayName = "CI",
            authority = _ci.Authority,
            enabled = false,
            groupsClaim = "repository",
            acceptApiTokens = true,
            apiAudiences = new[] { Audience },
            apiRequiredClaims = new[] { "repository_owner=acme" },
        });
        Assert.Equal(HttpStatusCode.Created, made.StatusCode);

        // The group "shop-deployers" reads values in the shop vault; the repository acme/shop is in it.
        // Set up the way a script would: the group, the link to the repository, the role. Each call again changes nothing.
        foreach (var attempt in new[] { HttpStatusCode.Created, HttpStatusCode.OK })
        {
            Assert.Equal(attempt, (await _admin.PutAsJsonAsync("/api/v1/groups/shop-deployers", new { description = "may deploy the shop" })).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/groups/shop-deployers/provider-links", new { provider = "ci", group = "acme/shop" })).StatusCode);
        }

        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/groups/shop-deployers/provider-links", new { provider = "no-such-provider", group = "acme/shop" })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await _admin.PutAsJsonAsync("/api/v1/groups/no-such-group/provider-links", new { provider = "ci", group = "acme/shop" })).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop/access", new { group = "shop-deployers", role = "SecretsUser" })).StatusCode);
    }

    public async ValueTask DisposeAsync()
    {
        _admin.Dispose();
        await _ci.DisposeAsync();
        await _factory.DisposeAsync();
        Directory.Delete(_directory, recursive: true);
    }

    private static Dictionary<string, object> Job(string repository = "acme/shop", string owner = "acme") => new()
    {
        ["sub"] = $"repo:{repository}:ref:refs/heads/main",
        ["repository"] = repository,
        ["repository_owner"] = owner,
        ["ref"] = "refs/heads/main",
    };

    private HttpClient With(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private async Task<List<AuditEvent>> Audit(string code)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Audit.Where(row => row.Code == code).OrderBy(row => row.Id).ToListAsync();
    }

    [Fact]
    public async Task A_job_reads_what_its_repository_was_given_with_no_key_stored_for_it_and_under_its_own_name()
    {
        using var job = With(_ci.CreateAccessToken(Audience, Job()));

        Assert.Equal("generated-shop-value", JsonDocument.Parse(await job.GetStringAsync("/api/v1/vaults/shop/secrets/deploy-token/value")).RootElement.GetProperty("value").GetString());
        var read = Assert.Single(await Audit("secret.value.read"));
        Assert.Equal(("ci:repo:acme/shop:ref:refs/heads/main", "shop", "deploy-token", "api"), (read.Principal, read.Vault, read.Secret, read.Via));

        // It sees the one vault its group has a role in; the other does not exist for it.
        Assert.Equal(["shop"], JsonDocument.Parse(await job.GetStringAsync("/api/v1/vaults")).RootElement.EnumerateArray().Select(vault => vault.GetProperty("name").GetString()));
        Assert.Equal(HttpStatusCode.NotFound, (await job.GetAsync("/api/v1/vaults/billing/secrets/deploy-token/value")).StatusCode);

        // The group reads values; it does not change them, and a token is never an administrator of anything.
        Assert.Equal(HttpStatusCode.Forbidden, (await job.PutAsJsonAsync("/api/v1/vaults/shop/secrets/deploy-token", new { value = "generated-x" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await job.PutAsJsonAsync("/api/v1/vaults/mine", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await job.GetAsync("/api/v1/providers")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await job.PutAsJsonAsync("/api/v1/service-identities/sneaky", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await job.GetAsync("/api/v1/audit")).StatusCode);

        // Another repository of the same organisation is a valid sign-in that was given nothing.
        using var other = With(_ci.CreateAccessToken(Audience, Job("acme/website")));
        Assert.Equal("[]", await other.GetStringAsync("/api/v1/vaults"));
        Assert.Equal(HttpStatusCode.NotFound, (await other.GetAsync("/api/v1/vaults/shop/secrets/deploy-token/value")).StatusCode);

        // Taking the repository's group out of the vault ends it at the next request: nothing was handed out to revoke.
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            var group = (await scope.ServiceProvider.GetRequiredService<IAccessStore>().ListGroupsAsync(default)).Single().Key;
            await scope.ServiceProvider.GetRequiredService<SecretService>().UnassignAsync("shop", null, group, Root);
        }

        Assert.Equal(HttpStatusCode.NotFound, (await job.GetAsync("/api/v1/vaults/shop/secrets/deploy-token/value")).StatusCode);
    }

    [Fact]
    public async Task A_token_that_is_not_exactly_what_was_trusted_is_refused_and_the_refusal_is_on_record()
    {
        var cases = new (string Why, string Token)[]
        {
            ("wrong audience", _ci.CreateAccessToken("https://another-service.example.test", Job())),
            ("required claim repository_owner missing or different", _ci.CreateAccessToken(Audience, Job("mallory/shop", "mallory"))),
            ("expired", _ci.CreateAccessToken(Audience, Job(), expires: DateTime.UtcNow.AddMinutes(-10), notBefore: DateTime.UtcNow.AddMinutes(-40), issuedAt: DateTime.UtcNow.AddMinutes(-40))),
            ("valid for longer than a day", _ci.CreateAccessToken(Audience, Job(), lifetime: TimeSpan.FromDays(30))),
            ("invalid signature", _ci.CreateAccessToken(Audience, Job(), key: FakeOidcProvider.ForgedKey())),
            ("issuer not trusted for API tokens", _ci.CreateAccessToken(Audience, Job(), issuer: "https://somewhere-else.example.test")),
            ("an ID token, not an access token", _ci.CreateAccessToken(Audience, new Dictionary<string, object>(Job()) { ["nonce"] = "abc" })),
            ("no expiry", _ci.CreateAccessToken(Audience, Job(), noExpiry: true)),
        };

        foreach (var (why, token) in cases)
        {
            using var client = With(token);
            Assert.True(HttpStatusCode.Unauthorized == (await client.GetAsync("/api/v1/vaults/shop/secrets/deploy-token/value")).StatusCode, why);
            var refused = (await Audit("token.refused")).Last();
            Assert.Equal((AuditSeverity.Security, why), (refused.Severity, refused.Detail));
            Assert.DoesNotContain(token, refused.Detail + refused.Principal, StringComparison.Ordinal);
        }

        // An unsigned token, and one signed with a shared secret, never get as far as an issuer.
        using var unsigned = With("eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ4In0.e30");
        Assert.Equal(HttpStatusCode.Unauthorized, (await unsigned.GetAsync("/api/v1/vaults")).StatusCode);
        Assert.Empty(await Audit("secret.value.read"));

        // Switched off for the provider: the same good token is no credential any more, with no restart.
        var good = _ci.CreateAccessToken(Audience, Job());
        using (var client = With(good))
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/v1/vaults")).StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/providers/ci", new { displayName = "CI", authority = _ci.Authority, clientId = "unused", enabled = false, groupsClaim = "repository", acceptApiTokens = false })).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/v1/vaults")).StatusCode);
        }
    }

    [Fact]
    public async Task A_second_provider_on_the_same_issuer_lets_one_repository_read_from_its_release_tags_only()
    {
        // The first provider takes main only. A second one for the same issuer takes release tags, and only the
        // repository linked at it gets anything from a tag: another repository's tag is a token without a group.
        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/providers/ci", new { displayName = "CI", authority = _ci.Authority, enabled = false, groupsClaim = "repository", acceptApiTokens = true, apiAudiences = new[] { Audience }, apiRequiredClaims = new[] { "repository_owner=acme", "ref=refs/heads/main" } })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/providers/ci-tags", new { displayName = "CI tags", authority = _ci.Authority, enabled = false, groupsClaim = "repository", acceptApiTokens = true, apiAudiences = new[] { Audience }, apiRequiredClaims = new[] { "repository_owner=acme", "ref=refs/tags/docker-*" } })).StatusCode);

        Dictionary<string, object> Tagged(string repository, string tag) => new(Job(repository)) { ["ref"] = "refs/tags/" + tag, ["sub"] = $"repo:{repository}:ref:refs/tags/{tag}" };
        const string Value = "/api/v1/vaults/shop/secrets/deploy-token/value";

        // Not linked at the second provider yet: the tag is accepted as a token and opens nothing.
        using (var tag = With(_ci.CreateAccessToken(Audience, Tagged("acme/shop", "docker-1.2.3"))))
        {
            Assert.Equal(HttpStatusCode.NotFound, (await tag.GetAsync(Value)).StatusCode);
        }

        Assert.Equal(HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/groups/shop-deployers/provider-links", new { provider = "ci-tags", group = "acme/shop" })).StatusCode);
        using (var tag = With(_ci.CreateAccessToken(Audience, Tagged("acme/shop", "docker-1.2.3"))))
        using (var main = With(_ci.CreateAccessToken(Audience, Job())))
        using (var otherTag = With(_ci.CreateAccessToken(Audience, Tagged("acme/shop", "nightly-7"))))
        using (var otherRepository = With(_ci.CreateAccessToken(Audience, Tagged("acme/website", "docker-1"))))
        {
            Assert.Equal(HttpStatusCode.OK, (await tag.GetAsync(Value)).StatusCode);
            Assert.Equal(HttpStatusCode.OK, (await main.GetAsync(Value)).StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, (await otherTag.GetAsync(Value)).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await otherRepository.GetAsync(Value)).StatusCode);
        }

        // A star that is not at the end, or one on its own, is refused before it is stored.
        foreach (var rule in new[] { "ref=*", "ref=refs/*/docker", "ref=refs/tags/*-docker-*" })
        {
            Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PutAsJsonAsync("/api/v1/providers/ci-tags", new { displayName = "CI tags", authority = _ci.Authority, enabled = false, groupsClaim = "repository", acceptApiTokens = true, apiAudiences = new[] { Audience }, apiRequiredClaims = new[] { rule } })).StatusCode);
        }
    }

    [Fact]
    public async Task A_provider_trusted_for_tokens_must_say_for_whom_and_needs_no_client()
    {
        // No audience: any token this issuer signs for anything would do.
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PutAsJsonAsync("/api/v1/providers/open", new { authority = _ci.Authority, enabled = false, acceptApiTokens = true })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PutAsJsonAsync("/api/v1/providers/typo", new { authority = _ci.Authority, enabled = false, acceptApiTokens = true, apiAudiences = new[] { Audience }, apiRequiredClaims = new[] { "ref_protected" } })).StatusCode);

        // Neither people nor tokens: there would be nothing it is for.
        Assert.Equal(HttpStatusCode.BadRequest, (await _admin.PutAsJsonAsync("/api/v1/providers/idle", new { authority = _ci.Authority, enabled = false })).StatusCode);

        var listed = JsonDocument.Parse(await _admin.GetStringAsync("/api/v1/providers")).RootElement.EnumerateArray().Single();
        Assert.Equal((true, false, Audience, "repository_owner=acme"), (
            listed.GetProperty("acceptApiTokens").GetBoolean(),
            listed.GetProperty("enabled").GetBoolean(),
            listed.GetProperty("apiAudiences")[0].GetString(),
            listed.GetProperty("apiRequiredClaims")[0].GetString()));

        // It is not offered to people on the sign-in page.
        Assert.DoesNotContain("Sign in with CI", await _factory.CreateClient().GetStringAsync("/login"), StringComparison.Ordinal);
        var created = Assert.Single(await Audit("provider.created"));
        Assert.Contains("apiTokens=True audiences=" + Audience, created.Detail, StringComparison.Ordinal);
    }
}
