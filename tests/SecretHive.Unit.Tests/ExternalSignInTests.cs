using System.Net;
using System.Net.Http.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;

namespace SecretHive.Unit.Tests;

/// <summary>
/// Signing in through an OpenID Connect provider, end to end through a real code flow against
/// <see cref="FakeOidcProvider"/>: the sign-in page, the server's handler, the provider's token and user info
/// answers, and the account decisions after them. A provider says who someone is; these tests are mostly about
/// everything it must not be able to decide.
/// </summary>
public sealed partial class ExternalSignInTests : IAsyncLifetime
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";
    private const string Password = "generated-password-123";
    private static readonly Caller Root = Caller.System("test");

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-oidc-").FullName;
    private WebApplicationFactory<SecretHive.Web.ServerMarker> _factory = null!;
    private FakeOidcProvider _idp = null!;

    public async ValueTask InitializeAsync()
    {
        _idp = await FakeOidcProvider.StartAsync();
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
        _ = _factory.Server;
    }

    public async ValueTask DisposeAsync()
    {
        await _idp.DisposeAsync();
        await _factory.DisposeAsync();
        Directory.Delete(_directory, recursive: true);
    }

    private async Task<T> With<TService, T>(Func<TService, Task<T>> act)
        where TService : notnull
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        return await act(scope.ServiceProvider.GetRequiredService<TService>());
    }

    private Task<int> AddProviderAsync(string slug = "idp", bool createAccounts = true, string groupsClaim = "", string domains = "") =>
        With<ProviderService, int>(service => service.CreateAsync(
            new ProviderSettings("Test provider", slug, _idp.Authority, FakeOidcProvider.ClientId, FakeOidcProvider.ClientSecret, GroupsClaim: groupsClaim, CreateAccounts: createAccounts, AllowedEmailDomains: domains),
            Root));

    private async Task<User> LocalUserAsync(string name, string email = "")
    {
        await With<IUserStore, bool>(async users => await users.AddAsync(
            new User
            {
                UserName = name,
                UserNameLower = name,
                Email = email,
                Role = UserRole.User,
                PasswordHash = _factory.Services.GetRequiredService<IPasswordHasher>().Hash(Password),
                SecurityStamp = AccountService.NewStamp(),
                CreatedUtc = DateTime.UtcNow,
            },
            default));
        return (await FindUserAsync(name))!;
    }

    private Task<User?> FindUserAsync(string name) => With<IUserStore, User?>(users => users.FindByUserNameAsync(name, default));

    private async Task<IReadOnlyList<AuditEvent>> AuditAsync()
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<SecretHiveDbContext>().Audit.AsNoTracking().OrderBy(row => row.AtUtc).ToListAsync();
    }

    private HttpClient Browser() => _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    private static async Task<HttpResponseMessage> PostFormAsync(HttpClient browser, string page, string action, params (string Name, string Value)[] fields)
    {
        var html = await (await browser.GetAsync(page)).Content.ReadAsStringAsync();
        var values = fields.ToDictionary(field => field.Name, field => field.Value);
        values["__RequestVerificationToken"] = WebUtility.HtmlDecode(AntiforgeryField().Match(html).Groups[1].Value);
        return await browser.PostAsync(action, new FormUrlEncodedContent(values));
    }

    private static async Task<HttpClient> SignInLocallyAsync(HttpClient browser, string user)
    {
        var answer = await PostFormAsync(browser, "/login", "/login", ("_handler", "signin"), ("UserName", user), ("Password", Password));
        Assert.Equal(HttpStatusCode.Redirect, answer.StatusCode);
        return browser;
    }

    /// <summary>
    /// What a browser does after a provider button: to the provider, back to the callback, through the page that
    /// ends the cross-site chain, and on to the decision. Returns the answer of that last step.
    /// </summary>
    private static async Task<HttpResponseMessage> ThroughProviderAsync(HttpClient browser, HttpResponseMessage challenge)
    {
        Assert.Equal(HttpStatusCode.Redirect, challenge.StatusCode);
        using var outside = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false });
        var atProvider = await outside.GetAsync(challenge.Headers.Location);
        Assert.Equal(HttpStatusCode.Redirect, atProvider.StatusCode);
        Assert.StartsWith("/signin-oidc/", atProvider.Headers.Location!.AbsolutePath, StringComparison.Ordinal);

        var callback = await browser.GetAsync(atProvider.Headers.Location.PathAndQuery);
        Assert.Equal(HttpStatusCode.Redirect, callback.StatusCode);
        if (callback.Headers.Location!.OriginalString != "/account/external/return")
        {
            return callback;
        }

        // Not a redirect: a page of this site that asks for the next one, so a strictly same-site session cookie travels again.
        var bounce = await browser.GetAsync("/account/external/return");
        Assert.Equal(HttpStatusCode.OK, bounce.StatusCode);
        Assert.Contains("http-equiv=\"refresh\" content=\"0;url=/account/external/complete\"", await bounce.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        return await browser.GetAsync("/account/external/complete");
    }

    private static async Task<HttpResponseMessage> ProviderSignInAsync(HttpClient browser, string slug = "idp") =>
        await ThroughProviderAsync(browser, await PostFormAsync(browser, "/login", $"/account/external/{slug}"));

    private static async Task<HttpResponseMessage> ProviderLinkAsync(HttpClient browser, string slug = "idp") =>
        await ThroughProviderAsync(browser, await PostFormAsync(browser, "/login", $"/account/external/{slug}/link"));

    private static string Where(HttpResponseMessage response) => response.Headers.Location!.OriginalString;

    [Fact]
    public async Task A_first_sign_in_makes_an_account_that_holds_nothing_and_the_next_one_returns_to_it()
    {
        await AddProviderAsync();
        await With<SecretService, bool>(async service =>
        {
            await service.CreateVaultAsync("shop", null, Root);
            return true;
        });
        _idp.Next = new FakeIdentity("sub-1", "newcomer", "newcomer@example.org", "New Comer");

        using (var browser = Browser())
        {
            Assert.Contains("Sign in with Test provider", await browser.GetStringAsync("/login"), StringComparison.Ordinal);
            var done = await ProviderSignInAsync(browser);
            Assert.Equal("/", Where(done));
            var cookie = done.Headers.GetValues("Set-Cookie").Single(value => value.StartsWith("secrethive=", StringComparison.Ordinal));
            Assert.Contains("samesite=strict", cookie, StringComparison.OrdinalIgnoreCase);
            Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/")).StatusCode);

            // A session it is, and one that sees no vault: a provider gives an identity, never a role.
            Assert.Equal("[]", await browser.GetStringAsync("/api/v1/vaults"));
        }

        var user = await FindUserAsync("newcomer");
        Assert.NotNull(user);
        Assert.Equal((UserRole.User, null, "New Comer", false), (user.Role, user.PasswordHash, user.DisplayName, user.MustChangePassword));

        using (var again = Browser())
        {
            Assert.Equal("/", Where(await ProviderSignInAsync(again)));
        }

        Assert.Single(await With<IUserStore, IReadOnlyList<User>>(users => users.ListAsync(default)), candidate => candidate.UserName.StartsWith("newcomer", StringComparison.Ordinal));
        var audit = await AuditAsync();
        Assert.Contains(audit, row => row.Code == "auth.external.created" && row.Principal == "newcomer" && row.Detail == "provider=idp");
        Assert.Contains(audit, row => row.Code == "auth.signin" && row.Principal == "newcomer" && row.Detail == "provider=idp");
    }

    [Fact]
    public async Task An_identity_is_never_matched_to_an_existing_account_by_name_or_email()
    {
        await AddProviderAsync();
        await LocalUserAsync("alice", "Alice@Example.org");

        foreach (var identity in new[] { new FakeIdentity("sub-a", "ALICE"), new FakeIdentity("sub-b", "someone-else", "alice@example.org") })
        {
            _idp.Next = identity;
            using var browser = Browser();
            Assert.Equal("/login?external=exists", Where(await ProviderSignInAsync(browser)));
            Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync("/")).StatusCode);
        }

        Assert.Null(await FindUserAsync("someone-else"));
        var alice = (await FindUserAsync("alice"))!;
        Assert.Empty(await With<IExternalLoginStore, IReadOnlyList<ExternalLogin>>(logins => logins.ListForUserAsync(alice.Key, default)));
        Assert.Contains(await AuditAsync(), row => row.Code == "auth.external.refused" && row.Detail!.Contains("matches-existing-account", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_provider_that_makes_no_accounts_only_lets_in_who_connected_it_from_their_profile()
    {
        await AddProviderAsync(createAccounts: false);
        var bob = await LocalUserAsync("bob");
        _idp.Next = new FakeIdentity("sub-bob", "bob.at.provider", "bob@example.org");

        using (var stranger = Browser())
        {
            Assert.Equal("/login?external=no-account", Where(await ProviderSignInAsync(stranger)));
        }

        Assert.Null(await FindUserAsync("bob.at.provider"));

        // Bob, signed in with his password, connects the provider. From then on it leads to his account.
        using (var browser = await SignInLocallyAsync(Browser(), "bob"))
        {
            Assert.Equal("/account/profile?linked=ok", Where(await ProviderLinkAsync(browser)));
            Assert.Equal("/account/profile?linked=already", Where(await ProviderLinkAsync(browser)));
        }

        using (var browser = Browser())
        {
            Assert.Equal("/", Where(await ProviderSignInAsync(browser)));
            Assert.Equal(HttpStatusCode.OK, (await browser.GetAsync("/")).StatusCode);
        }

        // The same identity cannot also be connected to somebody else's account.
        await LocalUserAsync("carol");
        using (var browser = await SignInLocallyAsync(Browser(), "carol"))
        {
            Assert.Equal("/account/profile?linked=taken", Where(await ProviderLinkAsync(browser)));
        }

        // Connecting needs a session: without one the request goes nowhere near the provider.
        using (var anonymous = Browser())
        {
            var refused = await PostFormAsync(anonymous, "/login", "/account/external/idp/link");
            Assert.StartsWith("/login", refused.Headers.Location!.PathAndQuery, StringComparison.Ordinal);
        }

        // Bob disconnects it; he has a password, so that is allowed, and the provider no longer leads anywhere.
        var login = Assert.Single(await With<IExternalLoginStore, IReadOnlyList<ExternalLogin>>(logins => logins.ListForUserAsync(bob.Key, default)));
        using (var browser = await SignInLocallyAsync(Browser(), "bob"))
        {
            Assert.Equal("/account/profile?unlinked=ok", Where(await PostFormAsync(browser, "/login", $"/account/external/logins/{login.Key}/remove")));
        }

        using (var browser = Browser())
        {
            Assert.Equal("/login?external=no-account", Where(await ProviderSignInAsync(browser)));
        }

        var audit = await AuditAsync();
        Assert.Contains(audit, row => row.Code == "auth.external.linked" && row.Principal == "bob" && row.Detail == "provider=idp status=Linked");
        Assert.Contains(audit, row => row.Code == "auth.external.unlinked" && row.Principal == "bob");
    }

    [Fact]
    public async Task An_account_with_no_password_cannot_remove_its_only_way_in()
    {
        await AddProviderAsync();
        _idp.Next = new FakeIdentity("sub-only", "only-provider");
        using var browser = Browser();
        Assert.Equal("/", Where(await ProviderSignInAsync(browser)));

        var user = (await FindUserAsync("only-provider"))!;
        var login = Assert.Single(await With<IExternalLoginStore, IReadOnlyList<ExternalLogin>>(logins => logins.ListForUserAsync(user.Key, default)));
        Assert.Equal("/account/profile?unlinked=last", Where(await PostFormAsync(browser, "/login", $"/account/external/logins/{login.Key}/remove")));
        Assert.Single(await With<IExternalLoginStore, IReadOnlyList<ExternalLogin>>(logins => logins.ListForUserAsync(user.Key, default)));
    }

    [Fact]
    public async Task Groups_at_the_provider_give_membership_of_linked_groups_and_through_them_a_role_until_they_are_left()
    {
        var provider = await AddProviderAsync(groupsClaim: "groups");
        await With<SecretService, bool>(async service =>
        {
            await service.CreateVaultAsync("shop", null, Root);
            await service.SetAsync(new SetSecret("shop", "token", "generated-shop-value"u8.ToArray()), Root);
            return true;
        });
        await With<GroupService, bool>(async groups =>
        {
            await groups.CreateAsync("shop-team", null, Root);
            await groups.CreateAsync("by-hand", null, Root);
            return true;
        });
        var all = await With<IAccessStore, IReadOnlyList<SecretHive.Domain.Entities.Group>>(access => access.ListGroupsAsync(default));
        var (team, byHand) = (all.Single(group => group.Name == "shop-team").Key, all.Single(group => group.Name == "by-hand").Key);
        await With<ProviderService, bool>(async service =>
        {
            await service.LinkGroupAsync(team, provider, "Shop Operators", Root);
            Assert.Equal("provider.link.exists", (await Assert.ThrowsAsync<DomainException>(() => service.LinkGroupAsync(team, provider, "Shop Operators", Root))).Code);
            return true;
        });
        await With<SecretService, bool>(async service =>
        {
            await service.AssignAsync("shop", null, team, VaultRole.Reader, Root);
            return true;
        });

        async Task<IReadOnlyList<int>> GroupsOf(User user) =>
            [.. (await With<IAccessStore, IReadOnlyList<GroupMember>>(async access =>
                [.. (await access.ListMembersAsync(team, default)).Concat(await access.ListMembersAsync(byHand, default))])).Where(member => member.UserKey == user.Key).Select(member => member.GroupKey)];

        // In the group at the provider: a member here, and so a Reader of the vault. Never more than the group holds.
        _idp.Next = new FakeIdentity("sub-dana", "dana", Groups: ["everyone", "shop operators"]);
        using (var browser = Browser())
        {
            Assert.Equal("/", Where(await ProviderSignInAsync(browser)));
            Assert.Contains("\"shop\"", await browser.GetStringAsync("/api/v1/vaults"), StringComparison.Ordinal);
            Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync("/api/v1/vaults/shop/secrets/token/value")).StatusCode);
        }

        var dana = (await FindUserAsync("dana"))!;
        Assert.Equal(UserRole.User, dana.Role);
        Assert.Equal([team], await GroupsOf(dana));

        // A membership an administrator gave by hand is not the provider's to take away.
        await With<GroupService, bool>(async groups =>
        {
            await groups.AddMemberAsync(byHand, dana.Key, Root);
            return true;
        });

        // Out of the group at the provider: at the next sign-in the membership it gave is gone, and the vault with it.
        _idp.Next = new FakeIdentity("sub-dana", "dana", Groups: ["everyone"]);
        using (var browser = Browser())
        {
            Assert.Equal("/", Where(await ProviderSignInAsync(browser)));
            Assert.Equal("[]", await browser.GetStringAsync("/api/v1/vaults"));
        }

        Assert.Equal([byHand], await GroupsOf(dana));

        // Deleting the provider takes its connections and links along, and leaves the account and its manual group.
        _idp.Next = new FakeIdentity("sub-dana", "dana", Groups: ["Shop Operators"]);
        using (var browser = Browser())
        {
            await ProviderSignInAsync(browser);
        }

        Assert.Equal(2, (await GroupsOf(dana)).Count);
        await With<ProviderService, bool>(async service =>
        {
            await service.DeleteAsync(provider, Root);
            return true;
        });
        Assert.Equal([byHand], await GroupsOf(dana));
        Assert.Empty(await With<IExternalLoginStore, IReadOnlyList<ExternalLogin>>(logins => logins.ListForUserAsync(dana.Key, default)));
        Assert.Empty(await With<IAccessStore, IReadOnlyList<GroupProviderLink>>(access => access.ProviderLinksAsync(team, default)));
        Assert.NotNull(await FindUserAsync("dana"));
    }

    [Fact]
    public async Task New_identities_can_be_limited_to_verified_addresses_in_allowed_domains()
    {
        await AddProviderAsync(domains: "example.org");
        var number = 0;
        foreach (var (email, verified) in new (string?, bool?)[] { ("x@other.test", true), ("x@sub.example.org", true), ("x@example.org", false), (null, null) })
        {
            var name = "refused" + ++number;
            _idp.Next = new FakeIdentity("sub-" + name, name, email, EmailVerified: verified);
            using var browser = Browser();
            Assert.Equal("/login?external=email-not-allowed", Where(await ProviderSignInAsync(browser)));
            Assert.Null(await FindUserAsync(name));
        }

        _idp.Next = new FakeIdentity("sub-allowed", "allowed", "allowed@EXAMPLE.org", EmailVerified: true);
        using var welcome = Browser();
        Assert.Equal("/", Where(await ProviderSignInAsync(welcome)));
    }

    [Fact]
    public async Task A_provider_that_is_off_cancelled_or_broken_signs_nobody_in()
    {
        var key = await AddProviderAsync();
        _idp.Next = new FakeIdentity("sub-erin", "erin");
        using (var browser = Browser())
        {
            Assert.Equal("/", Where(await ProviderSignInAsync(browser)));
        }

        // The person cancels at the provider.
        _idp.Next = null;
        using (var browser = Browser())
        {
            Assert.Equal("/login?external=failed", Where(await ProviderSignInAsync(browser)));
            Assert.Equal(HttpStatusCode.Redirect, (await browser.GetAsync("/")).StatusCode);
        }

        // A disabled account stays out, whatever the provider says.
        _idp.Next = new FakeIdentity("sub-erin", "erin");
        var erin = (await FindUserAsync("erin"))!;
        erin.IsDisabled = true;
        await With<IUserStore, bool>(async users =>
        {
            await users.UpdateAsync(erin, default);
            return true;
        });
        using (var browser = Browser())
        {
            Assert.Equal("/login?external=disabled", Where(await ProviderSignInAsync(browser)));
        }

        // Without this page's token nothing starts: another site cannot begin a sign-in in someone's browser.
        using (var browser = Browser())
        {
            var forged = await browser.PostAsync("/account/external/idp", new FormUrlEncodedContent([]));
            Assert.Equal("/login?external=expired", Where(forged));
        }

        // Switched off: no button, no scheme, and the callback address answers nothing. No restart was involved.
        await With<ProviderService, bool>(async service =>
        {
            await service.UpdateAsync(key, new ProviderSettings("Test provider", "idp", _idp.Authority, FakeOidcProvider.ClientId, Enabled: false), Root);
            return true;
        });
        using (var browser = Browser())
        {
            Assert.DoesNotContain("Sign in with", await browser.GetStringAsync("/login"), StringComparison.Ordinal);
            Assert.Equal("/login?external=unknown", Where(await PostFormAsync(browser, "/login", "/account/external/idp")));
            Assert.NotEqual(HttpStatusCode.OK, (await browser.GetAsync("/signin-oidc/idp?code=x&state=y")).StatusCode);
        }

        Assert.Contains(await AuditAsync(), row => row.Code == "auth.external.failed" && row.Detail!.StartsWith("provider=idp", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Only_a_super_admin_sets_providers_up_and_the_client_secret_never_comes_back_out()
    {
        var admin = new Caller("an-admin", UserKey: 2, Role: UserRole.Admin);
        var superAdmin = new Caller("root", UserKey: 1, Role: UserRole.SuperAdmin);
        var withKey = superAdmin with { KeyId = 7 };
        var settings = new ProviderSettings("Authentik", "authentik", "https://auth.example.org/application/o/secrethive/", "client-1", FakeOidcProvider.ClientSecret);

        foreach (var caller in new[] { admin, withKey, new Caller("someone", UserKey: 3) })
        {
            Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => With<ProviderService, int>(service => service.CreateAsync(settings, caller)))).Code);
            Assert.Equal("access.denied", (await Assert.ThrowsAsync<DomainException>(() => With<ProviderService, IReadOnlyList<OidcProvider>>(service => service.ListAsync(caller)))).Code);
        }

        foreach (var bad in new[]
        {
            settings with { Authority = "http://auth.example.org" },
            settings with { Authority = "auth.example.org" },
            settings with { Slug = "Not A Slug" },
            settings with { ClientId = " " },
            settings with { ClientSecret = "" },
            settings with { AllowedEmailDomains = "not a domain!" },
            settings with { GroupsClaim = "gr oups" },
        })
        {
            Assert.Equal("provider.invalid", (await Assert.ThrowsAsync<DomainException>(() => With<ProviderService, int>(service => service.CreateAsync(bad, superAdmin)))).Code);
        }

        var key = await With<ProviderService, int>(service => service.CreateAsync(settings, superAdmin));
        Assert.Equal("provider.exists", (await Assert.ThrowsAsync<DomainException>(() => With<ProviderService, int>(service => service.CreateAsync(settings, superAdmin)))).Code);

        // Stored encrypted; the trailing slash of the issuer is dropped, as the discovery address is built from it.
        var stored = Assert.Single(await With<ProviderService, IReadOnlyList<OidcProvider>>(service => service.ListAsync(superAdmin)));
        Assert.Equal("https://auth.example.org/application/o/secrethive", stored.Authority);
        Assert.NotEmpty(stored.ProtectedClientSecret);
        Assert.DoesNotContain(FakeOidcProvider.ClientSecret, stored.ProtectedClientSecret, StringComparison.Ordinal);
        Assert.True(await With<ProviderService, bool>(service => Task.FromResult(service.HasSecret(stored))));

        // An edit with no secret typed keeps the stored one.
        await With<ProviderService, bool>(async service =>
        {
            await service.UpdateAsync(key, settings with { DisplayName = "Authentik SSO", ClientSecret = null }, superAdmin);
            return true;
        });
        var edited = Assert.Single(await With<ProviderService, IReadOnlyList<OidcProvider>>(service => service.ListAsync(superAdmin)));
        Assert.Equal(("Authentik SSO", stored.ProtectedClientSecret), (edited.DisplayName, edited.ProtectedClientSecret));
        Assert.True(edited.UpdatedUtc >= stored.UpdatedUtc);

        // On record, without the secret.
        var audit = await AuditAsync();
        Assert.Contains(audit, row => row.Code == "provider.created" && row.Principal == "root");
        Assert.Contains(audit, row => row.Code == "provider.updated" && row.Detail!.EndsWith("secret=kept", StringComparison.Ordinal));
        Assert.DoesNotContain(audit, row => (row.Detail ?? "").Contains(FakeOidcProvider.ClientSecret, StringComparison.Ordinal));

        // The database file holds it nowhere in the clear either.
        foreach (var file in Directory.GetFiles(_directory, "secrethive.db*"))
        {
            await using var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream, System.Text.Encoding.Latin1);
            Assert.DoesNotContain(FakeOidcProvider.ClientSecret, await reader.ReadToEndAsync(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task The_api_sets_a_provider_up_for_the_bootstrap_token_only_and_never_returns_the_secret()
    {
        using var root = _factory.CreateClient();
        root.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", Token);
        var body = new { displayName = "Test provider", authority = _idp.Authority, clientId = FakeOidcProvider.ClientId, clientSecret = FakeOidcProvider.ClientSecret, createAccounts = true };

        Assert.Equal(HttpStatusCode.Created, (await root.PutAsJsonAsync("/api/v1/providers/idp", body)).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await root.PutAsJsonAsync("/api/v1/providers/idp", new { displayName = "Renamed", authority = _idp.Authority, clientId = FakeOidcProvider.ClientId, createAccounts = true })).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await root.PutAsJsonAsync("/api/v1/providers/idp", new { authority = "http://not-https.example.org", clientId = "x" })).StatusCode);

        var listed = await root.GetStringAsync("/api/v1/providers");
        Assert.Contains("\"hasClientSecret\":true", listed, StringComparison.Ordinal);
        Assert.Contains("Renamed", listed, StringComparison.Ordinal);
        Assert.DoesNotContain(FakeOidcProvider.ClientSecret, listed, StringComparison.Ordinal);
        Assert.DoesNotContain("protected", listed, StringComparison.OrdinalIgnoreCase);

        // The provider set up this way works: the secret that was kept on the second call is the right one.
        _idp.Next = new FakeIdentity("sub-api", "via-api");
        using (var browser = Browser())
        {
            Assert.Equal("/", Where(await ProviderSignInAsync(browser)));

            // That session is an ordinary account: the providers are not its to see.
            Assert.Equal(HttpStatusCode.Forbidden, (await browser.GetAsync("/api/v1/providers")).StatusCode);
        }

        using var anonymous = _factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync("/api/v1/providers")).StatusCode);
        Assert.Equal(HttpStatusCode.NoContent, (await root.DeleteAsync("/api/v1/providers/idp")).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await root.DeleteAsync("/api/v1/providers/idp")).StatusCode);
    }

    [Fact]
    public async Task Every_page_runs_only_the_servers_own_scripts_and_its_forms_may_post_only_here_and_to_a_provider()
    {
        await AddProviderAsync();
        using var browser = Browser();

        var login = await browser.GetAsync("/login");
        var policy = login.Headers.GetValues("Content-Security-Policy").Single();
        var directives = policy.Split(';', StringSplitOptions.TrimEntries).ToDictionary(part => part.Split(' ')[0], part => part);
        Assert.Equal("script-src 'self'", directives["script-src"]);
        Assert.Equal("frame-ancestors 'none'", directives["frame-ancestors"]);
        Assert.Equal("object-src 'none'", directives["object-src"]);
        Assert.Equal($"form-action 'self' {new Uri(_idp.Authority).GetLeftPart(UriPartial.Authority)}", directives["form-action"]);

        // With script-src 'self', an inline script would simply not run: there must be none to need it.
        Assert.DoesNotMatch("<script(?![^>]*\\bsrc=)", await login.Content.ReadAsStringAsync());

        // The API's answers carry it too; a JSON answer opened as a page runs nothing either.
        Assert.Equal(policy, (await browser.GetAsync("/health")).Headers.GetValues("Content-Security-Policy").Single());
    }

    [GeneratedRegex("name=\"__RequestVerificationToken\" value=\"([^\"]+)\"", RegexOptions.CultureInvariant)]
    private static partial Regex AntiforgeryField();
}
