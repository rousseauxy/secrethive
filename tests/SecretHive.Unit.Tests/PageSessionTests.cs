using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Web;

namespace SecretHive.Unit.Tests;

/// <summary>
/// A page is a circuit that outlives the request it was opened with. What the pages call must still check the
/// account as it is now: disabled, or changed since the sign-in, ends the page's work and sends the browser back to
/// the sign-in form, as the cookie check does for a request.
/// </summary>
public sealed class PageSessionTests : IDisposable
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-pages-").FullName;
    private readonly WebApplicationFactory<SecretHive.Web.ServerMarker> _factory;
    private readonly HttpClient _admin;

    public PageSessionTests()
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
        _admin = _factory.CreateClient();
        _admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
    }

    public void Dispose()
    {
        _admin.Dispose();
        _factory.Dispose();
        Directory.Delete(_directory, recursive: true);
    }

    /// <summary>Stands in for the browser: remembers where the page sent it.</summary>
    private sealed class Browser : NavigationManager
    {
        public Browser() => Initialize("http://localhost/", "http://localhost/vaults/shop");

        public List<string> SentTo { get; } = [];

        protected override void NavigateToCore(string uri, bool forceLoad) => SentTo.Add(uri);
    }

    [Fact]
    public async Task A_page_stops_when_its_account_is_disabled_or_changed_and_sends_the_browser_to_the_sign_in_form()
    {
        // An account with a role in a vault, and a page opened with its session.
        Assert.Equal(System.Net.HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { })).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.Created, (await _admin.PutAsJsonAsync("/api/v1/users/dev", new { password = "generated-first-password" })).StatusCode);
        Assert.Equal(System.Net.HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/vaults/shop/access", new { user = "dev", role = "Reader" })).StatusCode);
        User dev;
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            dev = (await scope.ServiceProvider.GetRequiredService<IUserStore>().FindByUserNameAsync("dev", default))!;
        }

        var browser = new Browser();
        var page = new Vaults(_factory.Services.GetRequiredService<IServiceScopeFactory>(), browser)
        {
            Caller = new Caller("dev", "192.0.2.1", "ui", dev.Key, UserRole.User),
            Stamp = dev.SecurityStamp,
        };
        Assert.Single(await page.Run(service => service.ListVaultsAsync(page.Caller)));

        // The administrator disables the account. The open page does nothing more, and the browser is sent to sign in.
        Assert.Equal(System.Net.HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/users/dev/disabled", new { disabled = true })).StatusCode);
        var ended = await Assert.ThrowsAsync<DomainException>(() => page.Run(service => service.ListVaultsAsync(page.Caller)));
        Assert.Equal("session.ended", ended.Code);
        Assert.Equal("/login", Assert.Single(browser.SentTo));
        Assert.Equal("This session has ended: the account was changed or disabled. Sign in again.", await page.Try(service => service.ListVaultsAsync(page.Caller)));

        // Enabled again: the stamp moved with the change, so the old session is still over; a fresh sign-in is not.
        Assert.Equal(System.Net.HttpStatusCode.NoContent, (await _admin.PutAsJsonAsync("/api/v1/users/dev/disabled", new { disabled = false })).StatusCode);
        await Assert.ThrowsAsync<DomainException>(() => page.Run(service => service.ListVaultsAsync(page.Caller)));
        await using (var scope = _factory.Services.CreateAsyncScope())
        {
            page.Stamp = (await scope.ServiceProvider.GetRequiredService<IUserStore>().FindByUserNameAsync("dev", default))!.SecurityStamp;
        }

        Assert.Single(await page.Run(service => service.ListVaultsAsync(page.Caller)));

        // A page opened by the bootstrap token has no account to check, and keeps working.
        var tool = new Vaults(_factory.Services.GetRequiredService<IServiceScopeFactory>(), browser) { Caller = new Caller("bootstrap-token", Unrestricted: true) };
        Assert.Single(await tool.Run(service => service.ListVaultsAsync(tool.Caller)));
    }
}
