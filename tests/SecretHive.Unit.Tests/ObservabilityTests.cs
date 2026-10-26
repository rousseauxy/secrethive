using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecretHive.Application.Accounts;
using SecretHive.Application.Secrets;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Accounts;
using SecretHive.Infrastructure.Backup;
using SecretHive.Infrastructure.Encryption;
using SecretHive.Infrastructure.Persistence;
using SecretHive.Infrastructure.Sqlite;
using SecretHive.Web.Security;

namespace SecretHive.Unit.Tests;

/// <summary>
/// What lets somebody outside the server see that something is wrong: every audit event as a log line, events for
/// what is about to expire, a limit on how fast a key may ask, and the numbers on the health probe.
/// </summary>
public sealed class ObservabilityTests : IAsyncLifetime
{
    private const string Token = "generated-bootstrap-token-0123456789abcdef";
    private static readonly Caller Root = Caller.System("test");

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-observe-").FullName;
    private readonly CapturedLogs _logs = new();
    private WebApplicationFactory<SecretHive.Web.ServerMarker> _factory = null!;
    private HttpClient _admin = null!;

    public ValueTask InitializeAsync()
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
            builder.UseSetting("SecretHive:Keys:RequestsPerMinute", "5");
            builder.ConfigureServices(services => services.AddLogging(logging => logging.AddProvider(_logs)));
        });
        _admin = _factory.CreateClient();
        _admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", Token);
        return ValueTask.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        _admin.Dispose();
        await _factory.DisposeAsync();
        Directory.Delete(_directory, recursive: true);
    }

    private async Task<T> With<TService, T>(Func<TService, Task<T>> act)
        where TService : notnull
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        return await act(scope.ServiceProvider.GetRequiredService<TService>());
    }

    [Fact]
    public async Task Every_audit_event_is_also_a_log_line_with_its_fields_and_never_a_value()
    {
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { });
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop/secrets/token", new { value = "generated-shop-value" });
        await _admin.GetStringAsync("/api/v1/vaults/shop/secrets/token/value");
        using (var wrong = _factory.CreateClient())
        {
            wrong.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "shv_00000000_" + new string('a', 43));
            await wrong.GetAsync("/api/v1/vaults");
        }

        var audit = _logs.Entries.Where(entry => entry.Category == AuditLogInterceptor.Category).ToList();
        var read = Assert.Single(audit, entry => (string?)entry.Fields["Code"] == "secret.value.read");
        Assert.Equal(("info", "bootstrap-token", "shop", "token", "api"), ((string?)read.Fields["Severity"], (string?)read.Fields["Principal"], (string?)read.Fields["Vault"], (string?)read.Fields["Secret"], (string?)read.Fields["Via"]));
        Assert.Equal(LogLevel.Information, read.Level);
        Assert.True((long)read.Fields["AuditId"]! > 0);

        // One line per row: as many audit lines as there are rows, with the same codes in the same order.
        var rows = await With<SecretHiveDbContext, List<string>>(db => db.Audit.OrderBy(row => row.Id).Select(row => row.Code).ToListAsync());
        Assert.Equal(rows, audit.Select(entry => (string?)entry.Fields["Code"]));

        // No line of any kind, from any part of the server, carries the value or the token.
        Assert.DoesNotContain(_logs.Entries, entry => entry.Message.Contains("generated-shop-value", StringComparison.Ordinal) || entry.Message.Contains(Token, StringComparison.Ordinal));
        Assert.DoesNotContain(_logs.Entries, entry => entry.Fields.Values.Any(value => value is string text && (text.Contains("generated-shop-value", StringComparison.Ordinal) || text.Contains(Token, StringComparison.Ordinal))));
    }

    [Fact]
    public async Task A_key_that_asks_faster_than_it_may_gets_429_and_the_first_refusal_is_on_record()
    {
        await _admin.PutAsJsonAsync("/api/v1/vaults/shop", new { });
        var root = await With<SecretHive.Application.Ports.IUserStore, User>(async users => (await users.FindByUserNameAsync("admin", default))!);
        var owner = new AccountActor(root.Key, UserRole.SuperAdmin);
        var job = await With<AccountService, User>(async accounts => (await accounts.CreateServiceAsync(owner, "stack-web-1-shop", "", default)).User!);
        await With<SecretService, bool>(async service =>
        {
            await service.AssignAsync("shop", job.Key, null, VaultRole.Reader, Root);
            return true;
        });
        var (_, key) = await With<KeyService, (KeySummary, string)>(keys => keys.CreateAsync(Root, job.Key, "deploy", 30, null, null));
        using var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);

        var answers = new List<HttpResponseMessage>();
        for (var i = 0; i < 9; i++)
        {
            answers.Add(await client.GetAsync("/api/v1/vaults"));
        }

        // The minute may turn over mid-test; then the count starts again, which is the rule and not a failure of it.
        var refused = answers.Where(answer => answer.StatusCode == HttpStatusCode.TooManyRequests).ToList();
        Assert.InRange(refused.Count, 1, 4);
        Assert.Equal(HttpStatusCode.OK, answers[0].StatusCode);
        Assert.All(refused, answer => Assert.InRange(int.Parse(answer.Headers.GetValues("Retry-After").Single(), System.Globalization.CultureInfo.InvariantCulture), 1, 60));
        Assert.Contains("key.rate_limited", await refused[0].Content.ReadAsStringAsync());

        // The bootstrap token and other keys are not slowed down by this key.
        Assert.Equal(HttpStatusCode.OK, (await _admin.GetAsync("/api/v1/vaults")).StatusCode);
        var rows = await With<SecretHiveDbContext, List<AuditEvent>>(db => db.Audit.Where(row => row.Code == "key.rate_limited").ToListAsync());
        Assert.InRange(rows.Count, 1, 2);
        Assert.All(rows, row => Assert.Equal((AuditSeverity.Security, "stack-web-1-shop"), (row.Severity, row.Principal)));

        // The health probe counts it, without saying what it was.
        var health = JsonDocument.Parse(await _factory.CreateClient().GetStringAsync("/health")).RootElement;
        Assert.InRange(health.GetProperty("securityEvents24h").GetInt32(), 1, 2);
    }

    [Fact]
    public async Task The_bootstrap_token_has_a_pace_of_its_own_too()
    {
        var answers = new List<HttpStatusCode>();
        for (var i = 0; i < 9; i++)
        {
            answers.Add((await _admin.GetAsync("/api/v1/vaults")).StatusCode);
        }

        Assert.Equal(HttpStatusCode.OK, answers[0]);
        Assert.InRange(answers.Count(status => status == HttpStatusCode.TooManyRequests), 1, 4);
        var rows = await With<SecretHiveDbContext, List<AuditEvent>>(db => db.Audit.Where(row => row.Code == "key.rate_limited").ToListAsync());
        Assert.All(rows, row => Assert.Equal(("bootstrap-token", "bootstrap limit=5/min"), (row.Principal, row.Detail)));
    }

    [Fact]
    public void The_limit_counts_per_key_and_per_minute_and_zero_switches_it_off()
    {
        var clock = new TestClock(new DateTimeOffset(2026, 10, 10, 12, 0, 10, TimeSpan.Zero));
        var limiter = new KeyRateLimiter(2, clock);
        Assert.True(limiter.Allow("key:1", out _, out _));
        Assert.True(limiter.Allow("key:1", out _, out _));
        Assert.False(limiter.Allow("key:1", out var first, out var retry));
        Assert.True(first);
        Assert.Equal(50, retry);
        Assert.False(limiter.Allow("key:1", out var again, out _));
        Assert.False(again);
        Assert.True(limiter.Allow("key:2", out _, out _));

        clock.Advance(TimeSpan.FromSeconds(50));
        Assert.True(limiter.Allow("key:1", out _, out _));

        var off = new KeyRateLimiter(0, clock);
        Assert.All(Enumerable.Range(0, 1000), attempt => Assert.True(off.Allow("key:1", out _, out _)));
    }

    [Fact]
    public async Task What_is_about_to_expire_is_said_once_per_step_and_a_missing_backup_once_a_day()
    {
        var clock = new TestClock(DateTimeOffset.UtcNow);
        var status = new BackupStatus();
        SecretHiveDbContext Open()
        {
            var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
            builder.UseSecretHiveSqlite($"Data Source={Path.Combine(_directory, "expiry.db")};Pooling=False");
            return new SecretHiveDbContext(builder.Options);
        }

        using var master = MasterKey.Load(Path.Combine(_directory, "master.key"));
        using var ring = new KeyRing(master);
        await using (var db = Open())
        {
            await db.Database.MigrateAsync(TestContext.Current.CancellationToken);
            var secrets = new SecretService(new EfSecretStore(db), ring, clock, new EfAccessStore(db), new EfUserStore(db));
            await secrets.CreateVaultAsync("edge", null, Root);
            await secrets.ImportCertificateAsync(new ImportCertificate("edge", "site", [new TestCertificate("shop.example.test", validDays: 20).CertificatePart]), Root);
            await secrets.ImportCertificateAsync(new ImportCertificate("edge", "far-away", [new TestCertificate("far.example.test", validDays: 200).CertificatePart]), Root);
            await secrets.ImportCertificateAsync(new ImportCertificate("edge", "thrown-away", [new TestCertificate("old.example.test", validDays: 2).CertificatePart]), Root);
            await secrets.DeleteAsync("edge", "thrown-away", Root);

            var users = new EfUserStore(db);
            var audit = new AuditWriter(new EfSecretStore(db), clock);
            var (_, job) = await new AccountService(users, new PlatformPasswordHasher(), clock).CreateServiceAsync(new AccountActor(-1, UserRole.SuperAdmin), "stack-web-1-shop", "", default);
            var keys = new KeyService(new EfKeyStore(db), users, new EfSecretStore(db), audit, clock, new EfAccessStore(db));
            await keys.CreateAsync(Root, job!.Key, "ends soon", 5, null, null);
            await keys.CreateAsync(Root, job.Key, "ends later", 60, null, null);
        }

        async Task<List<(string Code, AuditSeverity Severity, string? Secret, string? Detail)>> Look()
        {
            await using var db = Open();
            var before = await db.Audit.MaxAsync(row => (long?)row.Id) ?? 0;
            await new ExpiryWatch(db, status, new BackupOptions(Path.Combine(_directory, "none"), IntervalHours: 24), clock).LookAsync();
            return [.. (await db.Audit.Where(row => row.Id > before).OrderBy(row => row.Id).ToListAsync()).Select(row => (row.Code, row.Severity, row.Secret, row.Detail))];
        }

        // The first look says everything already inside a step: the certificate at 20 days, the key at 5.
        status.Verified(clock.GetUtcNow().UtcDateTime);
        var first = await Look();
        Assert.Equal([("certificate.expiring", AuditSeverity.Info, "site"), ("key.expiring", AuditSeverity.Notice, null)], first.Select(row => (row.Code, row.Severity, row.Secret)));
        Assert.StartsWith("days=20 ", first[0].Detail, StringComparison.Ordinal);
        Assert.Contains("of stack-web-1-shop (ends soon)", first[1].Detail, StringComparison.Ordinal);

        // Looking again says nothing again, however often.
        Assert.Empty(await Look());
        clock.Advance(TimeSpan.FromHours(1));
        status.Verified(clock.GetUtcNow().UtcDateTime);
        Assert.Empty(await Look());

        // Each tighter step is said once, louder each time; then that it is over.
        clock.Advance(TimeSpan.FromDays(8));
        status.Verified(clock.GetUtcNow().UtcDateTime);
        Assert.Equal([("certificate.expiring", AuditSeverity.Notice, "site")], (await Look()).Select(row => (row.Code, row.Severity, row.Secret)));
        clock.Advance(TimeSpan.FromDays(10));
        status.Verified(clock.GetUtcNow().UtcDateTime);
        Assert.Equal([("certificate.expiring", AuditSeverity.Security, "site")], (await Look()).Select(row => (row.Code, row.Severity, row.Secret)));
        clock.Advance(TimeSpan.FromDays(3));
        status.Verified(clock.GetUtcNow().UtcDateTime);
        Assert.Equal([("certificate.expired", AuditSeverity.Security, "site")], (await Look()).Select(row => (row.Code, row.Severity, row.Secret)));
        Assert.Empty(await Look());

        // No backup for two intervals: said, and not again within the day; once more the day after.
        clock.Advance(TimeSpan.FromHours(49));
        var stale = await Look();
        Assert.Contains(stale, row => row.Code == "backup.verified.stale" && row.Severity == AuditSeverity.Security);
        clock.Advance(TimeSpan.FromHours(2));
        Assert.DoesNotContain(await Look(), row => row.Code == "backup.verified.stale");
        clock.Advance(TimeSpan.FromHours(23));
        Assert.Contains(await Look(), row => row.Code == "backup.verified.stale");
    }

    private sealed class TestClock(DateTimeOffset start) : TimeProvider
    {
        private DateTimeOffset now = start;

        public override DateTimeOffset GetUtcNow() => now;

        public void Advance(TimeSpan by) => now += by;
    }

    private sealed record LogEntry(string Category, LogLevel Level, string Message, IReadOnlyDictionary<string, object?> Fields);

    /// <summary>Keeps every log line the server writes, with its structured fields, as a collector would receive them.</summary>
    private sealed class CapturedLogs : ILoggerProvider
    {
        private readonly ConcurrentQueue<LogEntry> entries = new();

        public IReadOnlyCollection<LogEntry> Entries => entries;

        public ILogger CreateLogger(string categoryName) => new Capture(categoryName, entries);

        public void Dispose()
        {
        }

        private sealed class Capture(string category, ConcurrentQueue<LogEntry> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                var fields = state is IEnumerable<KeyValuePair<string, object?>> pairs ? pairs.ToDictionary(pair => pair.Key, pair => pair.Value) : [];
                entries.Enqueue(new LogEntry(category, logLevel, formatter(state, exception) + (exception is null ? "" : " " + exception), fields));
            }
        }
    }
}
