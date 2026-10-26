using Microsoft.EntityFrameworkCore;
using SecretHive.Application.Accounts;
using SecretHive.Domain.Entities;
using SecretHive.Infrastructure.Accounts;
using SecretHive.Infrastructure.Persistence;
using SecretHive.Infrastructure.Sqlite;

namespace SecretHive.Unit.Tests;

/// <summary>Accounts against a real database: signing in, lockout, forced password change, and who may change whom.</summary>
public sealed class AccountTests : IAsyncLifetime
{
    private const string FirstPassword = "generated-first-password";
    private const string Chosen = "generated-chosen-password";

    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-accounts-").FullName;
    private ShiftedClock _clock = new(TimeSpan.Zero);

    private SecretHiveDbContext NewContext()
    {
        var builder = new DbContextOptionsBuilder<SecretHiveDbContext>();
        builder.UseSecretHiveSqlite($"Data Source={Path.Combine(_directory, "accounts.db")};Pooling=False");
        return new SecretHiveDbContext(builder.Options);
    }

    private async Task<T> With<T>(Func<AccountService, Task<T>> act)
    {
        await using var context = NewContext();
        return await act(new AccountService(new EfUserStore(context), new PlatformPasswordHasher(), _clock));
    }

    private async Task<User> UserAsync(string name)
    {
        await using var context = NewContext();
        return await context.Users.AsNoTracking().SingleAsync(user => user.UserNameLower == name);
    }

    public async ValueTask InitializeAsync()
    {
        await using var context = NewContext();
        await context.Database.MigrateAsync();
        await With(accounts => accounts.EnsureFirstAdminAsync(FirstPassword, default));
    }

    public ValueTask DisposeAsync()
    {
        Directory.Delete(_directory, recursive: true);
        return ValueTask.CompletedTask;
    }

    private async Task<AccountActor> SuperAdminAsync() => new((await UserAsync("admin")).Key, UserRole.SuperAdmin);

    [Fact]
    public async Task The_first_administrator_exists_once_with_the_given_password_and_must_change_it()
    {
        var again = await With(accounts => accounts.EnsureFirstAdminAsync("generated-other-password", default));
        var admin = await UserAsync("admin");

        Assert.False(again);
        Assert.Equal((UserRole.SuperAdmin, true, false), (admin.Role, admin.MustChangePassword, admin.IsDisabled));
        Assert.DoesNotContain(FirstPassword, admin.PasswordHash);
        Assert.Equal(SignInStatus.Success, (await With(accounts => accounts.SignInAsync("ADMIN", FirstPassword, default))).Status);
        Assert.Equal(SignInStatus.Invalid, (await With(accounts => accounts.SignInAsync("admin", "admin", default))).Status);
    }

    [Fact]
    public async Task Changing_the_password_clears_the_obligation_and_ends_other_sessions()
    {
        var before = await UserAsync("admin");

        Assert.Equal(AccountOutcome.WrongPassword, await With(accounts => accounts.ChangeOwnPasswordAsync(before.Key, "generated-wrong", Chosen, default)));
        Assert.Equal(AccountOutcome.PasswordTooShort, await With(accounts => accounts.ChangeOwnPasswordAsync(before.Key, FirstPassword, "short", default)));
        Assert.Equal(AccountOutcome.PasswordTooShort, await With(accounts => accounts.ChangeOwnPasswordAsync(before.Key, FirstPassword, FirstPassword, default)));
        Assert.Equal(AccountOutcome.Done, await With(accounts => accounts.ChangeOwnPasswordAsync(before.Key, FirstPassword, Chosen, default)));

        var after = await UserAsync("admin");
        Assert.False(after.MustChangePassword);
        Assert.NotEqual(before.SecurityStamp, after.SecurityStamp);
        Assert.Equal(SignInStatus.Invalid, (await With(accounts => accounts.SignInAsync("admin", FirstPassword, default))).Status);
        Assert.Equal(SignInStatus.Success, (await With(accounts => accounts.SignInAsync("admin", Chosen, default))).Status);
    }

    [Fact]
    public async Task Five_wrong_passwords_lock_an_account_for_fifteen_minutes_and_an_unknown_name_looks_the_same()
    {
        for (var attempt = 1; attempt <= 4; attempt++)
        {
            Assert.Equal(SignInStatus.Invalid, (await With(accounts => accounts.SignInAsync("admin", "generated-wrong", default))).Status);
        }

        Assert.Equal(SignInStatus.LockedOut, (await With(accounts => accounts.SignInAsync("admin", "generated-wrong", default))).Status);

        // Locked means locked: the right password does not get in either.
        Assert.Equal(SignInStatus.LockedOut, (await With(accounts => accounts.SignInAsync("admin", FirstPassword, default))).Status);

        var nobody = "nobody-" + Guid.NewGuid().ToString("N");
        var unknown = new List<SignInStatus>();
        for (var attempt = 1; attempt <= 5; attempt++)
        {
            unknown.Add((await With(accounts => accounts.SignInAsync(nobody, "generated-wrong", default))).Status);
        }

        Assert.Equal([SignInStatus.Invalid, SignInStatus.Invalid, SignInStatus.Invalid, SignInStatus.Invalid, SignInStatus.LockedOut], unknown);

        _clock = new ShiftedClock(TimeSpan.FromMinutes(16));
        Assert.Equal(SignInStatus.Success, (await With(accounts => accounts.SignInAsync("admin", FirstPassword, default))).Status);
    }

    [Fact]
    public async Task An_admin_manages_users_a_super_admin_manages_admins_and_nobody_manages_themselves()
    {
        var root = await SuperAdminAsync();
        var (made, admin) = await With(accounts => accounts.CreateAsync(root, "ops", "Ops", "ops@example.test", UserRole.Admin, Chosen, default));
        var asAdmin = new AccountActor(admin!.Key, UserRole.Admin);

        var (userOutcome, user) = await With(accounts => accounts.CreateAsync(asAdmin, "reader", "", "", UserRole.User, Chosen, default));
        var (tooHigh, _) = await With(accounts => accounts.CreateAsync(asAdmin, "other-admin", "", "", UserRole.Admin, Chosen, default));
        var (taken, _) = await With(accounts => accounts.CreateAsync(root, "READER", "", "", UserRole.User, Chosen, default));
        var (badName, _) = await With(accounts => accounts.CreateAsync(root, "has space", "", "", UserRole.User, Chosen, default));
        var (shortPassword, _) = await With(accounts => accounts.CreateAsync(root, "someone", "", "", UserRole.User, "short", default));

        Assert.Equal((AccountOutcome.Done, AccountOutcome.Done), (made, userOutcome));
        Assert.True(user!.MustChangePassword);
        Assert.Equal((AccountOutcome.Forbidden, AccountOutcome.NameTaken, AccountOutcome.InvalidName, AccountOutcome.PasswordTooShort), (tooHigh, taken, badName, shortPassword));

        // An admin cannot touch another admin or promote anyone to one; nobody changes their own role.
        Assert.Equal(AccountOutcome.Forbidden, await With(accounts => accounts.SetRoleAsync(asAdmin, user.Key, UserRole.Admin, default)));
        Assert.Equal(AccountOutcome.Forbidden, await With(accounts => accounts.SetDisabledAsync(asAdmin, root.Key, true, default)));
        Assert.Equal(AccountOutcome.Forbidden, await With(accounts => accounts.SetRoleAsync(root, root.Key, UserRole.User, default)));
        Assert.Equal(AccountOutcome.Done, await With(accounts => accounts.SetRoleAsync(root, user.Key, UserRole.Admin, default)));
    }

    [Fact]
    public async Task Disabling_resetting_and_a_role_change_each_end_the_sessions_of_that_account()
    {
        var root = await SuperAdminAsync();
        var (_, user) = await With(accounts => accounts.CreateAsync(root, "reader", "", "", UserRole.User, Chosen, default));
        var stamps = new List<string> { (await UserAsync("reader")).SecurityStamp };

        await With(accounts => accounts.SetRoleAsync(root, user!.Key, UserRole.Admin, default));
        stamps.Add((await UserAsync("reader")).SecurityStamp);
        await With(accounts => accounts.ResetPasswordAsync(root, user!.Key, "generated-temporary-password", default));
        stamps.Add((await UserAsync("reader")).SecurityStamp);
        await With(accounts => accounts.SetDisabledAsync(root, user!.Key, true, default));
        stamps.Add((await UserAsync("reader")).SecurityStamp);

        Assert.Equal(4, stamps.Distinct().Count());
        Assert.True((await UserAsync("reader")).MustChangePassword);

        // Disabled is only said after the right password, so it does not tell an outsider which names exist.
        Assert.Equal(SignInStatus.Disabled, (await With(accounts => accounts.SignInAsync("reader", "generated-temporary-password", default))).Status);
        Assert.Equal(SignInStatus.Invalid, (await With(accounts => accounts.SignInAsync("reader", "generated-wrong", default))).Status);
        Assert.Equal(AccountOutcome.Done, await With(accounts => accounts.DeleteAsync(root, user!.Key, default)));
        Assert.Equal(AccountOutcome.NotFound, await With(accounts => accounts.DeleteAsync(root, user!.Key, default)));
    }

    [Fact]
    public async Task The_last_super_admin_cannot_be_removed_by_any_route()
    {
        var root = await SuperAdminAsync();
        var (_, second) = await With(accounts => accounts.CreateAsync(root, "second", "", "", UserRole.SuperAdmin, Chosen, default));
        var asSecond = new AccountActor(second!.Key, UserRole.SuperAdmin);

        // With two, one may go; then the one left is the last.
        Assert.Equal(AccountOutcome.Done, await With(accounts => accounts.SetDisabledAsync(asSecond, root.Key, true, default)));
        Assert.Equal(AccountOutcome.Done, await With(accounts => accounts.SetDisabledAsync(asSecond, root.Key, false, default)));
        Assert.Equal(AccountOutcome.Done, await With(accounts => accounts.DeleteAsync(root, second.Key, default)));

        var (_, admin) = await With(accounts => accounts.CreateAsync(root, "ops", "", "", UserRole.Admin, Chosen, default));
        Assert.Equal(AccountOutcome.Forbidden, await With(accounts => accounts.DeleteAsync(new AccountActor(admin!.Key, UserRole.Admin), root.Key, default)));
        Assert.Equal(AccountOutcome.Forbidden, await With(accounts => accounts.SetDisabledAsync(root, root.Key, true, default)));
    }
}
