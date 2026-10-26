using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using SecretHive.Application.Ports;
using SecretHive.Domain.Entities;

namespace SecretHive.Application.Accounts;

/// <summary>Who is asking for an account change, as far as the rules below care.</summary>
public sealed record AccountActor(int Key, UserRole Role);

public enum SignInStatus
{
    Success,

    /// <summary>Unknown user or wrong password; deliberately indistinguishable.</summary>
    Invalid,

    LockedOut,

    /// <summary>Only reported after the right password, so it does not reveal which names exist.</summary>
    Disabled,
}

public sealed record SignInResult(SignInStatus Status, User? User = null);

public enum AccountOutcome
{
    Done,
    NotFound,

    /// <summary>The actor's role does not reach the account or the role involved, or it is the actor's own account.</summary>
    Forbidden,
    NameTaken,
    InvalidName,
    PasswordTooShort,
    WrongPassword,

    /// <summary>The change would leave no enabled super admin.</summary>
    LastSuperAdmin,
}

/// <summary>
/// Local accounts: signing in, passwords, roles and who may change whom. The rules live here rather than in the pages
/// so that every way in - a page, a future API, a recovery on start - applies the same ones.
/// </summary>
public sealed partial class AccountService(IUserStore users, IPasswordHasher hasher, TimeProvider time)
{
    public const int MinimumPasswordLength = 12;

    public const int MaxFailedSignIns = 5;

    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    public const string FirstAdminUserName = "admin";

    /// <summary>
    /// A hash of a random password, made once and checked against when the user does not exist, so a missing name costs one
    /// verification like a wrong password does. Hashing it on every attempt made a missing name cost twice as long, which
    /// told an outsider which names exist.
    /// </summary>
    private static string? decoyHash;

    /// <summary>
    /// Failed attempts at names no local account has, by lower-cased name, with when that name is locked until. Kept in
    /// memory and bounded: losing it only lets a name be tried a few more times, exactly like a real account after a restart
    /// of its lockout window.
    /// </summary>
    private static readonly ConcurrentDictionary<string, (int Failures, DateTime LockedUntilUtc, DateTime LastUtc)> unknownNames = new(StringComparer.Ordinal);

    private const int MaxTrackedUnknownNames = 10_000;

    /// <summary>Records a failed attempt at an unknown name; true when that name now counts as locked out.</summary>
    private static bool UnknownNameFailed(string nameLower, DateTime now)
    {
        var entry = unknownNames.AddOrUpdate(
            nameLower,
            _ => (1, DateTime.MinValue, now),
            (_, previous) => previous.LockedUntilUtc > now
                ? previous with { LastUtc = now }
                : now - previous.LastUtc > LockoutDuration
                    ? (1, DateTime.MinValue, now)
                    : previous.Failures + 1 >= MaxFailedSignIns
                        ? (0, now + LockoutDuration, now)
                        : (previous.Failures + 1, DateTime.MinValue, now));

        if (unknownNames.Count > MaxTrackedUnknownNames)
        {
            foreach (var old in unknownNames.OrderBy(e => e.Value.LastUtc).Take(unknownNames.Count - (MaxTrackedUnknownNames / 2)).Select(e => e.Key).ToList())
            {
                unknownNames.TryRemove(old, out _);
            }
        }

        return entry.LockedUntilUtc > now;
    }

    /// <summary>The decoy, hashed by the first attempt that needs it; a race hashes it twice and either one serves.</summary>
    private string DecoyHash() => decoyHash ??= hasher.Hash(Convert.ToHexString(RandomNumberGenerator.GetBytes(16)));

    public async Task<SignInResult> SignInAsync(string userName, string password, CancellationToken cancellationToken)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var user = string.IsNullOrWhiteSpace(userName) ? null : await users.FindByUserNameAsync(userName.Trim(), cancellationToken);
        if (user?.PasswordHash is null)
        {
            // A name with no password - none at all, or an account that signs in only with a provider - locks after the same
            // number of attempts as a real one, so "Too many failed attempts" does not tell an outsider which names exist.
            hasher.Verify(DecoyHash(), password ?? "");
            return new SignInResult(UnknownNameFailed((userName ?? "").Trim().ToLowerInvariant(), now) ? SignInStatus.LockedOut : SignInStatus.Invalid);
        }

        if (user.LockedUntilUtc > now)
        {
            // The same work as any other answer, so a locked account is not told apart by how fast it is refused.
            hasher.Verify(DecoyHash(), password ?? "");
            return new SignInResult(SignInStatus.LockedOut);
        }

        var check = hasher.Verify(user.PasswordHash, password ?? "");
        if (check == PasswordCheck.Failed)
        {
            var locked = await users.RecordFailedSignInAsync(user.Key, MaxFailedSignIns, now + LockoutDuration, cancellationToken);
            return new SignInResult(locked ? SignInStatus.LockedOut : SignInStatus.Invalid);
        }

        if (user.IsDisabled)
        {
            return new SignInResult(SignInStatus.Disabled);
        }

        user.FailedSignIns = 0;
        user.LockedUntilUtc = null;
        user.LastSignInUtc = now;
        if (check == PasswordCheck.SuccessRehashNeeded)
        {
            user.PasswordHash = hasher.Hash(password!);
        }

        await users.UpdateAsync(user, cancellationToken);
        return new SignInResult(SignInStatus.Success, user);
    }

    public async Task<AccountOutcome> ChangeOwnPasswordAsync(int userKey, string currentPassword, string newPassword, CancellationToken cancellationToken)
    {
        var user = await users.FindAsync(userKey, cancellationToken);
        if (user?.PasswordHash is null)
        {
            return AccountOutcome.NotFound;
        }

        if (hasher.Verify(user.PasswordHash, currentPassword ?? "") == PasswordCheck.Failed)
        {
            return AccountOutcome.WrongPassword;
        }

        if ((newPassword ?? "").Length < MinimumPasswordLength || newPassword == currentPassword)
        {
            return AccountOutcome.PasswordTooShort;
        }

        user.PasswordHash = hasher.Hash(newPassword!);
        user.MustChangePassword = false;
        user.SecurityStamp = NewStamp();
        await users.UpdateAsync(user, cancellationToken);
        return AccountOutcome.Done;
    }

    public async Task<AccountOutcome> UpdateProfileAsync(int userKey, string displayName, string email, CancellationToken cancellationToken)
    {
        var user = await users.FindAsync(userKey, cancellationToken);
        if (user is null)
        {
            return AccountOutcome.NotFound;
        }

        user.DisplayName = (displayName ?? "").Trim();
        user.Email = (email ?? "").Trim();
        await users.UpdateAsync(user, cancellationToken);
        return AccountOutcome.Done;
    }

    /// <summary>Creates a local account with a first password its owner must replace at their first sign-in.</summary>
    public async Task<(AccountOutcome Outcome, User? User)> CreateAsync(
        AccountActor actor,
        string userName,
        string displayName,
        string email,
        UserRole role,
        string password,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!CanManage(actor, role))
        {
            return (AccountOutcome.Forbidden, null);
        }

        if (!IsValidUserName(userName))
        {
            return (AccountOutcome.InvalidName, null);
        }

        if ((password ?? "").Length < MinimumPasswordLength)
        {
            return (AccountOutcome.PasswordTooShort, null);
        }

        var user = NewUser(userName.Trim(), role);
        user.DisplayName = (displayName ?? "").Trim();
        user.Email = (email ?? "").Trim();
        user.PasswordHash = hasher.Hash(password!);
        user.MustChangePassword = true;

        return await users.AddAsync(user, cancellationToken) ? (AccountOutcome.Done, user) : (AccountOutcome.NameTaken, null);
    }

    /// <summary>
    /// Creates a service identity: a name for a machine. It has no password and cannot sign in to the pages; it
    /// holds keys, and roles in vaults like any account.
    /// </summary>
    public async Task<(AccountOutcome Outcome, User? User)> CreateServiceAsync(AccountActor actor, string name, string description, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (!CanManage(actor, UserRole.User))
        {
            return (AccountOutcome.Forbidden, null);
        }

        if (!IsValidUserName(name))
        {
            return (AccountOutcome.InvalidName, null);
        }

        var user = NewUser(name.Trim(), UserRole.User);
        user.DisplayName = (description ?? "").Trim();
        user.IsService = true;
        return await users.AddAsync(user, cancellationToken) ? (AccountOutcome.Done, user) : (AccountOutcome.NameTaken, null);
    }

    /// <summary>Sets a password for someone else; they choose their own at their next sign-in.</summary>
    public async Task<AccountOutcome> ResetPasswordAsync(AccountActor actor, int userKey, string password, CancellationToken cancellationToken)
    {
        var (outcome, user) = await TargetAsync(actor, userKey, cancellationToken);
        if (outcome != AccountOutcome.Done)
        {
            return outcome;
        }

        if ((password ?? "").Length < MinimumPasswordLength)
        {
            return AccountOutcome.PasswordTooShort;
        }

        // A service identity never gets a password: that would turn a machine's name into a way to sign in.
        if (user!.IsService)
        {
            return AccountOutcome.Forbidden;
        }

        user.PasswordHash = hasher.Hash(password!);
        user.MustChangePassword = true;
        user.FailedSignIns = 0;
        user.LockedUntilUtc = null;
        user.SecurityStamp = NewStamp();
        await users.UpdateAsync(user, cancellationToken);
        return AccountOutcome.Done;
    }

    public async Task<AccountOutcome> SetRoleAsync(AccountActor actor, int userKey, UserRole role, CancellationToken cancellationToken)
    {
        var (outcome, user) = await TargetAsync(actor, userKey, cancellationToken);
        if (outcome != AccountOutcome.Done)
        {
            return outcome;
        }

        if (!CanManage(actor, role))
        {
            return AccountOutcome.Forbidden;
        }

        if (user!.Role == role)
        {
            return AccountOutcome.Done;
        }

        if (await RemovesLastSuperAdminAsync(user, cancellationToken))
        {
            return AccountOutcome.LastSuperAdmin;
        }

        user.Role = role;
        user.SecurityStamp = NewStamp();
        await users.UpdateAsync(user, cancellationToken);
        return AccountOutcome.Done;
    }

    /// <summary>
    /// Gives a service identity the instance role Admin, or takes it back. Only a super admin, and never Super admin
    /// itself: a machine may do what an admin does through its keys, and no more.
    /// </summary>
    public async Task<AccountOutcome> SetServiceRoleAsync(AccountActor actor, int userKey, UserRole role, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        if (actor.Role != UserRole.SuperAdmin || role == UserRole.SuperAdmin || !Enum.IsDefined(role))
        {
            return AccountOutcome.Forbidden;
        }

        var user = await users.FindAsync(userKey, cancellationToken);
        if (user is not { IsService: true })
        {
            return AccountOutcome.NotFound;
        }

        if (user.Role == role)
        {
            return AccountOutcome.Done;
        }

        user.Role = role;
        user.SecurityStamp = NewStamp();
        await users.UpdateAsync(user, cancellationToken);
        return AccountOutcome.Done;
    }

    public async Task<AccountOutcome> SetDisabledAsync(AccountActor actor, int userKey, bool disabled, CancellationToken cancellationToken)
    {
        var (outcome, user) = await TargetAsync(actor, userKey, cancellationToken);
        if (outcome != AccountOutcome.Done)
        {
            return outcome;
        }

        if (disabled && await RemovesLastSuperAdminAsync(user!, cancellationToken))
        {
            return AccountOutcome.LastSuperAdmin;
        }

        user!.IsDisabled = disabled;
        user.SecurityStamp = NewStamp();
        if (!disabled)
        {
            user.FailedSignIns = 0;
            user.LockedUntilUtc = null;
        }

        await users.UpdateAsync(user, cancellationToken);
        return AccountOutcome.Done;
    }

    public async Task<AccountOutcome> DeleteAsync(AccountActor actor, int userKey, CancellationToken cancellationToken)
    {
        var (outcome, user) = await TargetAsync(actor, userKey, cancellationToken);
        if (outcome != AccountOutcome.Done)
        {
            return outcome;
        }

        if (await RemovesLastSuperAdminAsync(user!, cancellationToken))
        {
            return AccountOutcome.LastSuperAdmin;
        }

        return await users.DeleteAsync(userKey, cancellationToken) ? AccountOutcome.Done : AccountOutcome.NotFound;
    }

    /// <summary>
    /// The first administrator, when there is no account at all: <c>admin</c>, super admin, and a new password
    /// required before anything else works. Its first password is handed in by the host, which takes it from the
    /// bootstrap token file: a vault must not start life with a password everyone knows. Returns whether it was created.
    /// </summary>
    public async Task<bool> EnsureFirstAdminAsync(string firstPassword, CancellationToken cancellationToken)
    {
        if (await users.AnyAsync(cancellationToken))
        {
            return false;
        }

        var user = NewUser(FirstAdminUserName, UserRole.SuperAdmin);
        user.DisplayName = "Administrator";
        user.PasswordHash = hasher.Hash(firstPassword);
        user.MustChangePassword = true;
        return await users.AddAsync(user, cancellationToken);
    }

    /// <summary>A super admin manages every account; an admin manages accounts with the user role; nobody else manages any.</summary>
    public static bool CanManage(AccountActor actor, UserRole targetRole)
    {
        ArgumentNullException.ThrowIfNull(actor);
        return actor.Role == UserRole.SuperAdmin || (actor.Role == UserRole.Admin && targetRole == UserRole.User);
    }

    public static bool IsValidUserName(string? userName) =>
        userName is not null && UserNamePattern().IsMatch(userName.Trim());

    public static string NewStamp() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    /// <summary>
    /// The account another account's change is about, if the actor may change it at all. Not the actor's own account:
    /// changing your own role, disabling or deleting yourself is how an instance loses its last way in.
    /// </summary>
    private async Task<(AccountOutcome Outcome, User? User)> TargetAsync(AccountActor actor, int userKey, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(actor);
        var user = await users.FindAsync(userKey, cancellationToken);
        if (user is null)
        {
            return (AccountOutcome.NotFound, null);
        }

        return user.Key == actor.Key || !CanManage(actor, user.Role) ? (AccountOutcome.Forbidden, null) : (AccountOutcome.Done, user);
    }

    private async Task<bool> RemovesLastSuperAdminAsync(User user, CancellationToken cancellationToken) =>
        user.Role == UserRole.SuperAdmin && !user.IsDisabled && await users.CountActiveSuperAdminsAsync(cancellationToken) <= 1;

    private User NewUser(string userName, UserRole role) => new()
    {
        UserName = userName,
        UserNameLower = userName.ToLowerInvariant(),
        Role = role,
        SecurityStamp = NewStamp(),
        CreatedUtc = time.GetUtcNow().UtcDateTime,
    };

    /// <summary>Letters, digits and <c>. _ - @</c>, so an email address works as a user name; at most 64.</summary>
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex UserNamePattern();
}
