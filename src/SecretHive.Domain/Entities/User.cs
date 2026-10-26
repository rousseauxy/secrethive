namespace SecretHive.Domain.Entities;

/// <summary>What an account may do beyond its vault roles. Ordered: each role includes the ones before it.</summary>
public enum UserRole
{
    /// <summary>Signs in, manages their own profile and keys; reaches vaults through role assignments.</summary>
    User = 0,

    /// <summary>Creates vaults and manages users, groups, role assignments and service keys.</summary>
    Admin = 1,

    /// <summary>Everything, including admins, sign-in providers and instance settings.</summary>
    SuperAdmin = 2,
}

/// <summary>A person who signs in to the web UI: with a local password, a sign-in provider, or both.</summary>
public sealed class User
{
    public int Key { get; set; }

    public required string UserName { get; set; }

    /// <summary>Lower-cased, for the unique index and for look-ups: user names are not case-sensitive.</summary>
    public required string UserNameLower { get; set; }

    public string DisplayName { get; set; } = "";

    public string Email { get; set; } = "";

    /// <summary>Null for an account that only signs in through a provider.</summary>
    public string? PasswordHash { get; set; }

    public UserRole Role { get; set; } = UserRole.User;

    public bool IsDisabled { get; set; }

    /// <summary>
    /// A machine, not a person: it has no password and cannot sign in to the pages. It holds keys, and roles in
    /// vaults like any account, so what a job read is on record under the job's own name.
    /// </summary>
    public bool IsService { get; set; }

    /// <summary>Set for the first administrator and after a reset: nothing works until a new password is chosen.</summary>
    public bool MustChangePassword { get; set; }

    /// <summary>
    /// Changed whenever what this account may do changes - password, role, disabled - and carried in the sign-in
    /// cookie, so an existing session ends on its next request instead of when the cookie expires.
    /// </summary>
    public required string SecurityStamp { get; set; }

    public int FailedSignIns { get; set; }

    public DateTime? LockedUntilUtc { get; set; }

    public DateTime CreatedUtc { get; set; }

    public DateTime? LastSignInUtc { get; set; }
}
