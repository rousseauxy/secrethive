using SecretHive.Domain.Entities;

namespace SecretHive.Application.Ports;

public interface IUserStore
{
    Task<User?> FindAsync(int key, CancellationToken cancellationToken);

    Task<User?> FindByUserNameAsync(string userName, CancellationToken cancellationToken);

    /// <summary>Whether any account has this email address, compared without regard to case.</summary>
    Task<bool> EmailInUseAsync(string email, CancellationToken cancellationToken);

    /// <summary>Every account, ordered by user name.</summary>
    Task<IReadOnlyList<User>> ListAsync(CancellationToken cancellationToken);

    Task<bool> AnyAsync(CancellationToken cancellationToken);

    /// <summary>Super admins that are not disabled: the count the last-super-admin rule is about.</summary>
    Task<int> CountActiveSuperAdminsAsync(CancellationToken cancellationToken);

    /// <summary>Adds the account. False when the user name is taken.</summary>
    Task<bool> AddAsync(User user, CancellationToken cancellationToken);

    /// <summary>Writes every field of an account read earlier. False when it no longer exists.</summary>
    Task<bool> UpdateAsync(User user, CancellationToken cancellationToken);

    /// <summary>
    /// Counts a wrong password in the database itself, so attempts that overlap each count, and locks the account until
    /// <paramref name="lockedUntilUtc"/> once the count reaches <paramref name="maxFailures"/>. True when this call locked it.
    /// </summary>
    Task<bool> RecordFailedSignInAsync(int key, int maxFailures, DateTime lockedUntilUtc, CancellationToken cancellationToken);

    Task<bool> DeleteAsync(int key, CancellationToken cancellationToken);
}

/// <summary>Hashes and checks passwords. An adapter, so the algorithm is the platform's, not ours.</summary>
public interface IPasswordHasher
{
    string Hash(string password);

    PasswordCheck Verify(string hash, string password);
}

public enum PasswordCheck
{
    Failed,
    Success,

    /// <summary>Correct, but hashed with parameters that have since moved on; store a fresh hash.</summary>
    SuccessRehashNeeded,
}
