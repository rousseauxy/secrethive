using SecretHive.Application.Ports;
using Microsoft.AspNetCore.Identity;

namespace SecretHive.Infrastructure.Accounts;

/// <summary>
/// ASP.NET Core Identity's password hasher on its own, without the rest of Identity: PBKDF2 with a salt and an
/// iteration count it raises between versions, which is what <see cref="PasswordCheck.SuccessRehashNeeded"/> reports.
/// </summary>
public sealed class PlatformPasswordHasher : Application.Ports.IPasswordHasher
{
    private static readonly object Owner = new();
    private readonly PasswordHasher<object> hasher = new();

    public string Hash(string password) => hasher.HashPassword(Owner, password);

    public PasswordCheck Verify(string hash, string password)
    {
        try
        {
            return hasher.VerifyHashedPassword(Owner, hash, password) switch
            {
                PasswordVerificationResult.Success => PasswordCheck.Success,
                PasswordVerificationResult.SuccessRehashNeeded => PasswordCheck.SuccessRehashNeeded,
                _ => PasswordCheck.Failed,
            };
        }
        catch (FormatException)
        {
            // Not a hash this hasher wrote; nothing to match.
            return PasswordCheck.Failed;
        }
    }
}
