using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Accounts;
using SecretHive.Application.Ports;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Api;

/// <summary>A person's account as a tool sends it. The first password is replaced at the first sign-in.</summary>
public sealed record PutUserRequest(string? DisplayName, string? Email, UserRole? Role, string? Password);

public sealed record RoleRequest(UserRole Role);

public sealed record DisabledRequest(bool Disabled);

/// <summary>The highest role a key acts with; null lets it follow its owner's role.</summary>
public sealed record KeyLimitRequest(VaultRole? MaxRole);

/// <summary>A new first password for someone else; they choose their own at their next sign-in.</summary>
public sealed record PasswordRequest(string? Password);

/// <summary>
/// What the pages do that is not about a vault, for a script: accounts, service identities and their keys, groups
/// and their members. The same rules as the pages, through the same services, with the same audit codes.
/// </summary>
/// <remarks>
/// Who may call: an administrator's session (GET only, like the rest of the API) and the bootstrap token. A key
/// manages nothing, and a token from a sign-in provider is no account: both are refused here before anything is
/// looked at. A person's own profile, password and keys are made on the pages with their session; a key that could
/// make keys would be a key that outlives its revocation.
/// </remarks>
public static class AccountEndpoints
{
    public static RouteGroupBuilder MapAccounts(this RouteGroupBuilder api)
    {
        // Accounts of people. Service identities are on their own routes below.
        api.MapGet("/users", async (IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            Actor(http);
            return (await users.ListAsync(ct)).Where(user => !user.IsService).Select(Shown);
        });

        api.MapPut("/users/{name}", async (string name, PutUserRequest? request, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var actor = Actor(http);
            if (await users.FindByUserNameAsync(name, ct) is { } existing)
            {
                return existing.IsService
                    ? Results.Problem(detail: $"'{name}' is a service identity, not a person's account.", statusCode: StatusCodes.Status409Conflict, extensions: Code("user.exists"))
                    : Results.Problem(detail: $"An account named '{name}' already exists.", statusCode: StatusCodes.Status409Conflict, extensions: Code("user.exists"));
            }

            var role = request?.Role ?? UserRole.User;
            var (outcome, user) = await accounts.CreateAsync(actor, name, request?.DisplayName ?? "", request?.Email ?? "", role, request?.Password ?? "", ct);
            Require(outcome);
            await audit.RecordAsync("user.created", caller, $"{user!.UserName} role={RoleName(role)}", role >= UserRole.Admin ? AuditSeverity.Security : AuditSeverity.Info, cancellationToken: ct);
            return Results.Created($"/api/v1/users/{user.UserName}", Shown(user));
        });

        api.MapPut("/users/{name}/role", async (string name, RoleRequest request, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var user = await PersonAsync(users, name, ct);
            var was = user.Role;
            Require(await accounts.SetRoleAsync(Actor(http), user.Key, request.Role, ct));
            if (was != request.Role)
            {
                await audit.RecordAsync("user.role.changed", CallerOf(http), $"{user.UserName} {RoleName(was)} -> {RoleName(request.Role)}", request.Role >= UserRole.Admin ? AuditSeverity.Security : AuditSeverity.Notice, cancellationToken: ct);
            }

            return Results.NoContent();
        });

        api.MapPut("/users/{name}/disabled", async (string name, DisabledRequest request, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var user = await PersonAsync(users, name, ct);
            Require(await accounts.SetDisabledAsync(Actor(http), user.Key, request.Disabled, ct));
            await audit.RecordAsync(request.Disabled ? "user.disabled" : "user.enabled", CallerOf(http), user.UserName, AuditSeverity.Notice, cancellationToken: ct);
            return Results.NoContent();
        });

        // The password itself is in the request body and nowhere else: not in the path, not in a row.
        api.MapPut("/users/{name}/password", async (string name, PasswordRequest request, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var user = await PersonAsync(users, name, ct);
            Require(await accounts.ResetPasswordAsync(Actor(http), user.Key, request.Password ?? "", ct));
            await audit.RecordAsync("user.password.reset", CallerOf(http), user.UserName, AuditSeverity.Security, cancellationToken: ct);
            return Results.NoContent();
        });

        api.MapDelete("/users/{name}", async (string name, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var user = await PersonAsync(users, name, ct);
            Require(await accounts.DeleteAsync(Actor(http), user.Key, ct));
            await audit.RecordAsync("user.deleted", CallerOf(http), user.UserName, AuditSeverity.Notice, cancellationToken: ct);
            return Results.NoContent();
        });

        // Service identities: the list, and what the tokens page does to one besides making it.
        // A service identity's instance role: User, or Admin so that its keys can do what an admin does. A super admin
        // decides, and widening is a security event.
        api.MapPut("/service-identities/{name}/role", async (string name, RoleRequest request, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            var was = service.Role;
            Require(await accounts.SetServiceRoleAsync(Actor(http), service.Key, request.Role, ct));
            if (was != request.Role)
            {
                await audit.RecordAsync("service.role.changed", CallerOf(http), $"{service.UserName} {RoleName(was)} -> {RoleName(request.Role)}", request.Role >= UserRole.Admin ? AuditSeverity.Security : AuditSeverity.Notice, cancellationToken: ct);
            }

            return Results.NoContent();
        });

        api.MapGet("/service-identities", async (IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            Actor(http);
            return (await users.ListAsync(ct)).Where(user => user.IsService).Select(Shown);
        });

        api.MapPut("/service-identities/{name}/disabled", async (string name, DisabledRequest request, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            Require(await accounts.SetDisabledAsync(Actor(http), service.Key, request.Disabled, ct));
            await audit.RecordAsync(request.Disabled ? "service.disabled" : "service.enabled", CallerOf(http), service.UserName, AuditSeverity.Notice, cancellationToken: ct);
            return Results.NoContent();
        });

        api.MapDelete("/service-identities/{name}", async (string name, AccountService accounts, IUserStore users, AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            Require(await accounts.DeleteAsync(Actor(http), service.Key, ct));
            await audit.RecordAsync("service.deleted", CallerOf(http), service.UserName, AuditSeverity.Notice, cancellationToken: ct);
            return Results.NoContent();
        });

        // A service identity's keys: never the key itself, only its prefix, limits and use.
        api.MapGet("/service-identities/{name}/keys", async (string name, KeyService keys, IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            return await keys.ListAsync(CallerOf(http), service.Key, ct);
        });

        api.MapDelete("/service-identities/{name}/keys/{key:int}", async (string name, int key, KeyService keys, IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            await RequireKeyOfAsync(keys, http, service, key, ct);
            await keys.RevokeAsync(CallerOf(http), key, ct);
            return Results.NoContent();
        });

        api.MapPut("/service-identities/{name}/keys/{key:int}/max-role", async (string name, int key, KeyLimitRequest request, KeyService keys, IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            await RequireKeyOfAsync(keys, http, service, key, ct);
            await keys.SetMaxRoleAsync(CallerOf(http), key, request.MaxRole, ct);
            return Results.NoContent();
        });

        api.MapPost("/service-identities/{name}/keys/{key:int}/networks", async (string name, int key, NetworkLineRequest request, KeyService keys, NetworkService networks, IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            await RequireKeyOfAsync(keys, http, service, key, ct);
            await keys.AllowNetworkAsync(CallerOf(http), key, await GroupKeyAsync(networks, request.Group, ct), request.Range, ct);
            return Results.NoContent();
        });

        api.MapDelete("/service-identities/{name}/keys/{key:int}/networks/{line:int}", async (string name, int key, int line, KeyService keys, IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var service = await ServiceAsync(users, name, ct);
            await RequireKeyOfAsync(keys, http, service, key, ct);
            await keys.DisallowNetworkAsync(CallerOf(http), key, line, ct);
            return Results.NoContent();
        });

        // Groups: what exists with its members, and the members and links that change.
        api.MapGet("/groups", async (GroupService groups, ProviderService providers, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var links = await providers.ListLinksAsync(caller, ct);
            return (await groups.ListAsync(caller, ct)).Select(group => new
            {
                group.Key,
                group.Name,
                group.Description,
                members = group.Members.Select(member => new { user = member.UserName, member.Source }),
                providerLinks = links.Where(link => link.GroupKey == group.Key).Select(link => new { link.Key, provider = link.ProviderName, group = link.ProviderGroup }),
            });
        });

        api.MapDelete("/groups/{name}", async (string name, GroupService groups, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            await groups.DeleteAsync((await GroupAsync(groups, caller, name, ct)).Key, caller, ct);
            return Results.NoContent();
        });

        api.MapPut("/groups/{name}/members/{user}", async (string name, string user, GroupService groups, IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var group = await GroupAsync(groups, caller, name, ct);
            var member = await users.FindByUserNameAsync(user, ct) ?? throw new DomainException("user.not_found", "That account does not exist.");
            await groups.AddMemberAsync(group.Key, member.Key, caller, ct);
            return Results.NoContent();
        });

        api.MapDelete("/groups/{name}/members/{user}", async (string name, string user, GroupService groups, IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var group = await GroupAsync(groups, caller, name, ct);
            var member = await users.FindByUserNameAsync(user, ct) ?? throw new DomainException("user.not_found", "That account does not exist.");
            await groups.RemoveMemberAsync(group.Key, member.Key, caller, ct);
            return Results.NoContent();
        });

        api.MapDelete("/groups/{name}/provider-links/{link:int}", async (string name, int link, GroupService groups, ProviderService providers, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            await providers.UnlinkGroupAsync((await GroupAsync(groups, caller, name, ct)).Key, link, caller, ct);
            return Results.NoContent();
        });

        return api;
    }

    private static Caller CallerOf(HttpContext http) => http.RequestServices.GetRequiredService<ICallerResolver>().Resolve(http);

    /// <summary>
    /// The account rules want an actor: the bootstrap token acts as a super admin, a signed-in administrator as
    /// what they are, the key of a service identity that is an admin as an admin. Any other key, and a provider
    /// token, is refused: neither manages accounts.
    /// </summary>
    private static AccountActor Actor(HttpContext http)
    {
        var caller = CallerOf(http);
        if (caller.Unrestricted)
        {
            return new AccountActor(-1, UserRole.SuperAdmin);
        }

        if (caller.IsInstanceAdmin && caller.UserKey is { } key)
        {
            return new AccountActor(key, caller.Role);
        }

        throw new DomainException("access.denied", "Accounts, identities and groups are managed by an administrator or the bootstrap token; a key manages nothing unless its service identity is an admin, and a token never does.");
    }

    private static void Require(AccountOutcome outcome)
    {
        if (outcome == AccountOutcome.Done)
        {
            return;
        }

        throw outcome switch
        {
            AccountOutcome.Forbidden => new DomainException("access.denied", "Your role does not reach that account, or it is your own."),
            AccountOutcome.NotFound => new DomainException("user.not_found", "That account does not exist."),
            AccountOutcome.NameTaken => new DomainException("user.exists", "That name is taken."),
            AccountOutcome.InvalidName => new DomainException("user.name.invalid", "A user name is letters, digits and . _ - @ only, starting with a letter or a digit, at most 64."),
            AccountOutcome.PasswordTooShort => new DomainException("user.password.short", $"A password is at least {AccountService.MinimumPasswordLength} characters."),
            AccountOutcome.LastSuperAdmin => new DomainException("user.last_super_admin", "That would leave no super admin who can sign in."),
            _ => new DomainException("user.invalid", $"The account could not be changed ({outcome})."),
        };
    }

    private static async Task<User> PersonAsync(IUserStore users, string name, CancellationToken ct) =>
        await users.FindByUserNameAsync(name, ct) is { IsService: false } user ? user : throw new DomainException("user.not_found", "That account does not exist.");

    private static async Task<User> ServiceAsync(IUserStore users, string name, CancellationToken ct) =>
        await users.FindByUserNameAsync(name, ct) is { IsService: true } user ? user : throw new DomainException("user.not_found", "That service identity does not exist.");

    /// <summary>A key named under one identity is that identity's, or it does not exist as far as the route can tell.</summary>
    private static async Task RequireKeyOfAsync(KeyService keys, HttpContext http, User owner, int key, CancellationToken ct)
    {
        if ((await keys.ListAsync(CallerOf(http), owner.Key, ct)).All(candidate => candidate.Key != key))
        {
            throw new DomainException("key.not_found", "That key does not exist.");
        }
    }

    private static async Task<GroupSummary> GroupAsync(GroupService groups, Caller caller, string name, CancellationToken ct) =>
        (await groups.ListAsync(caller, ct)).FirstOrDefault(group => string.Equals(group.Name, name, StringComparison.OrdinalIgnoreCase))
        ?? throw new DomainException("group.not_found", "That group does not exist.");

    private static async Task<int?> GroupKeyAsync(NetworkService networks, string? group, CancellationToken ct) =>
        string.IsNullOrWhiteSpace(group)
            ? null
            : (await networks.ListNamesAsync(ct)).Where(candidate => string.Equals(candidate.Name, group.Trim(), StringComparison.OrdinalIgnoreCase)).Select(candidate => (int?)candidate.Key).FirstOrDefault()
                ?? throw new DomainException("network.group.not_found", "That network group does not exist.");

    private static object Shown(User user) => new
    {
        user.Key,
        user.UserName,
        user.DisplayName,
        user.Email,
        role = user.Role.ToString(),
        user.IsDisabled,
        user.IsService,
        user.MustChangePassword,
        lockedUntilUtc = user.LockedUntilUtc > DateTime.UtcNow ? user.LockedUntilUtc : null,
        user.LastSignInUtc,
        user.CreatedUtc,
    };

    private static string RoleName(UserRole role) => role switch
    {
        UserRole.SuperAdmin => "super admin",
        UserRole.Admin => "admin",
        _ => "user",
    };

    private static Dictionary<string, object?> Code(string code) => new(StringComparer.Ordinal) { ["code"] = code };
}
