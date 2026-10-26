using System.Buffers;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Secrets;
using SecretHive.Domain;

namespace SecretHive.Api;

public sealed record PutVaultRequest(string? Description, string? Folder = null);

public sealed record FieldRequest(string Name, string Value, FieldType Type = FieldType.Text, bool Sensitive = false);

/// <summary>
/// A new secret, or a new version of one. What a new version does not name stays as it is: the description, the
/// content type, and every field, ordinary or sensitive. A field sent with an empty value is taken away. With
/// <c>ReplaceDetails</c> the new version is exactly what was sent and nothing else.
/// </summary>
public sealed record PutSecretRequest(string Value, string? ContentType, string? Description, IReadOnlyList<FieldRequest>? Fields, bool ReplaceDetails = false);

public sealed record RestoreRequest(string? Name);

/// <summary>What to look for across vaults: every word has to be found.</summary>
public sealed record SearchRequest(string? Query, int? Take = null);

/// <summary>A role for one account or one group. Exactly one of the two keys is given.</summary>
public sealed record AccessRequest(int? UserKey, int? GroupKey, SecretHive.Domain.Entities.VaultRole Role, string? User = null, string? Group = null);

/// <summary>A group as a tool sends it.</summary>
public sealed record GroupRequest(string? Description);

public sealed record RenameVaultRequest(string? Name);

public sealed record RenameRequest(string? Name);

/// <summary>A pin: a vault, or a secret in it.</summary>
public sealed record PinRequest(string Vault, string? Secret);

/// <summary>A new folder: the folder it goes in (none: at the top) and what it is for.</summary>
public sealed record PutFolderRequest(string? Parent, string? Description);

/// <summary>Where a folder or a vault goes: a folder, or null for the top.</summary>
public sealed record FolderPlaceRequest(string? Folder);

/// <summary>Whoever signs in through this provider while in this group there (for a CI system: this repository) is in the group here.</summary>
public sealed record GroupLinkRequest(string? Provider, string? Group);

/// <summary>A service identity as a tool sends it: a name for a machine, and what it is.</summary>
public sealed record ServiceIdentityRequest(string? Description);

/// <summary>A key to make for a service identity. The answer is the only time the key itself exists outside its owner's hands.</summary>
public sealed record ServiceKeyRequest(string? Label, int? Days, string? Vault, SecretHive.Domain.Entities.VaultRole? MaxRole, IReadOnlyList<string>? Networks, bool NoEndDate = false);

/// <summary>Says who is calling. The host knows how its sign-ins are shaped; the API only asks.</summary>
public interface ICallerResolver
{
    Caller Resolve(HttpContext http);
}

/// <summary>A network group as a tool sends it: its ranges, each written as 192.168.10.0/24 or one address.</summary>
public sealed record NetworkGroupRequest(IReadOnlyList<string>? Ranges, string? Description);

/// <summary>One network to allow for a vault: a group by name, or a literal range. One of the two.</summary>
public sealed record NetworkLineRequest(string? Group, string? Range);

/// <summary>A sign-in provider as a tool sends it. An empty client secret keeps the stored one.</summary>
public sealed record ProviderRequest(
    string? DisplayName,
    string? Authority,
    string? ClientId,
    string? ClientSecret,
    string? Scopes,
    string? UserNameClaim,
    string? GroupsClaim,
    bool? Enabled,
    bool? CreateAccounts,
    string? AllowedEmailDomains,
    bool? AcceptApiTokens = null,
    IReadOnlyList<string>? ApiAudiences = null,
    IReadOnlyList<string>? ApiRequiredClaims = null);

/// <summary>Where a link, a copy or a move goes: a vault, and a name when it should differ from the present one.</summary>
public sealed record TargetRequest(string Vault, string? Name);

/// <summary>The names, as <c>vault/name</c>, the caller expects to delete.</summary>
public sealed record DeleteEverywhereRequest(IReadOnlyList<string>? Expected);

public sealed record PurgeProtectionRequest(bool Enabled);

/// <summary>Days after which bins are emptied; null switches that off.</summary>
public sealed record RetentionRequest(int? Days);

/// <summary>One file of a certificate: <c>content</c> as base64 for any file, or <c>text</c> for a PEM file or a password.</summary>
public sealed record PartRequest(string Kind, string? FileName, string? Content, string? Text);

public sealed record PutCertificateRequest(string? Description, IReadOnlyList<PartRequest>? Parts);

/// <summary>
/// The REST API, version 1. Listing endpoints never touch a value; the two endpoints that return one say so in
/// their path (<c>/value</c>, <c>/fields/{field}</c>) and are the audited reads.
/// </summary>
public static class ApiEndpoints
{
    public static RouteGroupBuilder MapSecretHiveApi(this IEndpointRouteBuilder routes)
    {
        var api = routes.MapGroup("/api/v1").AddEndpointFilter<DomainErrorFilter>();

        api.MapGet("/vaults", (SecretService service, HttpContext http, CancellationToken ct) => service.ListVaultsAsync(CallerOf(http), ct));

        // Across every vault the caller has a role in: names, descriptions and ordinary fields. Never a value.
        // The words travel in the body, not in the address: an address ends up in request logs, and sooner or later
        // somebody pastes a value into a search.
        api.MapPost("/search", (SearchRequest request, SecretService service, HttpContext http, CancellationToken ct) => service.SearchAsync(request.Query, CallerOf(http), request.Take ?? 50, ct));

        api.MapPut("/vaults/{vault}", async (string vault, PutVaultRequest? request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.CreateVaultAsync(vault, request?.Description, CallerOf(http), string.IsNullOrWhiteSpace(request?.Folder) ? null : request.Folder.Trim(), ct);
            return Results.Created($"/api/v1/vaults/{vault}", null);
        });

        // Another name for the vault; what is in it stays. Manifests and references elsewhere have to follow by hand.
        api.MapPost("/vaults/{vault}/rename", async (string vault, RenameVaultRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.RenameVaultAsync(vault, (request.Name ?? "").Trim(), CallerOf(http), ct);
            return Results.Ok(new { name = (request.Name ?? "").Trim() });
        });

        // Only a vault that holds nothing, live or in its bin: this never destroys a value.
        api.MapDelete("/vaults/{vault}", async (string vault, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.DeleteVaultAsync(vault, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapGet("/vaults/{vault}/secrets", (string vault, SecretService service, HttpContext http, CancellationToken ct) => service.ListAsync(vault, CallerOf(http), bin: false, ct));

        api.MapGet("/vaults/{vault}/bin", (string vault, SecretService service, HttpContext http, CancellationToken ct) => service.ListAsync(vault, CallerOf(http), bin: true, ct));

        api.MapPut("/vaults/{vault}/secrets/{name}", async (string vault, string name, PutSecretRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            var fields = (request.Fields ?? []).Select(field => new FieldInput(field.Name, Encoding.UTF8.GetBytes(field.Value ?? ""), field.Type, field.Sensitive)).ToList();
            var version = await service.SetAsync(
                new SetSecret(vault, name, Encoding.UTF8.GetBytes(request.Value ?? ""), request.ContentType, request.Description, fields, Merge: !request.ReplaceDetails),
                CallerOf(http),
                ct);
            return Results.Ok(new { version });
        });

        // "?version=3" reads what the secret held as version 3; without it, the current one.
        api.MapGet("/vaults/{vault}/secrets/{name}/value", (string vault, string name, SecretService service, HttpContext http, CancellationToken ct, int? version = null) =>
            RevealAsync(service, http, vault, name, SecretService.ValueSlot, ct, version));

        api.MapGet("/vaults/{vault}/secrets/{name}/fields/{field}", (string vault, string name, string field, SecretService service, HttpContext http, CancellationToken ct, int? version = null) =>
            RevealAsync(service, http, vault, name, $"field:{field}", ct, version));

        // The history of a secret or a certificate: when each version was made and by whom, never a value.
        api.MapGet("/vaults/{vault}/secrets/{name}/versions", (string vault, string name, SecretService service, HttpContext http, CancellationToken ct) =>
            service.ListVersionsAsync(vault, name, CallerOf(http), ct));

        api.MapPost("/vaults/{vault}/secrets/{name}/versions/{number:int}/restore", async (string vault, string name, int number, SecretService service, HttpContext http, CancellationToken ct) =>
            Results.Ok(new { version = await service.RestoreVersionAsync(vault, name, number, CallerOf(http), ct) }));

        // Certificates share the listing, the bin and delete with secrets; only storing and reading parts differ.
        api.MapPut("/vaults/{vault}/certificates/{name}", async (string vault, string name, PutCertificateRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            var parts = (request.Parts ?? []).Select(part => new CertificatePart(
                CertificateParts.ParseKind(part.Kind),
                part.FileName ?? "",
                part.Text is not null ? Encoding.UTF8.GetBytes(part.Text) : FromBase64(part.Content))).ToList();
            var version = await service.ImportCertificateAsync(new ImportCertificate(vault, name, parts, request.Description), CallerOf(http), ct);
            return Results.Ok(new { version });
        });

        api.MapGet("/vaults/{vault}/certificates/{name}/parts/{kind}", async (string vault, string name, string kind, SecretService service, HttpContext http, CancellationToken ct, int? version = null) =>
        {
            using var part = await service.ReadPartAsync(vault, name, CertificateParts.ParseKind(kind), CallerOf(http), version, ct);
            http.Response.ContentType = "application/octet-stream";
            http.Response.Headers.CacheControl = "no-store";
            if (!string.IsNullOrEmpty(part.FileName))
            {
                http.Response.Headers.ContentDisposition = new System.Net.Mime.ContentDisposition { FileName = part.FileName }.ToString();
            }

            await http.Response.Body.WriteAsync(part.Content.Bytes.Reveal().ToArray(), ct);
        });

        api.MapDelete("/vaults/{vault}/secrets/{name}", async (string vault, string name, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.DeleteAsync(vault, name, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapPost("/vaults/{vault}/bin/{entryId:guid}/restore", async (string vault, Guid entryId, RestoreRequest? request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.RestoreAsync(vault, entryId, CallerOf(http), request?.Name, ct);
            return Results.NoContent();
        });

        // Between vaults. Secrets and certificates alike: the path says "secrets", the name decides.
        // Another name in the same vault; the secret, its versions, links and history stay.
        api.MapPost("/vaults/{vault}/secrets/{name}/rename", async (string vault, string name, RenameRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.RenameSecretAsync(vault, name, (request.Name ?? "").Trim(), CallerOf(http), ct);
            return Results.Ok(new { name = (request.Name ?? "").Trim() });
        });

        api.MapGet("/vaults/{vault}/secrets/{name}/links", (string vault, string name, SecretService service, HttpContext http, CancellationToken ct) =>
            service.LinkedNamesAsync(vault, name, CallerOf(http), ct));

        api.MapPost("/vaults/{vault}/secrets/{name}/link", async (string vault, string name, TargetRequest target, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.LinkAsync(vault, name, target.Vault, target.Name, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapPost("/vaults/{vault}/secrets/{name}/unlink", async (string vault, string name, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.UnlinkAsync(vault, name, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapPost("/vaults/{vault}/secrets/{name}/copy", async (string vault, string name, TargetRequest target, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.CopyAsync(vault, name, target.Vault, target.Name, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapPost("/vaults/{vault}/secrets/{name}/move", async (string vault, string name, TargetRequest target, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.MoveAsync(vault, name, target.Vault, target.Name, CallerOf(http), ct);
            return Results.NoContent();
        });

        // Deleting under every name needs the list of names it is expected to remove, so nothing is removed unseen.
        api.MapPost("/vaults/{vault}/secrets/{name}/delete-everywhere", async (string vault, string name, DeleteEverywhereRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.DeleteEverywhereAsync(vault, name, request.Expected ?? [], CallerOf(http), ct);
            return Results.NoContent();
        });

        // The bins: one overview for the administrator, purge as the only thing that destroys, retention off by default.
        api.MapGet("/bin", (SecretService service, HttpContext http, CancellationToken ct) => service.ListAllBinsAsync(CallerOf(http), ct));

        api.MapDelete("/vaults/{vault}/bin/{entryId:guid}", async (string vault, Guid entryId, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.PurgeAsync(vault, entryId, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapPut("/vaults/{vault}/purge-protection", async (string vault, PurgeProtectionRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.SetPurgeProtectionAsync(vault, request.Enabled, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapGet("/settings/bin-retention", async (SecretService service, CancellationToken ct) => Results.Ok(new { days = await service.GetRetentionDaysAsync(ct) }));

        api.MapPut("/settings/bin-retention", async (RetentionRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.SetRetentionDaysAsync(request.Days, CallerOf(http), ct);
            return Results.NoContent();
        });

        // Your own keys. Making one shows it once; it cannot be read back.
        api.MapGet("/account/keys", (SecretHive.Application.Accounts.KeyService keys, HttpContext http, CancellationToken ct) =>
            CallerOf(http).UserKey is { } owner ? keys.ListAsync(CallerOf(http), owner, ct) : throw new DomainException("access.denied", "This credential is not an identity that holds keys."));

        api.MapDelete("/account/keys/{key:int}", async (int key, SecretHive.Application.Accounts.KeyService keys, HttpContext http, CancellationToken ct) =>
        {
            await keys.RevokeAsync(CallerOf(http), key, ct);
            return Results.NoContent();
        });

        // Network groups, for administrators; and the networks a vault may be used from, for whoever manages its access.
        api.MapGet("/network-groups", (SecretHive.Application.Accounts.NetworkService networks, HttpContext http, CancellationToken ct) => networks.ListAsync(CallerOf(http), ct));

        api.MapPut("/network-groups/{name}", async (string name, NetworkGroupRequest request, SecretHive.Application.Accounts.NetworkService networks, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var ranges = string.Join('\n', request.Ranges ?? []);
            if ((await networks.ListAsync(caller, ct)).FirstOrDefault(group => string.Equals(group.Name, name, StringComparison.OrdinalIgnoreCase)) is { } existing)
            {
                await networks.UpdateAsync(existing.Key, request.Description ?? existing.Description, ranges, caller, ct);
                return Results.NoContent();
            }

            await networks.CreateAsync(name, request.Description, ranges, caller, ct);
            return Results.Created($"/api/v1/network-groups/{name}", null);
        });

        api.MapDelete("/network-groups/{name}", async (string name, SecretHive.Application.Accounts.NetworkService networks, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var group = (await networks.ListAsync(caller, ct)).FirstOrDefault(candidate => string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase));
            if (group is null)
            {
                return Results.NotFound();
            }

            await networks.DeleteAsync(group.Key, caller, ct);
            return Results.NoContent();
        });

        api.MapGet("/vaults/{vault}/networks", (string vault, SecretService service, HttpContext http, CancellationToken ct) => service.ListNetworksAsync(vault, CallerOf(http), ct));

        api.MapPost("/vaults/{vault}/networks", async (string vault, NetworkLineRequest request, SecretService service, SecretHive.Application.Accounts.NetworkService networks, HttpContext http, CancellationToken ct) =>
        {
            int? groupKey = null;
            if (!string.IsNullOrWhiteSpace(request.Group))
            {
                groupKey = (await networks.ListNamesAsync(ct)).Where(group => string.Equals(group.Name, request.Group.Trim(), StringComparison.OrdinalIgnoreCase)).Select(group => (int?)group.Key).FirstOrDefault()
                    ?? throw new DomainException("network.group.not_found", "That network group does not exist.");
            }

            await service.AllowNetworkAsync(vault, groupKey, request.Range, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapDelete("/vaults/{vault}/networks/{line:int}", async (string vault, int line, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.DisallowNetworkAsync(vault, line, CallerOf(http), ct);
            return Results.NoContent();
        });

        // Sign-in providers, for a super admin. What comes back says whether a client secret is stored, never the secret.
        api.MapGet("/providers", async (SecretHive.Application.Accounts.ProviderService providers, HttpContext http, CancellationToken ct) =>
            (await providers.ListAsync(CallerOf(http), ct)).Select(provider => new
            {
                provider.Key,
                provider.Slug,
                provider.DisplayName,
                provider.Authority,
                provider.ClientId,
                hasClientSecret = providers.HasSecret(provider),
                provider.Scopes,
                provider.UserNameClaim,
                provider.GroupsClaim,
                provider.Enabled,
                provider.CreateAccounts,
                provider.AllowedEmailDomains,
                provider.AcceptApiTokens,
                apiAudiences = SecretHive.Domain.Entities.OidcProvider.ParseAudiences(provider.ApiAudiences),
                apiRequiredClaims = provider.ApiRequiredClaims.Split('\n', StringSplitOptions.RemoveEmptyEntries),
            }));

        api.MapPut("/providers/{slug}", async (string slug, ProviderRequest request, SecretHive.Application.Accounts.ProviderService providers, HttpContext http, CancellationToken ct) =>
        {
            var settings = new SecretHive.Application.Accounts.ProviderSettings(
                request.DisplayName ?? slug,
                slug,
                request.Authority ?? "",
                request.ClientId ?? "",
                request.ClientSecret,
                request.Scopes ?? SecretHive.Domain.Entities.OidcProvider.DefaultScopes,
                request.UserNameClaim ?? SecretHive.Domain.Entities.OidcProvider.DefaultUserNameClaim,
                request.GroupsClaim ?? "",
                request.Enabled ?? true,
                request.CreateAccounts ?? false,
                request.AllowedEmailDomains ?? "",
                AcceptApiTokens: request.AcceptApiTokens ?? false,
                ApiAudiences: string.Join('\n', request.ApiAudiences ?? []),
                ApiRequiredClaims: string.Join('\n', request.ApiRequiredClaims ?? []));
            var caller = CallerOf(http);
            if ((await providers.ListAsync(caller, ct)).FirstOrDefault(provider => provider.Slug == slug) is { } existing)
            {
                await providers.UpdateAsync(existing.Key, settings, caller, ct);
                return Results.NoContent();
            }

            await providers.CreateAsync(settings, caller, ct);
            return Results.Created($"/api/v1/providers/{slug}", null);
        });

        api.MapDelete("/providers/{slug}", async (string slug, SecretHive.Application.Accounts.ProviderService providers, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var provider = (await providers.ListAsync(caller, ct)).FirstOrDefault(candidate => candidate.Slug == slug);
            if (provider is null)
            {
                return Results.NotFound();
            }

            await providers.DeleteAsync(provider.Key, caller, ct);
            return Results.NoContent();
        });

        // The newest first; with before, the rows older than that id: the next page back.
        api.MapGet("/audit", (SecretService service, HttpContext http, CancellationToken ct, int take = 100, long? before = null) => service.AuditAsync(take, CallerOf(http), before: before, cancellationToken: ct));

        // What happened in one vault, or to one secret in it.
        api.MapGet("/vaults/{vault}/audit", (string vault, SecretService service, HttpContext http, CancellationToken ct, string? secret = null, int take = 100, long? before = null) =>
            service.AuditAsync(take, CallerOf(http), vault, secret, before, ct));

        // Who holds which role in a vault. For the vault's admins, and for instance administrators.
        api.MapGet("/vaults/{vault}/access", (string vault, SecretService service, HttpContext http, CancellationToken ct) =>
            service.ListAccessAsync(vault, CallerOf(http), ct));

        api.MapPut("/vaults/{vault}/access", async (string vault, AccessRequest request, SecretService service, SecretHive.Application.Ports.IUserStore users, SecretHive.Application.Ports.IAccessStore access, HttpContext http, CancellationToken ct) =>
        {
            var (userKey, groupKey) = await TargetOfAsync(request, users, access, ct);
            await service.AssignAsync(vault, userKey, groupKey, request.Role, CallerOf(http), ct);
            return Results.NoContent();
        });

        // Groups, and which group at a provider (for a CI system: which repository) puts a caller in one.
        api.MapPut("/groups/{name}", async (string name, GroupRequest? request, SecretHive.Application.Accounts.GroupService groups, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            if ((await groups.ListAsync(caller, ct)).FirstOrDefault(group => string.Equals(group.Name, name, StringComparison.OrdinalIgnoreCase)) is { } existing)
            {
                return Results.Ok(new { key = existing.Key, name = existing.Name });
            }

            await groups.CreateAsync(name, request?.Description, caller, ct);
            var made = (await groups.ListAsync(caller, ct)).First(group => string.Equals(group.Name, name, StringComparison.OrdinalIgnoreCase));
            return Results.Created($"/api/v1/groups/{name}", new { key = made.Key, name = made.Name });
        });

        api.MapPut("/groups/{name}/provider-links", async (string name, GroupLinkRequest request, SecretHive.Application.Accounts.GroupService groups, SecretHive.Application.Accounts.ProviderService providers, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var group = (await groups.ListAsync(caller, ct)).FirstOrDefault(candidate => string.Equals(candidate.Name, name, StringComparison.OrdinalIgnoreCase))
                ?? throw new DomainException("group.not_found", "That group does not exist.");
            var provider = (await providers.ListAsync(caller, ct)).FirstOrDefault(candidate => string.Equals(candidate.Slug, (request.Provider ?? "").Trim(), StringComparison.OrdinalIgnoreCase))
                ?? throw new DomainException("provider.not_found", "That provider does not exist.");
            if ((await providers.ListLinksAsync(caller, ct)).Any(link => link.GroupKey == group.Key && link.ProviderKey == provider.Key && string.Equals(link.ProviderGroup, (request.Group ?? "").Trim(), StringComparison.Ordinal)))
            {
                return Results.NoContent();
            }

            await providers.LinkGroupAsync(group.Key, provider.Key, request.Group ?? "", caller, ct);
            return Results.NoContent();
        });

        // Service identities and their keys, for an administrator setting a host up from a script. What a page can do.
        api.MapPut("/service-identities/{name}", async (string name, ServiceIdentityRequest? request, SecretHive.Application.Accounts.AccountService accounts, SecretHive.Application.Ports.IUserStore users, SecretHive.Application.Accounts.AuditWriter audit, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            if (!caller.IsInstanceAdmin)
            {
                throw new DomainException("access.denied", "Only an administrator makes service identities.");
            }

            if (await users.FindByUserNameAsync(name, ct) is { } existing)
            {
                return existing.IsService
                    ? Results.Ok(new { key = existing.Key, name = existing.UserName })
                    : Results.Problem(detail: $"'{name}' is a person's account, not a service identity.", statusCode: StatusCodes.Status409Conflict);
            }

            var actor = caller.Unrestricted ? new SecretHive.Application.Accounts.AccountActor(-1, SecretHive.Domain.Entities.UserRole.SuperAdmin) : new SecretHive.Application.Accounts.AccountActor(caller.UserKey ?? -1, caller.Role);
            var (outcome, user) = await accounts.CreateServiceAsync(actor, name, request?.Description ?? "", ct);
            if (outcome != SecretHive.Application.Accounts.AccountOutcome.Done)
            {
                throw new DomainException("service.invalid", outcome == SecretHive.Application.Accounts.AccountOutcome.InvalidName ? "A service identity's name is letters, digits, dots, dashes and underscores, at most 64." : $"The service identity could not be made ({outcome}).");
            }

            await audit.RecordAsync("service.created", caller, name, cancellationToken: ct);
            return Results.Created($"/api/v1/service-identities/{name}", new { key = user!.Key, name = user.UserName });
        });

        api.MapPost("/service-identities/{name}/keys", async (string name, ServiceKeyRequest request, SecretHive.Application.Accounts.KeyService keys, SecretHive.Application.Accounts.NetworkService networks, SecretHive.Application.Ports.IUserStore users, HttpContext http, CancellationToken ct) =>
        {
            var caller = CallerOf(http);
            var owner = await users.FindByUserNameAsync(name, ct);
            if (owner is not { IsService: true })
            {
                throw new DomainException("user.not_found", "That service identity does not exist.");
            }

            var (made, secret) = await keys.CreateAsync(caller, owner.Key, request.Label ?? "", request.NoEndDate ? null : request.Days ?? SecretHive.Application.Accounts.KeyService.DefaultDays, request.Vault, request.MaxRole, ct);

            // Each network is a group by name or a literal range. A key that was asked to be limited is never left unlimited.
            try
            {
                foreach (var network in request.Networks ?? [])
                {
                    var group = (await networks.ListNamesAsync(ct)).Where(candidate => string.Equals(candidate.Name, network.Trim(), StringComparison.OrdinalIgnoreCase)).Select(candidate => (int?)candidate.Key).FirstOrDefault();
                    await keys.AllowNetworkAsync(caller, made.Key, group, group is null ? network : null, ct);
                }
            }
            catch (DomainException)
            {
                await keys.RevokeAsync(caller, made.Key, ct);
                throw;
            }

            http.Response.Headers.CacheControl = "no-store";
            return Results.Ok(new { key = secret, prefix = made.Prefix, expiresUtc = made.ExpiresUtc });
        });

        api.MapDelete("/vaults/{vault}/access", async (string vault, SecretService service, HttpContext http, CancellationToken ct, int? userKey = null, int? groupKey = null) =>
        {
            await service.UnassignAsync(vault, userKey, groupKey, CallerOf(http), ct);
            return Results.NoContent();
        });

        // The caller's own pins: what their home page keeps at hand. Seeing what is pinned is all it takes.
        api.MapGet("/pins", async (SecretService service, HttpContext http, CancellationToken ct) =>
            (await service.ListPinsAsync(CallerOf(http), ct)).Select(pin => new { vault = pin.Vault, secret = pin.Secret }));

        api.MapPut("/pins", async (PinRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.SetPinAsync(request.Vault, string.IsNullOrWhiteSpace(request.Secret) ? null : request.Secret, true, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapDelete("/pins", async (string vault, SecretService service, HttpContext http, CancellationToken ct, string? secret = null) =>
        {
            await service.SetPinAsync(vault, string.IsNullOrWhiteSpace(secret) ? null : secret, false, CallerOf(http), ct);
            return Results.NoContent();
        });

        // Folders of vaults, for administrators. A role given on a folder counts in every vault beneath it.
        api.MapGet("/folders", (SecretService service, HttpContext http, CancellationToken ct) => service.ListFoldersAsync(CallerOf(http), ct));

        api.MapPut("/folders/{folder}", async (string folder, PutFolderRequest? request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.CreateFolderAsync(folder, string.IsNullOrWhiteSpace(request?.Parent) ? null : request.Parent.Trim(), request?.Description, CallerOf(http), ct);
            return Results.Created($"/api/v1/folders/{folder}", null);
        });

        api.MapPost("/folders/{folder}/rename", async (string folder, RenameRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.RenameFolderAsync(folder, (request.Name ?? "").Trim(), CallerOf(http), ct);
            return Results.Ok(new { name = (request.Name ?? "").Trim() });
        });

        api.MapPost("/folders/{folder}/move", async (string folder, FolderPlaceRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.MoveFolderAsync(folder, string.IsNullOrWhiteSpace(request.Folder) ? null : request.Folder.Trim(), CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapDelete("/folders/{folder}", async (string folder, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.DeleteFolderAsync(folder, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapGet("/folders/{folder}/access", (string folder, SecretService service, HttpContext http, CancellationToken ct) =>
            service.ListFolderAccessAsync(folder, CallerOf(http), ct));

        api.MapPut("/folders/{folder}/access", async (string folder, AccessRequest request, SecretService service, SecretHive.Application.Ports.IUserStore users, SecretHive.Application.Ports.IAccessStore access, HttpContext http, CancellationToken ct) =>
        {
            var (userKey, groupKey) = await TargetOfAsync(request, users, access, ct);
            await service.AssignFolderAsync(folder, userKey, groupKey, request.Role, CallerOf(http), ct);
            return Results.NoContent();
        });

        api.MapDelete("/folders/{folder}/access", async (string folder, SecretService service, HttpContext http, CancellationToken ct, int? userKey = null, int? groupKey = null) =>
        {
            await service.UnassignFolderAsync(folder, userKey, groupKey, CallerOf(http), ct);
            return Results.NoContent();
        });

        // Which folder a vault is in; null puts it at the top. Who reaches it can change with it, and the trail says how.
        api.MapPut("/vaults/{vault}/folder", async (string vault, FolderPlaceRequest request, SecretService service, HttpContext http, CancellationToken ct) =>
        {
            await service.MoveVaultToFolderAsync(vault, string.IsNullOrWhiteSpace(request.Folder) ? null : request.Folder.Trim(), CallerOf(http), ct);
            return Results.NoContent();
        });

        // Accounts, service identities with their keys, and groups with their members: what the admin pages do.
        api.MapAccounts();

        return api;
    }

    /// <summary>
    /// The account or group a role is for: by key, or by name. A script knows the name it gave an identity, not the
    /// number the server gave it.
    /// </summary>
    private static async Task<(int? UserKey, int? GroupKey)> TargetOfAsync(AccessRequest request, SecretHive.Application.Ports.IUserStore users, SecretHive.Application.Ports.IAccessStore access, CancellationToken ct)
    {
        var userKey = request.UserKey;
        var groupKey = request.GroupKey;
        if (!string.IsNullOrWhiteSpace(request.User))
        {
            userKey = (await users.FindByUserNameAsync(request.User.Trim(), ct))?.Key ?? throw new DomainException("access.target.not_found", "That account or group does not exist.");
        }

        if (!string.IsNullOrWhiteSpace(request.Group))
        {
            groupKey = (await access.ListGroupsAsync(ct)).FirstOrDefault(group => string.Equals(group.Name, request.Group.Trim(), StringComparison.OrdinalIgnoreCase))?.Key
                ?? throw new DomainException("access.target.not_found", "That account or group does not exist.");
        }

        return (userKey, groupKey);
    }

    /// <summary>
    /// Writes the value into the response as bytes. It is never turned into a managed string on the way out, so
    /// there is nothing for a log line or an exception message to pick up.
    /// </summary>
    private static async Task RevealAsync(SecretService service, HttpContext http, string vault, string name, string slot, CancellationToken ct, int? version = null)
    {
        using var revealed = await service.RevealAsync(vault, name, CallerOf(http), slot, version, ct);
        var buffer = new ArrayBufferWriter<byte>();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("value"u8, revealed.Bytes.Reveal());
            writer.WriteNumber("version"u8, revealed.Version);
            writer.WriteString("versionId"u8, revealed.VersionId);
            writer.WriteEndObject();
        }

        http.Response.ContentType = "application/json";
        http.Response.Headers.CacheControl = "no-store";
        await http.Response.Body.WriteAsync(buffer.WrittenMemory, ct);
    }

    private static byte[] FromBase64(string? content)
    {
        try
        {
            return Convert.FromBase64String(content ?? "");
        }
        catch (FormatException)
        {
            throw new DomainException("certificate.part.encoding", "A part's content must be base64, or be given as text.");
        }
    }

    private static Caller CallerOf(HttpContext http) => http.RequestServices.GetRequiredService<ICallerResolver>().Resolve(http);

    /// <summary>A broken rule becomes a problem document with the rule's stable code; nothing else about the request is echoed.</summary>
    private sealed class DomainErrorFilter : IEndpointFilter
    {
        public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
        {
            try
            {
                return await next(context);
            }
            catch (DomainException e)
            {
                var status = e.Code switch
                {
                    _ when e.Code.EndsWith(".not_found", StringComparison.Ordinal) || e.Code == "secret.not_in_bin" => StatusCodes.Status404NotFound,
                    "vault.exists" or "vault.rename.same" or "vault.folder.same" or "folder.exists" or "folder.rename.same" or "folder.move.same" or "folder.move.circle" or "folder.not_empty" or "secret.rename.same" or "secret.name.taken" or "secret.links.changed" or "vault.purge_protected" or "secret.version.current" or "group.exists" or "provider.exists" or "provider.link.exists" or "network.group.exists" or "network.group.in_use" or "network.line.exists" or "user.exists" or "user.last_super_admin" => StatusCodes.Status409Conflict,
                    "access.denied" or "access.network.refused" => StatusCodes.Status403Forbidden,
                    "key.not_found" => StatusCodes.Status404NotFound,
                    _ => StatusCodes.Status400BadRequest,
                };
                return Results.Problem(detail: e.Message, statusCode: status, extensions: new Dictionary<string, object?> { ["code"] = e.Code });
            }
        }
    }
}
