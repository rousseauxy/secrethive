using System.Buffers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using SecretHive.Application.Secrets;
using SecretHive.Domain;
using SecretHive.Domain.Entities;

namespace SecretHive.Api;

/// <summary>
/// The read side of the 1Password Connect API, for a tool that can only fetch secrets that way: Termix's Secret
/// Sources plugin resolves <c>op://vault/item/field</c> with exactly these three calls. A vault is a vault, an item
/// is a secret, its fields are the value (<c>password</c>), its ordinary fields and its sensitive fields. Names are
/// the ids. Nothing can be changed here, and certificates are not offered.
/// </summary>
/// <remarks>
/// The caller is whoever the bearer key belongs to, with that key's limits, as on the rest of the API. Lists never
/// carry a value. The item call hands over every value of the secret, because the client picks the field it wants
/// only afterwards; each of them is an audited read, so one connection through Termix is one row per value.
/// </remarks>
public static partial class OnePasswordConnectEndpoints
{
    public const string BasePath = "/api/1password-connect";

    public static RouteGroupBuilder MapOnePasswordConnect(this IEndpointRouteBuilder routes)
    {
        var connect = routes.MapGroup(BasePath + "/v1");

        connect.MapGet("/vaults", async (SecretService service, HttpContext http, CancellationToken ct, string? filter = null) =>
            await Answer(async () =>
            {
                var title = TitleOf(filter);
                var vaults = await service.ListVaultsAsync(CallerOf(http), ct);
                return Results.Ok(vaults
                    .Where(vault => title is null || string.Equals(vault.Name, title, StringComparison.OrdinalIgnoreCase))
                    .Select(vault => new
                    {
                        id = vault.Name,
                        name = vault.Name,
                        description = vault.Description ?? "",
                        type = "USER_CREATED",
                        createdAt = vault.CreatedUtc,
                    }));
            }));

        connect.MapGet("/vaults/{vault}/items", async (string vault, SecretService service, HttpContext http, CancellationToken ct, string? filter = null) =>
            await Answer(async () =>
            {
                var title = TitleOf(filter);
                var secrets = await service.ListAsync(vault, CallerOf(http), bin: false, ct);
                return Results.Ok(secrets
                    .Where(secret => secret.Kind == ValueKind.Secret && (title is null || string.Equals(secret.Name, title, StringComparison.OrdinalIgnoreCase)))
                    .Select(secret => Summary(vault, secret)));
            }));

        connect.MapGet("/vaults/{vault}/items/{item}", async (string vault, string item, SecretService service, HttpContext http, CancellationToken ct) =>
            await Answer(async () =>
            {
                var caller = CallerOf(http);
                var secret = (await service.ListAsync(vault, caller, bin: false, ct))
                    .FirstOrDefault(candidate => candidate.Kind == ValueKind.Secret && string.Equals(candidate.Name, item, StringComparison.OrdinalIgnoreCase))
                    ?? throw new DomainException("secret.not_found", $"There is no secret '{item}' in '{vault}'.");
                await WriteItemAsync(http, service, caller, vault, secret, ct);
                return Results.Empty;
            }));

        return connect;
    }

    private static object Summary(string vault, SecretSummary secret) => new
    {
        id = secret.Name,
        title = secret.Name,
        vault = new { id = vault },
        category = "PASSWORD",
        version = secret.Version,
        updatedAt = secret.VersionCreatedUtc,
    };

    /// <summary>
    /// The item with its fields, values included: written as bytes into the response, never made into a managed
    /// string, as the value endpoint of the API does. Every value is read, and recorded, before the first byte goes.
    /// </summary>
    private static async Task WriteItemAsync(HttpContext http, SecretService service, Caller caller, string vault, SecretSummary secret, CancellationToken ct)
    {
        var reads = new List<(string Name, Revealed Read)>();
        try
        {
            reads.Add(("password", await service.RevealAsync(vault, secret.Name, caller, SecretService.ValueSlot, cancellationToken: ct)));
            foreach (var field in secret.SensitiveFields)
            {
                reads.Add((field, await service.RevealAsync(vault, secret.Name, caller, $"field:{field}", cancellationToken: ct)));
            }

            var buffer = new ArrayBufferWriter<byte>();
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("id", secret.Name);
                writer.WriteString("title", secret.Name);
                writer.WriteStartObject("vault");
                writer.WriteString("id", vault);
                writer.WriteEndObject();
                writer.WriteString("category", "PASSWORD");
                writer.WriteNumber("version", secret.Version);
                writer.WriteString("updatedAt", secret.VersionCreatedUtc);
                writer.WriteStartArray("fields");
                for (var i = 0; i < reads.Count; i++)
                {
                    var (name, read) = reads[i];
                    writer.WriteStartObject();
                    writer.WriteString("id", name);
                    writer.WriteString("label", name);
                    writer.WriteString("type", "CONCEALED");
                    if (i == 0)
                    {
                        // The secret's own value. A sensitive field that is also called "password" comes after it,
                        // and a client that looks for "password" takes the first.
                        writer.WriteString("purpose", "PASSWORD");
                    }

                    writer.WriteString("value"u8, read.Bytes.Reveal());
                    writer.WriteEndObject();

                    // A field holds one line, so an SSH key lives in a secret as its value. A reference to
                    // ".../private key" asks for the field private_key: that is the value too, the same read.
                    if (i == 0 && IsPrivateKey(read.Bytes.Reveal()))
                    {
                        writer.WriteStartObject();
                        writer.WriteString("id", "private_key");
                        writer.WriteString("label", "private key");
                        writer.WriteString("type", "CONCEALED");
                        writer.WriteString("value"u8, read.Bytes.Reveal());
                        writer.WriteEndObject();
                    }
                }

                foreach (var (name, text) in secret.Fields)
                {
                    writer.WriteStartObject();
                    writer.WriteString("id", name);
                    writer.WriteString("label", name);
                    writer.WriteString("type", name == "url" ? "URL" : "STRING");
                    if (name == "username")
                    {
                        writer.WriteString("purpose", "USERNAME");
                    }

                    writer.WriteString("value", text);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            http.Response.ContentType = "application/json";
            http.Response.Headers.CacheControl = "no-store";
            await http.Response.Body.WriteAsync(buffer.WrittenMemory, ct);
        }
        finally
        {
            foreach (var (_, read) in reads)
            {
                read.Dispose();
            }
        }
    }

    /// <summary>A PEM or OpenSSH private key: it starts with its BEGIN line. Looked at, never kept.</summary>
    private static bool IsPrivateKey(ReadOnlySpan<byte> value)
    {
        var start = value.TrimStart(" \t\r\n"u8);
        var firstLine = start.IndexOf((byte)'\n') is var end and >= 0 ? start[..end] : start;
        return firstLine.StartsWith("-----BEGIN "u8) && firstLine.TrimEnd("\r"u8).EndsWith("PRIVATE KEY-----"u8);
    }

    /// <summary>
    /// The one filter the client sends, <c>title eq "name"</c>; null without a filter. Anything else is refused
    /// rather than ignored, so a client that asks for something narrower never gets everything.
    /// </summary>
    private static string? TitleOf(string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter))
        {
            return null;
        }

        var match = TitleFilter().Match(filter.Trim());
        return match.Success
            ? match.Groups[1].Value.Replace("\\\"", "\"", StringComparison.Ordinal)
            : throw new DomainException("connect.filter.unsupported", "Only the filter title eq \"...\" is understood.");
    }

    [GeneratedRegex("""^title\s+eq\s+"((?:[^"\\]|\\.)*)"$""", RegexOptions.CultureInvariant)]
    private static partial Regex TitleFilter();

    /// <summary>A refusal in the shape the client expects: the status, and a message that never holds a value.</summary>
    private static async Task<IResult> Answer(Func<Task<IResult>> act)
    {
        try
        {
            return await act();
        }
        catch (DomainException e)
        {
            var status = e.Code switch
            {
                _ when e.Code.EndsWith(".not_found", StringComparison.Ordinal) => StatusCodes.Status404NotFound,
                "access.denied" or "access.network.refused" => StatusCodes.Status403Forbidden,
                _ => StatusCodes.Status400BadRequest,
            };
            return Results.Json(new { status, message = e.Message }, statusCode: status);
        }
    }

    private static Caller CallerOf(HttpContext http) => http.RequestServices.GetRequiredService<ICallerResolver>().Resolve(http);
}
