using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using SecretHive.Cli.Hosting;

namespace SecretHive.Cli.Server;

/// <summary>What the server says exists under a name, without its value.</summary>
internal sealed record RemoteSecret(int Version, bool Certificate);

/// <summary>The server did not answer at all: down, unreachable, or a proxy in front of it says so.</summary>
internal sealed class ServerUnreachableException(string message) : Exception(message);

/// <summary>The SecretHive server as the command line needs it: what exists in a vault, and one value at a time.</summary>
internal interface ISecretServer : IDisposable
{
    /// <summary>The live names of a vault with their current version. Refused with an <see cref="InputException"/> when the key may not see the vault.</summary>
    IReadOnlyDictionary<string, RemoteSecret> List(string vault);

    /// <summary>
    /// One value: a secret's value, one of its fields, or one part of a certificate; of the version the reference
    /// pins, or the current one. Null when the server has no such thing. Every call is a read the server writes
    /// down under the key's owner.
    /// </summary>
    SecretValue? Read(SecretReference reference, bool certificate);

    /// <summary>
    /// Makes a secret with a value and sensitive fields, and returns the version the server gave it. Only ever
    /// called for a name the server does not have: this is not a way to change what is there.
    /// </summary>
    int Create(string vault, string name, SecretValue value, IReadOnlyList<KeyValuePair<string, SecretValue>> fields, string description);

    /// <summary>
    /// Makes a certificate from its parts, each named by its kind (<c>certificate</c>, <c>chain</c>, <c>key</c>,
    /// <c>pfx</c>, <c>pfx-password</c>), and returns the version the server gave it. The server checks that the
    /// parts belong together and refuses otherwise. Only ever called for a name the server does not have.
    /// </summary>
    int CreateCertificate(string vault, string name, IReadOnlyList<KeyValuePair<string, SecretValue>> parts, string description);
}

/// <summary>
/// The server over HTTPS, with a key from a file. A refusal (wrong key, no role, outside the allowed networks) is
/// an answer and is reported as one; only silence counts as "not reachable", which is what lets a deploy fall back
/// to the bundle during an outage and never because the server said no.
/// </summary>
internal sealed class HttpSecretServer : ISecretServer
{
    private readonly HttpClient _client;
    private readonly string _keyFile;

    public HttpSecretServer(Uri address, string keyFile, HttpMessageHandler handler)
    {
        _keyFile = keyFile;
        string key;
        try
        {
            key = File.ReadAllText(keyFile).Trim();
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            throw new InputException($"{keyFile}: the server key cannot be read ({e.GetType().Name})", e);
        }

        if (!key.StartsWith("shv_", StringComparison.Ordinal) || key.Any(char.IsWhiteSpace))
        {
            throw new InputException($"{keyFile}: this is not a SecretHive key (shv_…, on one line)");
        }

        _client = new HttpClient(handler) { BaseAddress = address, Timeout = TimeSpan.FromSeconds(15) };
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", key);
    }

    /// <summary>
    /// The connection for a host profile. With a certificate named there, exactly that certificate is trusted and
    /// nothing else, which is how a server with a certificate it made for itself is reached without switching
    /// verification off.
    /// </summary>
    public static HttpSecretServer For(HostProfile profile)
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false, ConnectTimeout = TimeSpan.FromSeconds(5) };
        if (profile.ServerCertificatePath is { } path)
        {
            X509Certificate2 trusted;
            try
            {
                trusted = X509CertificateLoader.LoadCertificateFromFile(path);
            }
            catch (Exception e) when (e is CryptographicException or IOException or UnauthorizedAccessException)
            {
                throw new InputException($"{path}: not a certificate ({e.GetType().Name}). It is the server's certificate as PEM, without a key.", e);
            }

            var expected = trusted.GetCertHash(HashAlgorithmName.SHA256);
            handler.SslOptions.RemoteCertificateValidationCallback = (_, presented, _, _) =>
                presented is not null && CryptographicOperations.FixedTimeEquals(presented.GetCertHash(HashAlgorithmName.SHA256), expected);
        }

        return new HttpSecretServer(profile.Server!, profile.ServerKeyPath!, handler);
    }

    public IReadOnlyDictionary<string, RemoteSecret> List(string vault)
    {
        using var response = Send($"api/v1/vaults/{Uri.EscapeDataString(vault)}/secrets");
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            throw new InputException($"there is no vault '{vault}' as far as this key can tell: it does not exist, or the key's owner has no role in it");
        }

        Refuse(response, vault);
        var bytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        using var document = JsonDocument.Parse(bytes);
        var result = new Dictionary<string, RemoteSecret>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in document.RootElement.EnumerateArray())
        {
            result[item.GetProperty("name").GetString()!] = new RemoteSecret(item.GetProperty("version").GetInt32(), item.GetProperty("kind").GetString() == "Certificate");
        }

        return result;
    }

    public SecretValue? Read(SecretReference reference, bool certificate)
    {
        var vault = Uri.EscapeDataString(reference.Vault);
        var name = Uri.EscapeDataString(reference.Name);
        if (certificate && reference.Part is null)
        {
            throw new InputException($"{reference.BundleKey} is a certificate: say which part, as in {reference.BundleKey}#pfx (certificate, chain, key, pfx, pfx-password)");
        }

        var path = certificate ? $"api/v1/vaults/{vault}/certificates/{name}/parts/{Uri.EscapeDataString(reference.Part!)}"
            : reference.Part is null ? $"api/v1/vaults/{vault}/secrets/{name}/value"
            : $"api/v1/vaults/{vault}/secrets/{name}/fields/{Uri.EscapeDataString(reference.Part)}";
        if (reference.Version is not null)
        {
            path += "?version=" + Uri.EscapeDataString(reference.Version);
        }

        using var response = Send(path);
        if (response.StatusCode == HttpStatusCode.NotFound || (certificate && response.StatusCode == HttpStatusCode.BadRequest))
        {
            return null;
        }

        Refuse(response, reference.BundleKey);
        var bytes = response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult();
        if (certificate)
        {
            return new SecretValue(bytes) { Binary = true };
        }

        try
        {
            return ValueOf(bytes) ?? throw new InputException($"{reference.BundleKey}: the server's answer holds no value");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(bytes);
        }
    }

    public int Create(string vault, string name, SecretValue value, IReadOnlyList<KeyValuePair<string, SecretValue>> fields, string description)
    {
        // The request is built from bytes and never passes through a string, which could not be wiped. The buffer
        // is sized for the worst case of escaping so it does not grow and leave a copy behind.
        var buffer = new ArrayBufferWriter<byte>(512 + (6 * (description.Length + value.Length + fields.Sum(field => field.Key.Length + field.Value.Length + 64))));
        byte[]? body = null;
        try
        {
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("value"u8, value.Reveal());
                writer.WriteString("description", description);
                writer.WriteStartArray("fields");
                foreach (var (field, content) in fields)
                {
                    writer.WriteStartObject();
                    writer.WriteString("name", field);
                    writer.WriteString("value"u8, content.Reveal());
                    writer.WriteBoolean("sensitive", true);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            body = buffer.WrittenSpan.ToArray();
            using var request = new ByteArrayContent(body);
            request.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var response = Send($"api/v1/vaults/{Uri.EscapeDataString(vault)}/secrets/{Uri.EscapeDataString(name)}", request);
            Refuse(response, $"{vault}/{name}");
            using var answer = JsonDocument.Parse(response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult());
            return answer.RootElement.GetProperty("version").GetInt32();
        }
        finally
        {
            buffer.Clear();
            if (body is not null)
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
    }

    public int CreateCertificate(string vault, string name, IReadOnlyList<KeyValuePair<string, SecretValue>> parts, string description)
    {
        // Every part travels as base64, the password included: the server reads both forms as the same bytes, and
        // one form means one path for every part. The buffer is sized for the worst case so it does not grow.
        var buffer = new ArrayBufferWriter<byte>(512 + description.Length * 6 + parts.Sum(part => (part.Value.Length * 4 / 3) + part.Key.Length + name.Length + 64));
        byte[]? body = null;
        try
        {
            using (var writer = new Utf8JsonWriter(buffer))
            {
                writer.WriteStartObject();
                writer.WriteString("description", description);
                writer.WriteStartArray("parts");
                foreach (var (kind, content) in parts)
                {
                    writer.WriteStartObject();
                    writer.WriteString("kind", kind);
                    if (PartFileName(name, kind) is { } fileName)
                    {
                        writer.WriteString("fileName", fileName);
                    }

                    writer.WriteBase64String("content"u8, content.Reveal());
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
            }

            body = buffer.WrittenSpan.ToArray();
            using var request = new ByteArrayContent(body);
            request.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            using var response = Send($"api/v1/vaults/{Uri.EscapeDataString(vault)}/certificates/{Uri.EscapeDataString(name)}", request);
            Refuse(response, $"{vault}/{name}");
            using var answer = JsonDocument.Parse(response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult());
            return answer.RootElement.GetProperty("version").GetInt32();
        }
        finally
        {
            buffer.Clear();
            if (body is not null)
            {
                CryptographicOperations.ZeroMemory(body);
            }
        }
    }

    /// <summary>The name a part is handed back under later: the certificate's name with the usual extension; a password is no file.</summary>
    private static string? PartFileName(string name, string kind) => kind switch
    {
        "certificate" => $"{name}.cer",
        "chain" => $"{name}-chain.pem",
        "key" => $"{name}.key",
        "pfx" => $"{name}.pfx",
        _ => null,
    };

    public void Dispose() => _client.Dispose();

    /// <summary>The "value" of the answer, as bytes that are never turned into a string, which could not be wiped.</summary>
    private static SecretValue? ValueOf(byte[] json)
    {
        var reader = new Utf8JsonReader(json);
        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.PropertyName && reader.CurrentDepth == 1 && reader.ValueTextEquals("value"u8))
            {
                reader.Read();
                if (reader.TokenType != JsonTokenType.String)
                {
                    return null;
                }

                var buffer = new byte[reader.ValueSpan.Length];
                try
                {
                    var written = reader.CopyString(buffer);
                    return new SecretValue(buffer[..written]);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buffer);
                }
            }
        }

        return null;
    }

    private HttpResponseMessage Send(string path, HttpContent? put = null)
    {
        try
        {
            var address = new Uri(path, UriKind.Relative);
            var response = (put is null ? _client.GetAsync(address) : _client.PutAsync(address, put)).GetAwaiter().GetResult();

            // A proxy answering for a server that is not there is still the server not answering.
            if (response.StatusCode is HttpStatusCode.BadGateway or HttpStatusCode.ServiceUnavailable or HttpStatusCode.GatewayTimeout)
            {
                var status = (int)response.StatusCode;
                response.Dispose();
                throw new ServerUnreachableException($"{_client.BaseAddress!.Host} answers {status.ToString(CultureInfo.InvariantCulture)}");
            }

            return response;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException)
        {
            throw new ServerUnreachableException($"{_client.BaseAddress!.Host} does not answer ({(e.InnerException ?? e).GetType().Name})");
        }
    }

    /// <summary>Turns a refusal into words. The server's own sentence is used when it gave one; it never holds a value.</summary>
    private void Refuse(HttpResponseMessage response, string what)
    {
        if (response.IsSuccessStatusCode)
        {
            return;
        }

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new InputException($"the server does not accept the key in {_keyFile}: unknown, expired, revoked, or not allowed from this address");
        }

        if (response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.MovedPermanently or HttpStatusCode.TemporaryRedirect or HttpStatusCode.PermanentRedirect)
        {
            throw new InputException($"the server at {_client.BaseAddress} sends this request elsewhere: 'server' must be its https address");
        }

        string? detail = null;
        try
        {
            using var problem = JsonDocument.Parse(response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult());
            detail = problem.RootElement.TryGetProperty("detail", out var text) ? text.GetString() : null;
        }
        catch (JsonException)
        {
        }

        throw new InputException($"{what}: the server refuses ({((int)response.StatusCode).ToString(CultureInfo.InvariantCulture)}){(detail is null ? "" : ": " + detail)}");
    }
}
