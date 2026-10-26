using System.Text;
using System.Text.Json;

namespace SecretHive.Domain;

public enum FieldType
{
    Text,
    Multiline,
    Json,
    Url,
    Uuid,
}

/// <summary>
/// One named extra beside a secret's value. An ordinary field is metadata: a plain column, readable with the
/// Reader role and with a query. A sensitive one belongs to a version, is encrypted, and is read like the value.
/// </summary>
public sealed record Field
{
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    private static readonly string[] CredentialWords = ["password", "passwd", "secret", "token", "key", "credential"];

    private Field(string name, FieldType type, bool sensitive)
    {
        Name = name;
        Type = type;
        Sensitive = sensitive;
    }

    public string Name { get; }

    public FieldType Type { get; }

    public bool Sensitive { get; }

    /// <summary>Whether the name is one of the three every vault spells the same way.</summary>
    public bool Reserved => ReservedType(Name) is not null;

    /// <summary>
    /// Describes a field. A field is not sensitive unless asked for. The reserved names have a fixed type, which is
    /// what lets a job rely on <c>username</c> being <c>username</c> everywhere. <c>username</c> and <c>url</c> may be
    /// marked sensitive like any field; <c>owner</c> may not, because it is who an alert is sent to.
    /// </summary>
    public static Field Define(string name, FieldType type = FieldType.Text, bool sensitive = false)
    {
        Naming.Field(name);
        if (ReservedType(name) is { } fixedType)
        {
            if (type != fixedType)
            {
                throw new DomainException("field.reserved.type", $"The field '{name}' is always of type {fixedType}.");
            }

            if (sensitive && name == "owner")
            {
                throw new DomainException("field.reserved.sensitive", "The field 'owner' cannot be sensitive: it is who an alert is sent to.");
            }
        }

        return new Field(name, type, sensitive);
    }

    /// <summary>
    /// Whether a form should suggest marking this field sensitive. Fields are open by default, so a password typed
    /// into one would be visible to every reader of the vault; the name is the only hint there is.
    /// </summary>
    public static bool LooksLikeCredential(string name) =>
        ReservedType(name) is null && CredentialWords.Any(word => name.Contains(word, StringComparison.OrdinalIgnoreCase));

    /// <summary>Checks a value against this field's type. The message never repeats the value.</summary>
    public void Validate(ReadOnlySpan<byte> value)
    {
        string text;
        try
        {
            text = StrictUtf8.GetString(value);
        }
        catch (DecoderFallbackException)
        {
            throw new DomainException("field.value.encoding", $"The field '{Name}' is not UTF-8 text.");
        }

        switch (Type)
        {
            case FieldType.Text when text.AsSpan().IndexOfAny('\r', '\n') >= 0:
                throw new DomainException("field.value.multiline", $"The field '{Name}' is a single line.");
            case FieldType.Url when !Uri.TryCreate(text, UriKind.Absolute, out _):
                throw new DomainException("field.value.url", $"The field '{Name}' must be an absolute URL.");
            case FieldType.Uuid when !Guid.TryParseExact(text, "D", out _):
                throw new DomainException("field.value.uuid", $"The field '{Name}' must be a UUID, as 8-4-4-4-12 hexadecimal digits.");
            case FieldType.Json when !IsJson(value):
                throw new DomainException("field.value.json", $"The field '{Name}' must be valid JSON.");
            default:
                break;
        }
    }

    internal static bool IsJson(ReadOnlySpan<byte> value)
    {
        try
        {
            var reader = new Utf8JsonReader(value);
            while (reader.Read())
            {
            }

            return value.Length > 0;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static FieldType? ReservedType(string name) => name switch
    {
        "username" or "owner" => FieldType.Text,
        "url" => FieldType.Url,
        _ => null,
    };
}

/// <summary>The limits on what one secret may carry.</summary>
public static class SecretLimits
{
    public const int MaxValueBytes = 25 * 1024;
    public const int MaxFields = 20;
    public const int MaxFieldBytesInTotal = 25 * 1024;

    /// <summary>Checks a value against its declared content type and the size limit.</summary>
    public static void ValidateValue(ReadOnlySpan<byte> value, string? contentType)
    {
        if (value.Length > MaxValueBytes)
        {
            throw new DomainException("secret.value.too_large", $"A value is at most {MaxValueBytes} bytes.");
        }

        if (string.Equals(contentType, "application/json", StringComparison.OrdinalIgnoreCase) && !Field.IsJson(value))
        {
            throw new DomainException("secret.value.json", "The value is marked application/json and is not valid JSON.");
        }
    }

    /// <summary>Checks a secret's set of fields as a whole: distinct names, and the limits.</summary>
    public static void ValidateFields(IReadOnlyCollection<(Field Field, int Bytes)> fields)
    {
        if (fields.Count > MaxFields)
        {
            throw new DomainException("field.too_many", $"A secret has at most {MaxFields} fields.");
        }

        if (fields.Select(item => item.Field.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count() != fields.Count)
        {
            throw new DomainException("field.name.duplicate", "Two fields share a name.");
        }

        if (fields.Sum(item => (long)item.Bytes) > MaxFieldBytesInTotal)
        {
            throw new DomainException("field.too_large", $"The fields of a secret hold at most {MaxFieldBytesInTotal} bytes together.");
        }
    }
}
