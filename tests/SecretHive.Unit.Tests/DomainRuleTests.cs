using System.Reflection;
using System.Text;
using SecretHive.Domain;

namespace SecretHive.Unit.Tests;

public sealed class DomainRuleTests
{
    [Theory]
    [InlineData("shop-prod")]
    [InlineData("a")]
    [InlineData("SQL-App-1")]
    public void Names_are_letters_digits_and_hyphens(string name)
    {
        Assert.Equal(name, Naming.Vault(name));
        Assert.Equal(name, Naming.Secret(name));
    }

    [Theory]
    [InlineData("")]
    [InlineData("with space")]
    [InlineData("under_score")]
    [InlineData("ConnectionStrings__Default")]
    [InlineData("dot.ted")]
    public void Other_names_are_refused_with_a_stable_code(string name)
    {
        Assert.Equal("secret.name.invalid", Assert.Throws<DomainException>(() => Naming.Secret(name)).Code);
        Assert.Equal("vault.name.invalid", Assert.Throws<DomainException>(() => Naming.Vault(name)).Code);
    }

    [Fact]
    public void A_name_may_be_127_characters_and_no_more()
    {
        Assert.Equal(127, Naming.Secret(new string('a', 127)).Length);
        Assert.Throws<DomainException>(() => Naming.Secret(new string('a', 128)));
        Assert.Throws<DomainException>(() => Naming.Field(new string('a', 64)));
    }

    [Fact]
    public void A_field_is_not_sensitive_unless_asked_for()
    {
        Assert.False(Field.Define("keyvault-name").Sensitive);
        Assert.True(Field.Define("pin", sensitive: true).Sensitive);
    }

    [Fact]
    public void The_reserved_fields_have_a_fixed_type_and_only_owner_can_never_be_sensitive()
    {
        Assert.Equal(FieldType.Url, Field.Define("url", FieldType.Url).Type);
        Assert.True(Field.Define("username").Reserved);
        Assert.True(Field.Define("owner").Reserved);
        Assert.False(Field.Define("tenant-id").Reserved);
        Assert.Equal("field.reserved.type", Assert.Throws<DomainException>(() => Field.Define("url")).Code);
        Assert.Equal("field.reserved.type", Assert.Throws<DomainException>(() => Field.Define("username", FieldType.Json)).Code);
        Assert.True(Field.Define("username", sensitive: true).Sensitive);
        Assert.True(Field.Define("url", FieldType.Url, sensitive: true).Sensitive);
        Assert.Equal("field.reserved.sensitive", Assert.Throws<DomainException>(() => Field.Define("owner", sensitive: true)).Code);
    }

    [Theory]
    [InlineData("db-password", true)]
    [InlineData("ApiToken", true)]
    [InlineData("signing-key", true)]
    [InlineData("tenant-id", false)]
    [InlineData("username", false)]
    public void A_form_can_tell_which_field_names_look_like_credentials(string name, bool expected) =>
        Assert.Equal(expected, Field.LooksLikeCredential(name));

    [Fact]
    public void A_field_value_is_checked_against_its_type_without_being_repeated()
    {
        Field.Define("note", FieldType.Multiline).Validate("line one\nline two"u8);
        Field.Define("settings", FieldType.Json).Validate("""{"retries":3}"""u8);
        Field.Define("url", FieldType.Url).Validate("https://example.test/path"u8);
        Field.Define("application-id", FieldType.Uuid).Validate("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b"u8);
        Assert.Equal("field.value.uuid", Assert.Throws<DomainException>(() => Field.Define("application-id", FieldType.Uuid).Validate("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6"u8)).Code);
        Assert.Equal("field.value.uuid", Assert.Throws<DomainException>(() => Field.Define("application-id", FieldType.Uuid).Validate("not-a-uuid"u8)).Code);

        var line = Assert.Throws<DomainException>(() => Field.Define("label").Validate("generated-one\ngenerated-two"u8));
        var json = Assert.Throws<DomainException>(() => Field.Define("settings", FieldType.Json).Validate("{generated-broken"u8));
        var url = Assert.Throws<DomainException>(() => Field.Define("url", FieldType.Url).Validate("generated-not-a-url"u8));
        var bytes = Assert.Throws<DomainException>(() => Field.Define("label").Validate([0xFF, 0xFE]));

        Assert.Equal(["field.value.multiline", "field.value.json", "field.value.url", "field.value.encoding"], [line.Code, json.Code, url.Code, bytes.Code]);
        Assert.All(new[] { line, json, url }, e => Assert.DoesNotContain("generated", e.Message));
    }

    [Fact]
    public void A_value_marked_json_must_be_json_and_a_value_has_a_size_limit()
    {
        SecretLimits.ValidateValue("""{"a":1}"""u8, "application/json");
        SecretLimits.ValidateValue("generated-plain"u8, "text/plain");
        SecretLimits.ValidateValue("generated-plain"u8, null);

        Assert.Equal("secret.value.json", Assert.Throws<DomainException>(() => SecretLimits.ValidateValue("generated-plain"u8, "application/json")).Code);
        Assert.Equal("secret.value.too_large", Assert.Throws<DomainException>(() => SecretLimits.ValidateValue(new byte[SecretLimits.MaxValueBytes + 1], null)).Code);
    }

    [Fact]
    public void A_secret_carries_at_most_twenty_distinct_fields_within_a_total_size()
    {
        var twenty = Enumerable.Range(0, 20).Select(i => (Field.Define($"f{i}"), 10)).ToList();
        SecretLimits.ValidateFields(twenty);

        Assert.Equal("field.too_many", Assert.Throws<DomainException>(() => SecretLimits.ValidateFields([.. twenty, (Field.Define("one-more"), 1)])).Code);
        Assert.Equal("field.name.duplicate", Assert.Throws<DomainException>(() => SecretLimits.ValidateFields([(Field.Define("Region"), 1), (Field.Define("region"), 1)])).Code);
        Assert.Equal("field.too_large", Assert.Throws<DomainException>(() => SecretLimits.ValidateFields([(Field.Define("big"), SecretLimits.MaxFieldBytesInTotal + 1)])).Code);
    }

    [Fact]
    public void Decrypted_bytes_have_no_string_form()
    {
        using var bytes = new SecretBytes(Encoding.UTF8.GetBytes("generated-value"));

        Assert.Equal("[secret]", bytes.ToString());
        Assert.Equal("[secret]", $"{bytes}");
    }

    /// <summary>The layering the sibling applications use, enforced the same way: by looking at what each assembly references.</summary>
    [Fact]
    public void The_layers_only_depend_inwards()
    {
        static string[] Ours(Assembly assembly) =>
            [.. assembly.GetReferencedAssemblies().Select(name => name.Name!).Where(name => name.StartsWith("SecretHive.", StringComparison.Ordinal)).Order(StringComparer.Ordinal)];

        static string[] Foreign(Assembly assembly) =>
            [.. assembly.GetReferencedAssemblies().Select(name => name.Name!).Where(name => !name.StartsWith("System", StringComparison.Ordinal) && !name.StartsWith("SecretHive.", StringComparison.Ordinal) && name != "netstandard")];

        var domain = typeof(Naming).Assembly;
        var application = typeof(Application.Ports.IKeyRing).Assembly;
        var infrastructure = typeof(Infrastructure.Encryption.KeyRing).Assembly;

        Assert.Empty(Ours(domain));
        Assert.Empty(Foreign(domain));
        Assert.Equal(["SecretHive.Domain"], Ours(application));
        Assert.Empty(Foreign(application));
        Assert.Equal(["SecretHive.Application", "SecretHive.Domain"], Ours(infrastructure));
    }
}
