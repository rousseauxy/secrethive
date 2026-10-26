using System.Text.RegularExpressions;

namespace SecretHive.Domain;

/// <summary>
/// The naming rules. Vaults, secrets and certificates share one rule, the one cloud key vaults use, so a name
/// here is a valid name there and an outside job can copy a secret across without renaming it.
/// </summary>
public static partial class Naming
{
    public const int MaxNameLength = 127;
    public const int MaxFieldNameLength = 63;

    public static string Vault(string name) => Check(name, NameShape(), "vault.name.invalid", "a vault name");

    public static string Folder(string name) => Check(name, NameShape(), "folder.name.invalid", "a folder name");

    public static string Secret(string name) => Check(name, NameShape(), "secret.name.invalid", "a secret name");

    public static string Field(string name) => Check(name, FieldShape(), "field.name.invalid", "a field name");

    private static string Check(string name, Regex shape, string code, string what) =>
        name is not null && shape.IsMatch(name)
            ? name
            : throw new DomainException(code, $"Not {what}: letters, digits and hyphens only.");

    [GeneratedRegex("^[0-9a-zA-Z-]{1,127}$", RegexOptions.CultureInvariant)]
    private static partial Regex NameShape();

    [GeneratedRegex("^[0-9a-zA-Z-]{1,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex FieldShape();
}
