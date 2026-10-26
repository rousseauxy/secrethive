using System.Text;
using SecretHive.Application.Secrets;
using SecretHive.Domain;

namespace SecretHive.Web.Components.Shared;

/// <summary>One row of the field editor.</summary>
public sealed class FieldRow
{
    public string Name { get; set; } = "";

    public FieldType Type { get; set; } = FieldType.Text;

    public bool Sensitive { get; set; }

    public string Value { get; set; } = "";

    public FieldInput ToInput() => new(Name.Trim(), Encoding.UTF8.GetBytes(Value), Type, Sensitive);

    /// <summary>The names that mean something to SecretHive itself: their kind is fixed.</summary>
    public static bool IsReserved(string name) => name is "username" or "url" or "owner";

    /// <summary>The two a form simply offers, without being asked: left empty they are not stored.</summary>
    public static bool IsAlwaysThere(string name) => name is "username" or "url";

    /// <summary>What a form sends: every row, except an offered one nobody filled in.</summary>
    public static IReadOnlyList<FieldInput> Inputs(IEnumerable<FieldRow> rows) =>
        [.. rows.Where(row => !(IsAlwaysThere(row.Name) && row.Value.Length == 0)).Select(row => row.ToInput())];
}
