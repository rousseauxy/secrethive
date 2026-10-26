using SecretHive.Application.Secrets;

namespace SecretHive.Web.Components.Shared;

/// <summary>Folders in a select: indented by depth, in the order the server gives them (parents before children).</summary>
public static class FolderOptions
{
    public static string Label(FolderSummary folder) =>
        string.Concat(Enumerable.Repeat("\u00a0\u00a0\u00a0", Math.Max(0, folder.Path.Count - 1))) + folder.Name;

    /// <summary>Whether <paramref name="folder"/> is <paramref name="root"/> or lies beneath it: where a folder cannot go.</summary>
    public static bool IsWithin(FolderSummary folder, string root) =>
        folder.Path.Contains(root, StringComparer.OrdinalIgnoreCase);
}
