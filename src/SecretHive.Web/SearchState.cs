namespace SecretHive.Web;

/// <summary>
/// What the search in the top bar narrows a vault's list to, for the page that shows that list. The search lives in
/// MainLayout and the list in a page under VaultLayout; both are in the same circuit, so they share this.
/// </summary>
public sealed class SearchState
{
    /// <summary>The words a vault's list is narrowed to; empty for all of it.</summary>
    public string Filter { get; private set; } = "";

    /// <summary>Raised when <see cref="Filter"/> changed.</summary>
    public event Action? Changed;

    public void Narrow(string filter)
    {
        if (filter != Filter)
        {
            Filter = filter;
            Changed?.Invoke();
        }
    }
}
