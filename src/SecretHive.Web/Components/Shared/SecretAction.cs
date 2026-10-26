namespace SecretHive.Web.Components.Shared;

/// <summary>What can be done to one secret from a dialog, on its vault's list and on its own page alike.</summary>
public enum SecretAction
{
    NewVersion,
    Rename,
    Elsewhere,
    Unlink,
    Delete,
}

/// <summary>
/// What an action did, said in a sentence, and where the secret is now: its new page after a rename or a move, the
/// vault after a delete, nothing when it stayed where it was.
/// </summary>
public sealed record SecretActionResult(string Message, string? Location);
