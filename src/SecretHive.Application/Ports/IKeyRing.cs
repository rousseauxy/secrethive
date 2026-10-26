using SecretHive.Domain;

namespace SecretHive.Application.Ports;

/// <summary>A key encrypted under a master key. <see cref="MasterKeyId"/> says which one, which is what makes rotation possible.</summary>
public sealed record WrappedKey(string MasterKeyId, byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>One encrypted item: a value, a sensitive field, a certificate part.</summary>
public sealed record SealedItem(byte[] Nonce, byte[] Ciphertext, byte[] Tag);

/// <summary>Everything secret about one version, under that version's own data key.</summary>
public sealed record SealedVersion(WrappedKey Key, IReadOnlyDictionary<string, SealedItem> Items);

/// <summary>
/// Which value and which of its versions. Part of what is authenticated, so a ciphertext moved to another row does
/// not open. The vault is deliberately not part of it: a value can be moved, and can be linked under names in
/// several vaults, without being encrypted again.
/// </summary>
public sealed record VersionAddress(Guid ValueId, Guid VersionId);

/// <summary>
/// Envelope encryption. Each version has its own random data key; data keys are wrapped by the master key, which is
/// never in the database.
/// </summary>
public interface IKeyRing
{
    /// <summary>The master key new material is wrapped with.</summary>
    string CurrentKeyId { get; }

    /// <summary>Encrypts the items of a new version. Keys of <paramref name="items"/> are slots: <c>value</c>, <c>field:name</c>, <c>part:name</c>.</summary>
    SealedVersion Seal(VersionAddress address, IReadOnlyDictionary<string, ReadOnlyMemory<byte>> items);

    /// <summary>Decrypts one slot of a version.</summary>
    SecretBytes Open(VersionAddress address, SealedVersion version, string slot);

    /// <summary>Moves a version's data key to the current master key. The items are returned untouched: rotation never re-encrypts a value.</summary>
    SealedVersion Rewrap(VersionAddress address, SealedVersion version);
}

/// <summary>Material could not be decrypted: the wrong master key, or it was altered or moved.</summary>
public sealed class KeyRingException : Exception
{
    public KeyRingException(string message)
        : base(message)
    {
    }

    public KeyRingException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public KeyRingException()
    {
    }
}
