using System.Text;
using SecretHive.Application.Ports;
using SecretHive.Infrastructure.Encryption;

namespace SecretHive.Unit.Tests;

public sealed class KeyRingTests : IDisposable
{
    private readonly string _directory = Directory.CreateTempSubdirectory("secrethive-keys-").FullName;

    private static readonly VersionAddress Address = new(Guid.NewGuid(), Guid.NewGuid());

    private MasterKey NewMasterKey(string name)
    {
        var path = Path.Combine(_directory, name);
        MasterKey.Create(path);
        return MasterKey.Load(path);
    }

    private static Dictionary<string, ReadOnlyMemory<byte>> Items(params (string Slot, string Text)[] items) =>
        items.ToDictionary(item => item.Slot, item => (ReadOnlyMemory<byte>)Encoding.UTF8.GetBytes(item.Text));

    private static string Text(Domain.SecretBytes bytes) => Encoding.UTF8.GetString(bytes.Reveal());

    [Fact]
    public void A_version_opens_slot_by_slot_and_stores_no_plaintext()
    {
        using var ring = new KeyRing(NewMasterKey("a"));

        var version = ring.Seal(Address, Items(("value", "generated-value"), ("field:pin", "generated-pin")));

        Assert.Equal("generated-value", Text(ring.Open(Address, version, "value")));
        Assert.Equal("generated-pin", Text(ring.Open(Address, version, "field:pin")));
        Assert.Equal(ring.CurrentKeyId, version.Key.MasterKeyId);
        Assert.DoesNotContain("generated", Encoding.Latin1.GetString(version.Items["value"].Ciphertext));
        Assert.Throws<KeyRingException>(() => ring.Open(Address, version, "field:absent"));
    }

    [Fact]
    public void The_same_value_sealed_twice_looks_different()
    {
        using var ring = new KeyRing(NewMasterKey("a"));

        var first = ring.Seal(Address, Items(("value", "generated-value")));
        var second = ring.Seal(Address, Items(("value", "generated-value")));

        Assert.NotEqual(first.Items["value"].Ciphertext, second.Items["value"].Ciphertext);
        Assert.NotEqual(first.Key.Ciphertext, second.Key.Ciphertext);
    }

    [Fact]
    public void Material_moved_to_another_version_or_another_slot_does_not_open()
    {
        using var ring = new KeyRing(NewMasterKey("a"));
        var version = ring.Seal(Address, Items(("value", "generated-value"), ("field:pin", "generated-pin")));

        // Another row: the same bytes presented as a different version, and as a different value.
        Assert.Throws<KeyRingException>(() => ring.Open(Address with { VersionId = Guid.NewGuid() }, version, "value"));
        Assert.Throws<KeyRingException>(() => ring.Open(Address with { ValueId = Guid.NewGuid() }, version, "value"));

        // Another column: a field's ciphertext put where the value's belongs.
        var swapped = version with { Items = new Dictionary<string, SealedItem> { ["value"] = version.Items["field:pin"] } };
        Assert.Throws<KeyRingException>(() => ring.Open(Address, swapped, "value"));
    }

    [Fact]
    public void An_altered_ciphertext_does_not_open()
    {
        using var ring = new KeyRing(NewMasterKey("a"));
        var version = ring.Seal(Address, Items(("value", "generated-value")));
        var item = version.Items["value"];
        var altered = (byte[])item.Ciphertext.Clone();
        altered[0] ^= 1;

        var tampered = version with { Items = new Dictionary<string, SealedItem> { ["value"] = item with { Ciphertext = altered } } };

        Assert.Throws<KeyRingException>(() => ring.Open(Address, tampered, "value"));
    }

    [Fact]
    public void Another_master_key_is_named_not_guessed_at()
    {
        using var ring = new KeyRing(NewMasterKey("a"));
        using var other = new KeyRing(NewMasterKey("b"));
        var version = ring.Seal(Address, Items(("value", "generated-value")));

        var e = Assert.Throws<KeyRingException>(() => other.Open(Address, version, "value"));

        Assert.Contains(ring.CurrentKeyId, e.Message);
        Assert.NotEqual(ring.CurrentKeyId, other.CurrentKeyId);
    }

    [Fact]
    public void Rotation_rewraps_the_key_and_never_touches_the_value()
    {
        var oldKey = NewMasterKey("old");
        using var before = new KeyRing(oldKey);
        var version = before.Seal(Address, Items(("value", "generated-value")));

        using var during = new KeyRing(NewMasterKey("new"), [MasterKey.Load(Path.Combine(_directory, "old"))]);
        var rewrapped = during.Rewrap(Address, version);

        Assert.Equal(during.CurrentKeyId, rewrapped.Key.MasterKeyId);
        Assert.Same(version.Items, rewrapped.Items);
        Assert.Same(rewrapped, during.Rewrap(Address, rewrapped));

        // Once everything is re-wrapped the old master key is no longer needed.
        using var after = new KeyRing(MasterKey.Load(Path.Combine(_directory, "new")));
        Assert.Equal("generated-value", Text(after.Open(Address, rewrapped, "value")));
        Assert.Throws<KeyRingException>(() => after.Open(Address, version, "value"));
    }

    [Fact]
    public void A_master_key_file_is_32_bytes_raw_or_base64_and_nothing_else()
    {
        var raw = Path.Combine(_directory, "raw");
        File.WriteAllBytes(raw, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        var created = Path.Combine(_directory, "created");
        MasterKey.Create(created);
        var weak = Path.Combine(_directory, "weak");
        File.WriteAllText(weak, "correct horse battery staple");

        Assert.Equal(16, MasterKey.Load(raw).Id.Length);
        Assert.Equal(MasterKey.Load(created).Id, MasterKey.Load(created).Id);
        Assert.NotEqual(MasterKey.Load(raw).Id, MasterKey.Load(created).Id);
        Assert.Throws<KeyRingException>(() => MasterKey.Load(weak));
        Assert.Throws<KeyRingException>(() => MasterKey.Load(Path.Combine(_directory, "absent")));
        Assert.Throws<KeyRingException>(() => MasterKey.Create(created));
    }

    public void Dispose() => Directory.Delete(_directory, recursive: true);
}
