namespace SecretHive.Domain;

/// <summary>
/// A rule of the model was broken. <see cref="Code"/> is stable and is what a client branches on; the message is
/// for a person and never contains a value.
/// </summary>
public sealed class DomainException : Exception
{
    public DomainException(string code, string message)
        : base(message) => Code = code;

    public DomainException(string message)
        : this("invalid", message)
    {
    }

    public DomainException(string message, Exception innerException)
        : base(message, innerException) => Code = "invalid";

    public DomainException()
        : this("invalid", "invalid")
    {
    }

    public string Code { get; }
}
