namespace SecretHive.Cli;

/// <summary>
/// Something the operator has to fix: a manifest that does not parse, a key that does not resolve, a value that
/// may not be written. The message is printed as is, so it names things and never contains a value.
/// </summary>
internal sealed class InputException : Exception
{
    public InputException(string message)
        : base(message)
    {
    }

    public InputException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    public InputException()
    {
    }
}
