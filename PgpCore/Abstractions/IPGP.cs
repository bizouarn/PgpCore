namespace PgpCore.Abstractions
{
    public interface IPgp : IDecryptAsync, IDecryptSync, IEncryptAsync, IEncryptSync, IInspectAsync, IInspectSync,
        IKeySync, IRecipientsSync, ISignAsync, ISignSync, IVerifyAsync, IVerifySync
    {
    }
}