using System.Collections.Generic;

namespace PgpCore.Models
{
    public class PgpInspectResult : PgpInspectBaseResult
    {
        public PgpInspectResult(
            PgpInspectBaseResult baseResult,
            bool isArmored,
            Dictionary<string, string> messageHeaders
        ) : base(
            baseResult.IsCompressed,
            baseResult.IsEncrypted,
            baseResult.IsIntegrityProtected,
            baseResult.IsSigned,
            baseResult.SymmetricKeyAlgorithm,
            baseResult.FileName,
            baseResult.ModificationDateTime)
        {
            IsArmored = isArmored;
            MessageHeaders = messageHeaders;
        }

        public bool IsArmored { get; }
        public Dictionary<string, string> MessageHeaders { get; }
        public string Version => MessageHeaders.ContainsKey("Version") ? MessageHeaders["Version"] : null;
        public string Comment => MessageHeaders.ContainsKey("Comment") ? MessageHeaders["Comment"] : null;
    }
}