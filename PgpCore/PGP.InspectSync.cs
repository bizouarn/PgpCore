using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;

namespace PgpCore
{
    public partial class Pgp : IInspectSync
    {
        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="inputStream">The input stream containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public PgpInspectResult Inspect(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            var isArmored = IsArmored(inputStream);
            Dictionary<string, string> messageHeaders = null;

            if (isArmored)
                messageHeaders = GetMessageHeaders(inputStream);

            var pgpInspectBaseResult = GetPgpInspectBaseResult(inputStream);

            return new PgpInspectResult(
                pgpInspectBaseResult,
                isArmored,
                messageHeaders
            );
        }

        private PgpInspectBaseResult GetPgpInspectBaseResult(Stream inputStream)
        {
            var isSigned = false;
            var isCompressed = false;
            var isEncrypted = false;
            var isIntegrityProtected = false;
            var symmetricKeyAlgorithm = SymmetricKeyAlgorithmTag.Null;

            PgpLiteralData pgpLiteralData;

            inputStream.Seek(0, SeekOrigin.Begin);
            var pgpObjectFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            var pgpObject = pgpObjectFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            PgpObject message = null;

            switch (pgpObject)
            {
                case PgpEncryptedDataList dataList:
                    isEncrypted = true;
                    enc = dataList;
                    break;
                case PgpCompressedData compressedData:
                    isCompressed = true;
                    message = compressedData;
                    break;
                case PgpLiteralData literalData:
                    message = literalData;
                    break;
                case PgpOnePassSignatureList _:
                case PgpSignatureList _:
                    isSigned = true;
                    message = pgpObjectFactory.NextPgpObject();
                    break;
                default:
                    enc = (PgpEncryptedDataList) pgpObjectFactory.NextPgpObject();
                    break;
            }

            // If enc and message are null at this point, we failed to detect the contents of the encrypted stream.
            if (enc == null && message == null)
                throw new ArgumentException("Failed to detect encrypted content format.", nameof(inputStream));

            using (var disposables = new CompositeDisposable())
            {
                // decrypt
                PgpPrivateKey privateKey = null;
                PgpPublicKeyEncryptedData pbe = null;
                if (enc != null)
                {
                    isEncrypted = true;
                    foreach (PgpPublicKeyEncryptedData publicKeyEncryptedData in enc.GetEncryptedDataObjects())
                    {
                        isIntegrityProtected = publicKeyEncryptedData.IsIntegrityProtected();
                        privateKey = EncryptionKeys.FindSecretKey(publicKeyEncryptedData.KeyId);

                        if (privateKey != null)
                        {
                            symmetricKeyAlgorithm = publicKeyEncryptedData.GetSymmetricAlgorithm(privateKey);
                            pbe = publicKeyEncryptedData;
                            break;
                        }
                    }

                    if (privateKey == null)
                        throw new ArgumentException("Secret key for message not found.");

                    var clear = pbe.GetDataStream(privateKey).DisposeWith(disposables);
                    var plainFact = new PgpObjectFactory(clear);

                    message = plainFact.NextPgpObject();

                    if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                    {
                        isSigned = true;
                        message = plainFact.NextPgpObject();
                    }
                }

                switch (message)
                {
                    case PgpCompressedData pgpCompressedData:
                    {
                        isCompressed = true;
                        var compDataIn = pgpCompressedData.GetDataStream().DisposeWith(disposables);
                        var objectFactory = new PgpObjectFactory(compDataIn);
                        message = objectFactory.NextPgpObject();

                        if (message is PgpOnePassSignatureList || message is PgpSignatureList)
                        {
                            isSigned = true;
                            message = objectFactory.NextPgpObject();
                            pgpLiteralData = (PgpLiteralData) message;
                        }
                        else
                        {
                            pgpLiteralData = (PgpLiteralData) message;
                        }

                        break;
                    }
                    case PgpLiteralData literalData:
                        pgpLiteralData = literalData;
                        break;
                    default:
                        throw new PgpException("Message is not a simple encrypted file.");
                }
            }

            return new PgpInspectBaseResult(
                isCompressed,
                isEncrypted,
                isIntegrityProtected,
                isSigned,
                symmetricKeyAlgorithm,
                pgpLiteralData?.FileName,
                pgpLiteralData?.ModificationTime ?? DateTime.MinValue
            );
        }

        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="inputFile">The input file containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public PgpInspectResult Inspect(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (var inputStream = inputFile.OpenRead())
            {
                return Inspect(inputStream);
            }
        }

        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="input">The input string containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public PgpInspectResult Inspect(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Input");

            using (var inputStream = input.GetStream())
            {
                return Inspect(inputStream);
            }
        }

        private static Dictionary<string, string> GetMessageHeaders(Stream inputStream)
        {
            var headers = new Dictionary<string, string>();

            var reader = new StreamReader(inputStream);
            string line;

            while ((line = reader.ReadLine()) != null)
            {
                if (line.StartsWith("-----")) break;

                var colonIndex = line.IndexOf(':');
                if (colonIndex != -1)
                {
                    var key = line.Substring(0, colonIndex).Trim();
                    var value = line.Substring(colonIndex + 1).Trim();
                    headers[key] = value;
                }
            }

            return headers;
        }

        private static bool IsArmored(IReadOnlyList<byte> data)
        {
            return data[0] == 0x2D && data[1] == 0x2D && data[2] == 0x2D && data[3] == 0x2D && data[4] == 0x2D &&
                   data[5] == 0x42 && data[6] == 0x45 && data[7] == 0x47 && data[8] == 0x49 && data[9] == 0x4E &&
                   data[10] == 0x20 && data[11] == 0x50 && data[12] == 0x47 && data[13] == 0x50 && data[14] == 0x20 &&
                   data[15] == 0x4D && data[16] == 0x45 && data[17] == 0x53 && data[18] == 0x53 && data[19] == 0x41 &&
                   data[20] == 0x47 && data[21] == 0x45 && data[22] == 0x2D && data[23] == 0x2D && data[24] == 0x2D &&
                   data[25] == 0x2D;
        }

        private static bool IsArmored(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            var headerBytes = new byte[26];
            stream.Read(headerBytes, 0, 26);
            return IsArmored(headerBytes);
        }
    }
}