using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Helpers;
using PgpCore.Models;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class Pgp : IVerifyAsync
    {
        #region VerifyAsync

        /// <summary>
        /// PGP verify a given file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="outputFile">File to write the decrypted data to</param>
        /// <param name="throwIfEncrypted">Throw if inputFile contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<bool> VerifyAsync(FileInfo inputFile, FileInfo outputFile = null,
            bool throwIfEncrypted = false)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentException("EncryptionKeys");

            if (!inputFile.Exists)
                throw new FileNotFoundException($"Encrypted File [{inputFile.FullName}] not found.");

            if (outputFile == null)
                using (Stream inputStream = inputFile.OpenRead())
                {
                    return await VerifyAsync(inputStream, null, throwIfEncrypted);
                }
            else
                using (Stream inputStream = inputFile.OpenRead())
                using (Stream outputStream = outputFile.OpenWrite())
                {
                    return await VerifyAsync(inputStream, outputStream, throwIfEncrypted);
                }
        }

        /// <summary>
        /// PGP verify a given stream.
        /// </summary>
        /// <param name="inputStream">Plain data stream to be verified</param>
        /// <param name="outputStream">Stream to write the decrypted data to</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<bool> VerifyAsync(Stream inputStream, Stream outputStream = null,
            bool throwIfEncrypted = false)
        {
            var verified = false;

            // If no output stream provided just write to memory stream and discard
            if (outputStream == null)
                outputStream = new MemoryStream();

            inputStream.Seek(0, SeekOrigin.Begin);
            var encodedFile = PgpUtilities.GetDecoderStream(inputStream);
            var factory = new PgpObjectFactory(encodedFile);
            var pgpObject = factory.NextPgpObject();

            switch (pgpObject)
            {
                case PgpCompressedData _:
                {
                    var publicKeyEncryptedData = Utilities.ExtractPublicKeyEncryptedData(encodedFile);

                    // Verify against public key ID and that of any sub keys
                    var keyIdToVerify = publicKeyEncryptedData.KeyId;
                    verified = Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
                        out _);
                    break;
                }
                case PgpEncryptedDataList dataList when throwIfEncrypted:
                    throw new ArgumentException("Input is encrypted. Decrypt the input first.");
                case PgpEncryptedDataList dataList:
                {
                    var publicKeyEncryptedData = Utilities.ExtractPublicKey(dataList);
                    var keyIdToVerify = publicKeyEncryptedData.KeyId;
                    // If we encounter an encrypted packet, verify with the encryption keys used instead
                    // TODO does this even make sense? maybe throw exception instead, or try to decrypt first
                    verified = Utilities.FindPublicKeyInKeyRings(keyIdToVerify,
                        EncryptionKeys.PublicKeyRings.Select(keyRing => keyRing.PgpPublicKeyRing), out _);
                    break;
                }
                case PgpOnePassSignatureList onePassSignatureList:
                {
                    var pgpOnePassSignature = onePassSignatureList[0];
                    var pgpLiteralData = (PgpLiteralData) factory.NextPgpObject();
                    var pgpLiteralStream = pgpLiteralData.GetInputStream();

                    // Verify against public key ID and that of any sub keys
                    var keyIdToVerify = pgpOnePassSignature.KeyId;
                    if (Utilities.FindPublicKey(keyIdToVerify, EncryptionKeys.VerificationKeys,
                            out var validationKey))
                    {
                        pgpOnePassSignature.InitVerify(validationKey);

                        int ch;
                        while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                        {
                            pgpOnePassSignature.Update((byte) ch);
                            outputStream.WriteByte((byte) ch);
                        }

                        var pgpSignatureList = (PgpSignatureList) factory.NextPgpObject();

                        for (var i = 0; i < pgpSignatureList.Count; i++)
                        {
                            var pgpSignature = pgpSignatureList[i];

                            if (pgpOnePassSignature.Verify(pgpSignature))
                            {
                                verified = true;
                                break;
                            }
                        }
                    }

                    break;
                }
                case PgpSignatureList signatureList:
                {
                    var pgpSignature = signatureList[0];
                    var pgpLiteralData = (PgpLiteralData) factory.NextPgpObject();
                    var pgpLiteralStream = pgpLiteralData.GetInputStream();

                    // Verify against public key ID and that of any sub keys
                    if (Utilities.FindPublicKey(pgpSignature.KeyId, EncryptionKeys.VerificationKeys,
                            out var publicKey))
                        foreach (var _ in publicKey.GetSignatures())
                            if (!verified)
                            {
                                pgpSignature.InitVerify(publicKey);

                                int ch;
                                while ((ch = pgpLiteralStream.ReadByte()) >= 0)
                                {
                                    pgpSignature.Update((byte) ch);
                                    outputStream.WriteByte((byte) ch);
                                }

                                verified = pgpSignature.Verify();
                            }
                            else
                            {
                                break;
                            }

                    break;
                }
                default:
                    throw new PgpException("Message is not a encrypted and signed file or simple signed file.");
            }

            await outputStream.FlushAsync();
            outputStream.Seek(0, SeekOrigin.Begin);

            return verified;
        }

        /// <summary>
        /// PGP verify a given string.
        /// </summary>
        /// <param name="input">Plain string to be verified</param>
        /// <param name="throwIfEncrypted">Throw if inputStream contains encrypted data. Otherwise, verify encryption key.</param>
        public async Task<bool> VerifyAsync(string input, bool throwIfEncrypted = false)
        {
            using (var inputStream = await input.GetStreamAsync())
            {
                return await VerifyAsync(inputStream, null, throwIfEncrypted);
            }
        }

        public async Task<bool> VerifyFileAsync(FileInfo inputFile, bool throwIfEncrypted = false)
        {
            return await VerifyAsync(inputFile, null, throwIfEncrypted);
        }

        public async Task<bool> VerifyStreamAsync(Stream inputStream, bool throwIfEncrypted = false)
        {
            return await VerifyAsync(inputStream, null, throwIfEncrypted);
        }

        public async Task<bool> VerifyArmoredStringAsync(string input, bool throwIfEncrypted = false)
        {
            return await VerifyAsync(input, throwIfEncrypted);
        }

        public async Task<VerificationResult> VerifyAndReadSignedFileAsync(FileInfo inputFile,
            bool throwIfEncrypted = false)
        {
            using (Stream inputStream = inputFile.OpenRead())
            {
                return await VerifyAndReadSignedStreamAsync(inputStream, throwIfEncrypted);
            }
        }

        public async Task<VerificationResult> VerifyAndReadSignedStreamAsync(Stream inputStream,
            bool throwIfEncrypted = false)
        {
            using (Stream outputStream = new MemoryStream())
            {
                var verified = await VerifyAsync(inputStream, outputStream, throwIfEncrypted);

                return new VerificationResult(verified, await outputStream.GetStringAsync());
            }
        }

        public async Task<VerificationResult> VerifyAndReadSignedArmoredStringAsync(string input,
            bool throwIfEncrypted = false)
        {
            using (var inputStream = await input.GetStreamAsync())
            {
                return await VerifyAndReadSignedStreamAsync(inputStream, throwIfEncrypted);
            }
        }

        #endregion VerifyAsync

        #region VerifyClearAsync

        /// <summary>
        /// PGP verify a given clear signed file.
        /// </summary>
        /// <param name="inputFile">Plain data file to be verified</param>
        /// <param name="outputFile">File to write the clear data to</param>
        public async Task<bool> VerifyClearAsync(FileInfo inputFile, FileInfo outputFile = null)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");

            if (outputFile == null)
                using (Stream inputStream = inputFile.OpenRead())
                {
                    return await VerifyClearAsync(inputStream);
                }
            else
                using (Stream inputStream = inputFile.OpenRead())
                using (Stream outputStream = outputFile.OpenWrite())
                {
                    return await VerifyClearAsync(inputStream, outputStream);
                }
        }

        /// <summary>
        /// PGP verify a given clear signed stream.
        /// </summary>
        /// <param name="inputStream">Clear signed data stream to be verified</param>
        /// <param name="outputStream">Stream to write the clear data to</param>
        // https://github.com/bcgit/bc-csharp/blob/master/crypto/test/src/openpgp/examples/ClearSignedFileProcessor.cs
        public async Task<bool> VerifyClearAsync(Stream inputStream, Stream outputStream = null)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (EncryptionKeys == null)
                throw new ArgumentNullException(nameof(EncryptionKeys), "Verification Key not found.");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            bool verified;

            using (var outStream = new MemoryStream())
            {
                using (var armoredInputStream = new ArmoredInputStream(inputStream))
                {
                    var lineOut = new MemoryStream();
                    var lineSep = _lineSeparator;
                    var lookAhead = ReadInputLine(lineOut, armoredInputStream);

                    // Read past message to signature and store message in stream
                    if (lookAhead != -1 && armoredInputStream.IsClearText())
                    {
                        var line = lineOut.ToArray();
                        await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        await outStream.WriteAsync(lineSep, 0, lineSep.Length);

                        while (lookAhead != -1 && armoredInputStream.IsClearText())
                        {
                            lookAhead = ReadInputLine(lineOut, lookAhead, armoredInputStream);

                            line = lineOut.ToArray();
                            await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                        }
                    }
                    else if (lookAhead != -1)
                    {
                        var line = lineOut.ToArray();
                        await outStream.WriteAsync(line, 0, GetLengthWithoutSeparatorOrTrailingWhitespace(line));
                    }

                    // Get public key from correctly positioned stream and initialise for verification
                    var pgpObjectFactory = new PgpObjectFactory(armoredInputStream);
                    var pgpSignatureList = (PgpSignatureList) pgpObjectFactory.NextPgpObject();
                    var pgpSignature = pgpSignatureList[0];

                    pgpSignature.InitVerify(EncryptionKeys.VerificationKeys.First());

                    // Read through message again and calculate signature
                    outStream.Position = 0;
                    lookAhead = ReadInputLine(lineOut, outStream);

                    ProcessLine(pgpSignature, lineOut.ToArray());

                    while (lookAhead != -1)
                    {
                        lookAhead = ReadInputLine(lineOut, lookAhead, outStream);

                        pgpSignature.Update((byte) '\r');
                        pgpSignature.Update((byte) '\n');

                        ProcessLine(pgpSignature, lineOut.ToArray());
                    }

                    verified = pgpSignature.Verify();
                }

                // Copy the message to the outputStream, if supplied
                if (outputStream != null)
                {
                    outStream.Position = 0;
                    await outStream.CopyToAsync(outputStream);
                }
            }

            return verified;
        }

        /// <summary>
        /// PGP verify a given clear signed string.
        /// </summary>
        /// <param name="input">Clear signed string to be verified</param>
        public async Task<bool> VerifyClearAsync(string input)
        {
            using (var inputStream = await input.GetStreamAsync())
            {
                return await VerifyClearAsync(inputStream);
            }
        }

        public async Task<bool> VerifyClearFileAsync(FileInfo inputFile) => await VerifyClearAsync(inputFile, null);

        public async Task<bool> VerifyClearStreamAsync(Stream inputStream)
        {
            return await VerifyClearAsync(inputStream);
        }

        public async Task<bool> VerifyClearArmoredStringAsync(string input)
        {
            return await VerifyClearAsync(input);
        }

        public async Task<VerificationResult> VerifyAndReadClearFileAsync(FileInfo inputFile)
        {
            using (Stream inputStream = inputFile.OpenRead())
            {
                return await VerifyAndReadClearStreamAsync(inputStream);
            }
        }

        public async Task<VerificationResult> VerifyAndReadClearStreamAsync(Stream inputStream)
        {
            using (Stream outputStream = new MemoryStream())
            {
                var verified = await VerifyClearAsync(inputStream, outputStream);
                outputStream.Position = 0;

                return new VerificationResult(verified, await outputStream.GetStringAsync());
            }
        }

        public async Task<VerificationResult> VerifyAndReadClearArmoredStringAsync(string input)
        {
            using (var inputStream = await input.GetStreamAsync())
            {
                return await VerifyAndReadClearStreamAsync(inputStream);
            }
        }

        #endregion VerifyClearAsync
    }
}