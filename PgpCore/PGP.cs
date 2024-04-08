using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PgpCore.Abstractions;
using PgpCore.Enums;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class Pgp : IPgp
    {
        public static Pgp Instance => _instance ?? (_instance = new Pgp());
        private static Pgp _instance;

        private const int _bufferSize = 0x10000;
        private const string _defaultFileName = "name";

        public CompressionAlgorithmTag CompressionAlgorithm { get; set; } = CompressionAlgorithmTag.Uncompressed;

        public SymmetricKeyAlgorithmTag SymmetricKeyAlgorithm { get; set; } = SymmetricKeyAlgorithmTag.TripleDes;

        public int PgpSignatureType { get; set; } = PgpSignature.DefaultCertification;

        public PublicKeyAlgorithmTag PublicKeyAlgorithm { get; set; } = PublicKeyAlgorithmTag.RsaGeneral;

        public PgpFileType FileType { get; set; } = PgpFileType.Binary;

        public HashAlgorithmTag HashAlgorithmTag { get; set; } = HashAlgorithmTag.Sha1;

        public IEncryptionKeys EncryptionKeys { get; private set; }

        #region Constructor

        public Pgp()
        {
        }

        public Pgp(IEncryptionKeys encryptionKeys)
        {
            EncryptionKeys = encryptionKeys;
        }

        #endregion Constructor

        #region Private helpers

        #region OutputEncryptedAsync

        private async Task OutputEncryptedAsync(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck,
            string name, bool oldFormat)
        {
            using (var encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (var compressedOut = ChainCompressedOut(encryptedOut))
                {
                    var signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (var literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
                    {
                        using (var inputFileStream = inputFile.OpenRead())
                        {
                            await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream,
                                signatureGenerator);
                        }
                    }
                }
            }
        }

		private async Task OutputEncryptedAsync(Stream inputStream, Stream outputStream, bool withIntegrityCheck,
			string name, bool oldFormat)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
					{
						await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
					}
				}
			}
		}

        #endregion OutputEncryptedAsync

        #region OutputEncrypted

        private void OutputEncrypted(FileInfo inputFile, Stream outputStream, bool withIntegrityCheck, string name,
            bool oldFormat)
        {
            using (var encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
            {
                using (var compressedOut = ChainCompressedOut(encryptedOut))
                {
                    var signatureGenerator = InitSignatureGenerator(compressedOut);
                    using (var literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
                    {
                        using (var inputFileStream = inputFile.OpenRead())
                        {
                            WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                        }
                    }
                }
            }
        }

		private void OutputEncrypted(Stream inputStream, Stream outputStream, bool withIntegrityCheck, string name, bool oldFormat)
		{
			using (Stream encryptedOut = ChainEncryptedOut(outputStream, withIntegrityCheck))
			{
				using (Stream compressedOut = ChainCompressedOut(encryptedOut))
				{
					PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
					using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
					{
						WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
					}
				}
			}
		}

        #endregion OutputEncrypted

        #region OutputSignedAsync

        private async Task OutputSignedAsync(FileInfo inputFile, Stream outputStream, string name, bool oldFormat)
        {
            using (var compressedOut = ChainCompressedOut(outputStream))
            {
                var signatureGenerator = InitSignatureGenerator(compressedOut);
                using (var literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
                {
                    using (var inputFileStream = inputFile.OpenRead())
                    {
                        await WriteOutputAndSignAsync(compressedOut, literalOut, inputFileStream, signatureGenerator);
                    }
                }
            }
        }

		private async Task OutputSignedAsync(Stream inputStream, Stream outputStream,
			string name, bool oldFormat)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
                PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
                using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
                {
                    await WriteOutputAndSignAsync(compressedOut, literalOut, inputStream, signatureGenerator);
                }
            }
        }

        #endregion OutputSignedAsync

        #region OutputSigned

        private void OutputSigned(FileInfo inputFile, Stream outputStream, string name, bool oldFormat)
        {
            using (var compressedOut = ChainCompressedOut(outputStream))
            {
                var signatureGenerator = InitSignatureGenerator(compressedOut);
                using (var literalOut = ChainLiteralOut(compressedOut, inputFile, name, oldFormat))
                {
                    using (var inputFileStream = inputFile.OpenRead())
                    {
                        WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                    }
                }
            }
        }

		private void OutputSigned(Stream inputStream, Stream outputStream, string name, bool oldFormat)
		{
			using (Stream compressedOut = ChainCompressedOut(outputStream))
			{
				PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut);
				using (Stream literalOut = ChainLiteralOut(compressedOut, inputStream, name, oldFormat))
				{
					WriteOutputAndSign(compressedOut, literalOut, inputStream, signatureGenerator);
				}
			}
		}

        #endregion OutputSigned

        #region OutputClearSignedAsync

        private async Task OutputClearSignedAsync(FileInfo inputFile, Stream outputStream,
            IDictionary<string, string> headers)
        {
            using (var inputFileStream = inputFile.OpenRead())
            {
                await OutputClearSignedAsync(inputFileStream, outputStream, headers);
            }
        }

        private async Task OutputClearSignedAsync(Stream inputStream, Stream outputStream,
            IDictionary<string, string> headers)
        {
            using (var streamReader = new StreamReader(inputStream))
            using (var armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
            {
                var pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

                while (streamReader.Peek() >= 0)
                {
                    var line = await streamReader.ReadLineAsync();
                    var lineByteArray = Encoding.ASCII.GetBytes(line);
                    // Does the line end with whitespace?
                    // Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
                    var cleanLine = line.TrimEnd();
                    var cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

                    pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
                    await armoredOutputStream.WriteAsync(lineByteArray, 0, lineByteArray.Length);

                    // Add a line break back to the stream
                    armoredOutputStream.Write((byte) '\r');
                    armoredOutputStream.Write((byte) '\n');

                    // Update signature with line breaks unless we're on the last line
                    if (streamReader.Peek() >= 0)
                    {
                        pgpSignatureGenerator.Update((byte) '\r');
                        pgpSignatureGenerator.Update((byte) '\n');
                    }
                }

                armoredOutputStream.EndClearText();

                var bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
                pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
            }
        }

        #endregion OutputClearSignedAsync

        #region OutputClearSigned

        private void OutputClearSigned(FileInfo inputFile, Stream outputStream, IDictionary<string, string> headers)
        {
            using (var inputFileStream = inputFile.OpenRead())
            {
                OutputClearSigned(inputFileStream, outputStream, headers);
            }
        }

        private void OutputClearSigned(Stream inputStream, Stream outputStream, IDictionary<string, string> headers)
        {
            using (var streamReader = new StreamReader(inputStream))
            using (var armoredOutputStream = new ArmoredOutputStream(outputStream, headers))
            {
                var pgpSignatureGenerator = InitClearSignatureGenerator(armoredOutputStream);

                while (streamReader.Peek() >= 0)
                {
                    var line = streamReader.ReadLine();
                    if (line == null) continue;
                    var lineByteArray = Encoding.ASCII.GetBytes(line);
                    // Does the line end with whitespace?
                    // Trailing white space needs to be removed from the end of the document for a valid signature RFC 4880 Section 7.1
                    var cleanLine = line.TrimEnd();
                    var cleanLineByteArray = Encoding.ASCII.GetBytes(cleanLine);

                    pgpSignatureGenerator.Update(cleanLineByteArray, 0, cleanLineByteArray.Length);
                    armoredOutputStream.Write(lineByteArray, 0, lineByteArray.Length);

                    // Add a line break back to the stream
                    armoredOutputStream.Write((byte) '\r');
                    armoredOutputStream.Write((byte) '\n');

                    // Update signature with line breaks unless we're on the last line
                    if (streamReader.Peek() >= 0)
                    {
                        pgpSignatureGenerator.Update((byte) '\r');
                        pgpSignatureGenerator.Update((byte) '\n');
                    }
                }

                armoredOutputStream.EndClearText();

                var bcpgOutputStream = new BcpgOutputStream(armoredOutputStream);
                pgpSignatureGenerator.Generate().Encode(bcpgOutputStream);
            }
        }

        #endregion OutputClearSigned

        #region WriteOutputAndSign

        private static async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut,
            FileStream inputFileStream,
            PgpSignatureGenerator signatureGenerator)
        {
            int length;
            var buf = new byte[_bufferSize];
            while ((length = await inputFileStream.ReadAsync(buf, 0, buf.Length)) > 0)
            {
                await literalOut.WriteAsync(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOut);
        }

        private static void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFileStream,
            PgpSignatureGenerator signatureGenerator)
        {
            int length;
            var buf = new byte[_bufferSize];
            while ((length = inputFileStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOut);
        }

        private static async Task WriteOutputAndSignAsync(Stream compressedOut, Stream literalOut, Stream inputStream,
            PgpSignatureGenerator signatureGenerator)
        {
            int length;
            var buf = new byte[_bufferSize];
            while ((length = await inputStream.ReadAsync(buf, 0, buf.Length)) > 0)
            {
                await literalOut.WriteAsync(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOut);
        }

        private static void WriteOutputAndSign(Stream compressedOut, Stream literalOut, Stream inputStream,
            PgpSignatureGenerator signatureGenerator)
        {
            int length;
            var buf = new byte[_bufferSize];
            while ((length = inputStream.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }

            signatureGenerator.Generate().Encode(compressedOut);
        }

        #endregion WriteOutputAndSign

        #region ChainEncryptedOut

        private Stream ChainEncryptedOut(Stream outputStream, bool withIntegrityCheck)
        {
            var encryptedDataGenerator =
                new PgpEncryptedDataGenerator(SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());

            foreach (var publicKeyRing in EncryptionKeys.PublicKeyRings)
            {
                var publicKey = publicKeyRing.PreferredEncryptionKey ?? publicKeyRing.DefaultEncryptionKey;
                encryptedDataGenerator.AddMethod(publicKey);
            }

            return encryptedDataGenerator.Open(outputStream, new byte[_bufferSize]);
        }

        #endregion ChainEncryptedOut

        #region ChainCompressedOut

        private Stream ChainCompressedOut(Stream encryptedOut)
        {
            if (CompressionAlgorithm != CompressionAlgorithmTag.Uncompressed)
            {
                var compressedDataGenerator =
                    new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);
                return compressedDataGenerator.Open(encryptedOut);
            }

            return encryptedOut;
        }

        #endregion ChainCompressedOut

        #region ChainLiteralOut

		private Stream ChainLiteralOut(Stream compressedOut, FileInfo file, string name, bool oldFormat)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator(oldFormat);

            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, file.Length,
				DateTime.UtcNow);
		}

		private Stream ChainLiteralOut(Stream compressedOut, Stream inputStream, string name, bool oldFormat)
		{
			PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator(oldFormat);
			return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), name, inputStream.Length,
				DateTime.UtcNow);
		}

        #endregion ChainLiteralOut

        #region InitSignatureGenerator

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut)
		{
			PublicKeyAlgorithmTag tag = EncryptionKeys.SigningSecretKey.PublicKey.Algorithm;
			PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
			pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, EncryptionKeys.SigningPrivateKey);
			foreach (string userId in EncryptionKeys.SigningSecretKey.PublicKey.GetUserIds())
			{
				PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
				subPacketGenerator.AddSignerUserId(false, userId);
				pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
				// Just the first one!
				break;
			}

            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
            return pgpSignatureGenerator;
        }

        #endregion InitSignatureGenerator

        #region InitClearSignatureGenerator

		private PgpSignatureGenerator InitClearSignatureGenerator(ArmoredOutputStream armoredOutputStream)
		{
			PublicKeyAlgorithmTag tag = EncryptionKeys.SigningSecretKey.PublicKey.Algorithm;
			PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag);
			pgpSignatureGenerator.InitSign(PgpSignature.CanonicalTextDocument, EncryptionKeys.SigningPrivateKey);
			armoredOutputStream.BeginClearText(HashAlgorithmTag);
			foreach (string userId in EncryptionKeys.SigningSecretKey.PublicKey.GetUserIds())
			{
				PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
				subPacketGenerator.AddSignerUserId(false, userId);
				pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
				// Just the first one!
				break;
			}

            return pgpSignatureGenerator;
        }

        #endregion InitClearSignatureGenerator

        #region Misc Utilities

        private char FileTypeToChar()
        {
            switch (FileType)
            {
                case PgpFileType.Utf8:
                    return PgpLiteralData.Utf8;
                case PgpFileType.Text:
                    return PgpLiteralData.Text;
                case PgpFileType.Binary:
                default:
                    return PgpLiteralData.Binary;
            }
        }

        private static void ExportKeyPair(
            Stream secretOut,
            Stream publicOut,
            PgpSecretKey secretKey,
            bool armor,
            bool emitVersion)
        {
            if (secretOut == null)
                throw new ArgumentException("secretOut");
            if (publicOut == null)
                throw new ArgumentException("publicOut");

            ArmoredOutputStream secretOutArmored;
            if (armor)
            {
                secretOutArmored = new ArmoredOutputStream(secretOut);
                if (!emitVersion) secretOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);

                secretOut = secretOutArmored;
            }
            else
            {
                secretOutArmored = null;
            }

            secretKey.Encode(secretOut);

            secretOutArmored?.Dispose();

            ArmoredOutputStream publicOutArmored;
            if (armor)
            {
                publicOutArmored = new ArmoredOutputStream(publicOut);
                if (!emitVersion) publicOutArmored.SetHeader(ArmoredOutputStream.HeaderVersion, null);

                publicOut = publicOutArmored;
            }
            else
            {
                publicOutArmored = null;
            }

            var key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOutArmored?.Dispose();
        }

        private static int ReadInputLine(Stream streamOut, Stream encodedFile)
        {
            streamOut.SetLength(0);

            var lookAhead = -1;
            int character;

            while ((character = encodedFile.ReadByte()) >= 0)
            {
                streamOut.WriteByte((byte) character);
                if (character == '\r' || character == '\n')
                {
                    lookAhead = ReadPassedEol(streamOut, character, encodedFile);
                    break;
                }
            }

            return lookAhead;
        }

        private static int ReadInputLine(Stream streamOut, int lookAhead, Stream encodedFile)
        {
            streamOut.SetLength(0);

            var character = lookAhead;

            do
            {
                streamOut.WriteByte((byte) character);
                if (character == '\r' || character == '\n')
                {
                    lookAhead = ReadPassedEol(streamOut, character, encodedFile);
                    break;
                }
            } while ((character = encodedFile.ReadByte()) >= 0);

            if (character < 0) lookAhead = -1;

            return lookAhead;
        }

        private static int ReadPassedEol(Stream streamOut, int lastCharacter, Stream encodedFile)
        {
            var lookAhead = encodedFile.ReadByte();

            if (lastCharacter == '\r' && lookAhead == '\n')
            {
                streamOut.WriteByte((byte) lookAhead);
                lookAhead = encodedFile.ReadByte();
            }

            return lookAhead;
        }

        private static int GetLengthWithoutSeparatorOrTrailingWhitespace(IReadOnlyList<byte> line)
        {
            var end = line.Count - 1;

            while (end >= 0 && IsWhiteSpace(line[end])) end--;

            return end + 1;
        }

        private static int GetLengthWithoutWhiteSpace(IReadOnlyList<byte> line)
        {
            var end = line.Count - 1;

            while (end >= 0 && IsWhiteSpace(line[end])) end--;

            return end + 1;
        }

        private static bool IsWhiteSpace(byte b)
        {
            return IsLineEnding(b) || b == '\t' || b == ' ';
        }

        private static bool IsLineEnding(byte b)
        {
            return b == '\r' || b == '\n';
        }

        private static void ProcessLine(PgpSignature sig, byte[] line)
        {
            // note: trailing white space needs to be removed from the end of
            // each line for signature calculation RFC 4880 Section 7.1
            var length = GetLengthWithoutWhiteSpace(line);
            if (length > 0) sig.Update(line, 0, length);
        }

        private static byte[] _lineSeparator => Encoding.ASCII.GetBytes(Environment.NewLine);

        public void Dispose()
        {
        }

        # endregion Misc Utilities

        #endregion Private helpers
    }
}