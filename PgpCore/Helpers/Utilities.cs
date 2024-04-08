using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg.Sig;
using PgpCore.Extensions;

namespace PgpCore.Helpers
{
    /// <remarks>Basic utility class.</remarks>
    public static class Utilities
    {
        public static Task WriteStreamToLiteralDataAsync(
            Stream output,
            char fileType,
            Stream input,
            string name,
            bool oldFormat)
        {
            var lData = new PgpLiteralDataGenerator(oldFormat);
            var pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
            return PipeStreamContentsAsync(input, pOut, 4096);
        }

        public static void WriteStreamToLiteralData(
            Stream output,
            char fileType,
            Stream input,
            string name,
            bool oldFormat)
        {
            var lData = new PgpLiteralDataGenerator(oldFormat);
            var pOut = lData.Open(output, fileType, name, input.Length, DateTime.Now);
            PipeStreamContents(input, pOut, 4096);
        }

        /// <summary>
        /// Opens a key ring file and returns first available sub-key suitable for encryption.
        /// If such sub-key is not found, return master key that can encrypt.
        /// </summary>
        /// <param name="publicKeyStream">Input stream containing the public key contents</param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(Stream publicKeyStream)
        {
            using (var inputStream = PgpUtilities.GetDecoderStream(publicKeyStream))
            {
                var pgpPub = new PgpPublicKeyRingBundle(inputStream);

                // we just loop through the collection till we find a key suitable for encryption, in the real
                // world you would probably want to be a bit smarter about this.
                // iterate through the key rings.
                foreach (var kRing in pgpPub.GetKeyRings())
                {
                    var keys = kRing.GetPublicKeys()
                        .Where(k => k.IsEncryptionKey).ToList();

                    const int encryptKeyFlags = PgpKeyFlags.CanEncryptCommunications | PgpKeyFlags.CanEncryptStorage;

                    foreach (var key in keys.Where(k => k.Version >= 4))
                    foreach (var s in key.GetSignatures())
                        if (s.HasSubpackets && s.GetHashedSubPackets().GetKeyFlags() == encryptKeyFlags)
                            return key;
                    if (keys.Count > 0)
                        return keys[0];
                }
            }

            throw new ArgumentException("Can't find encryption key in key ring.");
        }

        /// <summary>
        /// Parses a public key
        /// </summary>
        /// <param name="publicKey">The plain text value of the public key</param>
        /// <returns></returns>
        public static PgpPublicKey ReadPublicKey(string publicKey)
        {
            if (string.IsNullOrEmpty(publicKey))
                throw new FileNotFoundException("Public key was not provided");

            return ReadPublicKey(publicKey.GetStream());
        }

        /// <summary>
        /// Opens a key ring file and returns all public keys found.
        /// </summary>
        /// <param name="publicKeyStream">Input stream containing the public key contents</param>
        /// <returns></returns>
        public static PgpPublicKeyRingBundle ReadPublicKeyRingBundle(Stream publicKeyStream)
        {
            using (var inputStream = PgpUtilities.GetDecoderStream(publicKeyStream))
            {
                return new PgpPublicKeyRingBundle(inputStream);
            }
        }

        /// <summary>
        /// Returns all public key rings from multiple public key streams
        /// </summary>
        /// <param name="publicKeyStreams"></param>
        /// <returns></returns>
        public static IEnumerable<PgpPublicKeyRing> ReadAllKeyRings(IEnumerable<Stream> publicKeyStreams)
        {
            var publicKeyBundles = publicKeyStreams.Select(ReadPublicKeyRingBundle);
            return ReadAllKeyRings(publicKeyBundles);
        }

        /// <summary>
        /// Returns all public key rings from a public key stream
        /// </summary>
        /// <param name="publicKeyStream"></param>
        /// <returns></returns>
        public static IEnumerable<PgpPublicKeyRing> ReadAllKeyRings(Stream publicKeyStream)
        {
            var publicKeyBundles = ReadPublicKeyRingBundle(publicKeyStream);
            return publicKeyBundles.GetKeyRings();
        }

        private static IEnumerable<PgpPublicKeyRing> ReadAllKeyRings(
            IEnumerable<PgpPublicKeyRingBundle> publicKeyRingBundles)
        {
            return publicKeyRingBundles.SelectMany(bundle => bundle.GetKeyRings());
        }

        /// <summary>
        /// Returns the secret key ring bundle from a private key stream
        /// </summary>
        /// <param name="privateKeyStream"></param>
        /// <returns></returns>
        public static PgpSecretKeyRingBundle ReadSecretKeyRingBundle(Stream privateKeyStream)
        {
            using (var inputStream = PgpUtilities.GetDecoderStream(privateKeyStream))
            {
                return new PgpSecretKeyRingBundle(inputStream);
            }
        }

        /// <summary>
        /// Finds and returns the public key most suitable for verification in a key ring. Master keys are prioritized
        /// </summary>
        /// <param name="publicKeys"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static PgpPublicKey FindBestVerificationKey(PgpPublicKeyRing publicKeys)
        {
            var keys = publicKeys.GetPublicKeys().ToArray();

            // Has Key Flags for signing content
            var verificationKeys = keys.Where(key => GetSigningScore(key) >= 3).ToArray();
            // Failsafe, get master key with signing capabilities.
            if (!verificationKeys.Any())
                verificationKeys = keys.Where(key => GetSigningScore(key) >= 1).ToArray();

            var signingKeys = verificationKeys.OrderByDescending(GetSigningScore).ToList();
            if (signingKeys.Count <= 0)
                throw new ArgumentException("No verification keys in keyring");

            return signingKeys[0];
        }

        /// <summary>
        /// Finds and returns the public key most suitable for encryption in a key ring. Master keys are prioritized
        /// </summary>
        /// <param name="publicKeys"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static PgpPublicKey FindBestEncryptionKey(PgpPublicKeyRing publicKeys)
        {
            var keys = publicKeys.GetPublicKeys().ToArray();
            // Is encryption key and has the two encryption key flags
            var encryptKeys = keys.Where(key => GetEncryptionScore(key) >= 4).ToArray();

            // If no suitable encryption keys are found, get master key with encryption capability
            if (!encryptKeys
                    .Any())
                encryptKeys = keys.Where(key => GetEncryptionScore(key) >= 3).ToArray();

            // Otherwise get any keys with encryption capability
            if (!encryptKeys
                    .Any())
                encryptKeys = keys.Where(key => GetEncryptionScore(key) >= 2).ToArray();

            var encryptionKeys = encryptKeys.OrderByDescending(GetEncryptionScore).ToList();
            if (encryptionKeys.Count <= 0)
                throw new ArgumentException("No encryption keys in keyring");
            return encryptionKeys[0];
        }

        /// <summary>
        /// Finds the first secret key in the key ring suitable for signing. 
        /// </summary>
        /// <param name="secretKeyRingBundle">The key ring bundle to search</param>
        /// <returns></returns>
        /// <exception cref="ArgumentException">When no rings are suitable for signing</exception>
        public static PgpSecretKey FindBestSigningKey(PgpSecretKeyRingBundle secretKeyRingBundle)
        {
            var keyRings = secretKeyRingBundle.GetKeyRings().ToArray();

            var secretKeys = keyRings.SelectMany(ring => ring.GetSecretKeys())
                .OrderByDescending(GetSigningScore).ToArray();

            if (secretKeys.Length <= 0)
                throw new ArgumentException("Could not find any signing keys in keyring");
            return secretKeys[0];
        }

        /// <summary>
        /// Finds and returns the master key
        /// </summary>
        /// <param name="publicKeys"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static PgpPublicKey FindMasterKey(PgpPublicKeyRing publicKeys)
        {
            var keys = publicKeys.GetPublicKeys().ToArray();

            return keys.Single(x => x.IsMasterKey);
        }

        /// <summary>
        /// Checks if the key with the given id is present in the collection of public keys, and if it is, return it.
        /// </summary>
        /// <param name="keyId"></param>
        /// <param name="verificationKeys"></param>
        /// <param name="verificationKey"></param>
        /// <returns></returns>
        public static bool FindPublicKey(long keyId, IEnumerable<PgpPublicKey> verificationKeys,
            out PgpPublicKey verificationKey)
        {
            var foundKeys = verificationKeys.Where(key =>
                key.KeyId == keyId ||
                key.GetSignatures().Any(signature => signature.KeyId == keyId)).ToArray();
            verificationKey = foundKeys.FirstOrDefault();
            return foundKeys.Any();
        }

        public static bool FindPublicKeyInKeyRings(long keyId, IEnumerable<PgpPublicKeyRing> publicKeyRings,
            out PgpPublicKey verificationKey)
        {
            verificationKey = null;

            foreach (var publicKeyRing in publicKeyRings)
            {
                var verificationKeys = publicKeyRing.GetPublicKeys();
                if (FindPublicKey(keyId, verificationKeys, out verificationKey))
                    return true;
            }

            return false;
        }

        private static async Task PipeStreamContentsAsync(Stream input, Stream pOut, int bufSize)
        {
            var buf = new byte[bufSize];

            int len;
            while ((len = await input.ReadAsync(buf, 0, buf.Length)) > 0) await pOut.WriteAsync(buf, 0, len);
        }

        private static void PipeStreamContents(Stream input, Stream pOut, int bufSize)
        {
            var buf = new byte[bufSize];

            int len;
            while ((len = input.Read(buf, 0, buf.Length)) > 0) pOut.Write(buf, 0, len);
        }

        public static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(Stream encodedFile)
        {
            var encryptedDataList = GetEncryptedDataList(encodedFile);
            return ExtractPublicKey(encryptedDataList);
        }


        public static PgpPublicKeyEncryptedData ExtractPublicKey(PgpEncryptedDataList encryptedDataList)
        {
            return encryptedDataList.GetEncryptedDataObjects().Cast<PgpPublicKeyEncryptedData>()
                .FirstOrDefault(encryptedData => encryptedData != null);
        }

        public static PgpEncryptedDataList GetEncryptedDataList(Stream encodedFile)
        {
            var factory = new PgpObjectFactory(encodedFile);
            var pgpObject = factory.NextPgpObject();

            PgpEncryptedDataList encryptedDataList;

            if (pgpObject is PgpEncryptedDataList dataList)
                encryptedDataList = dataList;
            else
                encryptedDataList = (PgpEncryptedDataList) factory.NextPgpObject();

            return encryptedDataList;
        }

        /// <summary>
        /// Scores the public key for how suitable it is as an encryption key
        /// Master key += 1
        /// IsEncryptionKey += 2
        /// Either of the encryption flags += 1 (for each)
        /// Highest score is 5
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        private static int GetEncryptionScore(PgpPublicKey key)
        {
            var score = 0;
            if (key.IsMasterKey)
                score += 1;
            if (key.IsEncryptionKey)
                score += 2;
            var signatures = key.GetSignatures()
                .Where(signature => signature.HasSubpackets).ToList();

            if (signatures.Exists(signature =>
                    (signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.EncryptComms) > 0))
                score += 1;
            if (signatures.Exists(signature =>
                    (signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.EncryptStorage) > 0))
                score += 1;
            return score;
        }

        /// <summary>
        /// Scores the public key for how suitable it is as a verification key
        /// Master key += 1
        /// Signing key flag += 2
        /// Highest score is 3
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        private static int GetSigningScore(PgpPublicKey key)
        {
            var score = 0;
            if (key.IsMasterKey)
                score += 1;
            var signatures = key.GetSignatures();
            if (signatures.Any(signature => signature.HasSubpackets &&
                                            (signature.GetHashedSubPackets().GetKeyFlags() & KeyFlags.SignData) > 0))
                score += 2;
            return score;
        }

        /// <summary>
        /// Scores the secret key for how suitable it is as a signing key
        /// Master key += 1
        /// IsSigningKey += 2
        /// Signing key flag += 2
        /// Highest score is 5
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        private static int GetSigningScore(PgpSecretKey key)
        {
            var score = 0;
            if (key.IsSigningKey)
                score += 2;
            score += GetSigningScore(key.PublicKey);
            return score;
        }
    }
}