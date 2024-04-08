using Org.BouncyCastle.Bcpg.OpenPgp;
using PgpCore.Abstractions;
using PgpCore.Extensions;
using PgpCore.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace PgpCore
{
    public partial class Pgp : IInspectAsync
    {
        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="inputStream">The input stream containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public async Task<PgpInspectResult> InspectAsync(Stream inputStream)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (inputStream.Position != 0)
                throw new ArgumentException("inputStream should be at start of stream");

            var isArmored = await IsArmoredAsync(inputStream);
            Dictionary<string, string> messageHeaders = null;

            if (isArmored)
                messageHeaders = await GetMessageHeadersAsync(inputStream);

            var pgpInspectBaseResult = GetPgpInspectBaseResult(inputStream);

            return new PgpInspectResult(
                pgpInspectBaseResult,
                isArmored,
                messageHeaders
            );
        }

        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="inputFile">The input file containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public async Task<PgpInspectResult> InspectAsync(FileInfo inputFile)
        {
            if (inputFile == null)
                throw new ArgumentException("InputFile");
            if (!inputFile.Exists)
                throw new FileNotFoundException($"Input file [{inputFile.FullName}] does not exist.");

            using (var inputStream = inputFile.OpenRead())
            {
                return await InspectAsync(inputStream);
            }
        }

        /// <summary>
        /// Inspect an arbitrary PGP message returning information about the message
        /// </summary>
        /// <param name="input">The input string containing the PGP message</param>
        /// <returns>Returns an object containing details of the provided PGP message</returns>
        /// <exception cref="ArgumentException">Exception returned if input argument is invalid</exception>
        /// <exception cref="PgpException">Exception returned if the input is not a PGP object</exception>
        public async Task<PgpInspectResult> InspectAsync(string input)
        {
            if (string.IsNullOrEmpty(input))
                throw new ArgumentException("Input");

            using (var inputStream = await input.GetStreamAsync())
            {
                return await InspectAsync(inputStream);
            }
        }

        private static async Task<bool> IsArmoredAsync(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);
            var headerBytes = new byte[26];
            await stream.ReadAsync(headerBytes, 0, 26);
            return IsArmored(headerBytes);
        }

        private static async Task<Dictionary<string, string>> GetMessageHeadersAsync(Stream inputStream)
        {
            var headers = new Dictionary<string, string>();

            var reader = new StreamReader(inputStream);
            string line;

            while ((line = await reader.ReadLineAsync()) != null)
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
    }
}