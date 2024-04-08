using System;
using System.IO;

namespace PgpCore.Abstractions
{
    public interface IDecryptSync : IDisposable
    {
        void Decrypt(FileInfo inputFile, FileInfo outputFile);
        void Decrypt(Stream inputStream, Stream outputStream);
        string Decrypt(string input);
        void DecryptAndVerify(FileInfo inputFile, FileInfo outputFile);
        void DecryptAndVerify(Stream inputStream, Stream outputStream);
        string DecryptAndVerify(string input);

        void DecryptFile(FileInfo inputFile, FileInfo outputFile);
        void DecryptStream(Stream inputStream, Stream outputStream);
        string DecryptArmoredString(string input);
        void DecryptFileAndVerify(FileInfo inputFile, FileInfo outputFile);
        void DecryptStreamAndVerify(Stream inputStream, Stream outputStream);
        string DecryptArmoredStringAndVerify(string input);
    }
}