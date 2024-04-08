using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace PgpCore.Tests
{
    public class TestFactory
    {
        private string _uniqueIdentifier;
        private string _userName;
        private string _password;

        public TestFactory()
        {
            _uniqueIdentifier = Guid.NewGuid().ToString();
        }

        public TestFactory(string uniqueIdentifier)
        {
            _uniqueIdentifier = uniqueIdentifier;
        }

        public string ContentDirectory => $"{Constants.Contentbasedirectory}{_uniqueIdentifier}/";

        public string KeyDirectory => $"{Constants.Keybasedirectory}{_uniqueIdentifier}/";

        public string Content => Constants.Content;

        private string _contentFilePath => $"{ContentDirectory}{Constants.Contentfilename}";

        public FileInfo ContentFileInfo => new FileInfo(_contentFilePath);

        public Stream ContentStream => GetFileStream(ContentFileInfo);

        private string _encryptedContentFilePath => $"{ContentDirectory}{Constants.Encryptedcontentfilename}";

        public FileInfo EncryptedContentFileInfo => new FileInfo(_encryptedContentFilePath);

        public string EncryptedContent => File.ReadAllText(_encryptedContentFilePath);

        public Stream EncryptedContentStream => GetFileStream(EncryptedContentFileInfo);

        private string _signedContentFilePath => $"{ContentDirectory}{Constants.Signedcontentfilename}";

        public FileInfo SignedContentFileInfo => new FileInfo(_signedContentFilePath);

        public string SignedContent => File.ReadAllText(_signedContentFilePath);

        public Stream SignedContentStream => GetFileStream(SignedContentFileInfo);

        private string _decryptedContentFilePath => $"{ContentDirectory}{Constants.Decryptedcontentfilename}";

        public FileInfo DecryptedContentFileInfo => new FileInfo(_decryptedContentFilePath);

        public string DecryptedContent => File.ReadAllText(_decryptedContentFilePath);

        public Stream DecryptedContentStream => GetFileStream(DecryptedContentFileInfo);

        private string _privateKeyFilePath => $"{KeyDirectory}{Constants.Privatekeyfilename}";

        public FileInfo PrivateKeyFileInfo => new FileInfo(_privateKeyFilePath);

        public string PrivateKey => File.ReadAllText(_privateKeyFilePath);

        public Stream PrivateKeyStream => GetFileStream(PrivateKeyFileInfo);

        private string _publicKeyFilePath => $"{KeyDirectory}{Constants.Publickeyfilename}";

        public FileInfo PublicKeyFileInfo => new FileInfo(_publicKeyFilePath);

        public string PublicKey => File.ReadAllText(_publicKeyFilePath);

        public Stream PublicKeyStream => GetFileStream(PublicKeyFileInfo);

        public string UserName => _userName != null ? _userName : $"{_uniqueIdentifier}@email.com" ;

        public string Password => _password != null ? _password : _uniqueIdentifier;

        public void Arrange(KeyType keyType)
        {
            Arrange();
            Pgp pgp = new Pgp();

            // Create keys
            if (keyType == KeyType.Generated)
            {
                pgp.GenerateKey(PublicKeyFileInfo, PrivateKeyFileInfo, UserName, Password);
            }
            else if (keyType == KeyType.Known)
            {
                using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                {
                    streamWriter.WriteLine(Constants.Publickey1);
                }

                using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                {
                    streamWriter.WriteLine(Constants.Privatekey1);
                }

                _userName = Constants.Username1;
                _password = Constants.Password1;
            }
            else if (keyType == KeyType.KnownGpg)
            {
                using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                {
                    streamWriter.WriteLine(Constants.Publicgpgkey1);
                }

                using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                {
                    streamWriter.WriteLine(Constants.Privategpgkey1);
                }

                _userName = Constants.Username1;
                _password = Constants.Password1;
            }
        }

        public async Task ArrangeAsync(KeyType keyType)
        {
            Arrange();
            Pgp pgp = new Pgp();

            // Create keys
            if (keyType == KeyType.Generated)
            {
                pgp.GenerateKey(PublicKeyFileInfo, PrivateKeyFileInfo, UserName, Password);
            }
            else if (keyType == KeyType.Known)
            {
                using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                {
                    await streamWriter.WriteLineAsync(Constants.Publickey1);
                }

                using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                {
                    await streamWriter.WriteLineAsync(Constants.Privatekey1);
                }

                _userName = Constants.Username1;
                _password = Constants.Password1;
            }
            else if (keyType == KeyType.KnownGpg)
            {
                using (StreamWriter streamWriter = PublicKeyFileInfo.CreateText())
                {
                    await streamWriter.WriteLineAsync(Constants.Publicgpgkey1);
                }

                using (StreamWriter streamWriter = PrivateKeyFileInfo.CreateText())
                {
                    await streamWriter.WriteLineAsync(Constants.Privategpgkey1);
                }

                _userName = Constants.Username1;
                _password = Constants.Password1;
            }
        }

        public void Arrange(FileType fileType)
        {
            Arrange();

            // Create content file
            if (fileType == FileType.Known)
            {
                using (StreamWriter streamWriter = ContentFileInfo.CreateText())
                {
                    streamWriter.Write(Constants.Content);
                }
            }
            else if (fileType == FileType.GeneratedMedium)
            {
                CreateRandomFile(_contentFilePath, 300);
            }
            else if (fileType == FileType.GeneratedLarge)
            {
                CreateRandomFile(_contentFilePath, 5000);
            }
        }

        public async Task ArrangeAsync(FileType fileType)
        {
            Arrange();

            // Create content file
            if (fileType == FileType.Known)
            {
                using (StreamWriter streamWriter = ContentFileInfo.CreateText())
                {
                    await streamWriter.WriteAsync(Constants.Content);
                }
            }
            else if (fileType == FileType.GeneratedMedium)
            {
                await CreateRandomFileAsync(_contentFilePath, 300);
            }
            else if (fileType == FileType.GeneratedLarge)
            {
                await CreateRandomFileAsync(_contentFilePath, 5000);
            }
        }

        public void Arrange(KeyType keyType, FileType fileType)
        {
            Arrange();
            Arrange(keyType);
            Arrange(fileType);
        }

        public async Task ArrangeAsync(KeyType keyType, FileType fileType)
        {
            Arrange();
            await ArrangeAsync(keyType);
            await ArrangeAsync(fileType);
        }

        public void Arrange()
        {
            if (!Directory.Exists(ContentDirectory))
            {
                Directory.CreateDirectory(ContentDirectory);
            }

            if (!Directory.Exists(KeyDirectory))
            {
                Directory.CreateDirectory(KeyDirectory);
            }
        }

        public void Teardown()
        {
            if (Directory.Exists(ContentDirectory))
            {
                Directory.Delete(ContentDirectory, true);
            }

            if (Directory.Exists(KeyDirectory))
            {
                Directory.Delete(KeyDirectory, true);
            }
        }

        private void CreateRandomFile(string filePath, int sizeInMb)
        {
            // Note: block size must be a factor of 1MB to avoid rounding errors
            const int blockSize = 1024 * 8;
            const int blocksPerMb = 1024 * 1024 / blockSize;

            byte[] data = new byte[blockSize];

            using (RandomNumberGenerator crypto = RandomNumberGenerator.Create())
            {
                using (FileStream stream = File.OpenWrite(filePath))
                {
                    for (int i = 0; i < sizeInMb * blocksPerMb; i++)
                    {
                        crypto.GetBytes(data);
                        stream.Write(data, 0, data.Length);
                    }
                }
            }
        }

        private async Task CreateRandomFileAsync(string filePath, int sizeInMb)
        {
            // Note: block size must be a factor of 1MB to avoid rounding errors
            const int blockSize = 1024 * 8;
            const int blocksPerMb = 1024 * 1024 / blockSize;

            byte[] data = new byte[blockSize];

            using (RandomNumberGenerator crypto = RandomNumberGenerator.Create())
            {
                using (FileStream stream = File.OpenWrite(filePath))
                {
                    for (int i = 0; i < sizeInMb * blocksPerMb; i++)
                    {
                        crypto.GetBytes(data);
                        await stream.WriteAsync(data, 0, data.Length);
                    }
                }
            }
        }

        private Stream GetFileStream(FileInfo fileInfo)
        {
            Stream outputStream = new MemoryStream();
            using (FileStream fileStream = fileInfo.OpenRead())
            {
                fileStream.CopyTo(outputStream);
            }

            outputStream.Position = 0;
            outputStream.Seek(0, SeekOrigin.Begin);
            return outputStream;
        }
    }

    public enum KeyType
    {
        Generated,
        Known,
        KnownGpg
    }

    public enum FileType
    {
        GeneratedMedium,
        GeneratedLarge,
        Known
    }
}