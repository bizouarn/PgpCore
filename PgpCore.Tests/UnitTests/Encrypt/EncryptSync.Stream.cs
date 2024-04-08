using FluentAssertions.Execution;
using FluentAssertions;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using PgpCore.Models;
using System.IO;

namespace PgpCore.Tests.UnitTests.Encrypt
{
    public class EncryptSync_Stream : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Encrypt_EncryptMessageWithDefaultProperties_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Encrypt_EncryptMessageAsBinary_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, armor: false);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeFalse();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().NotBeNullOrEmpty();
                pgpInspectResult.MessageHeaders.Should().BeNullOrEmpty();
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Encrypt_EncryptMessageWithoutIntegrityCheck_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeFalse();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Encrypt_EncryptMessageWithName_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, name: Testname);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Testname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Encrypt_EncryptMessageWithHeaders_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(2);
                pgpInspectResult.MessageHeaders.First().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.First().Value.Should().Be(Version);
                pgpInspectResult.MessageHeaders.Last().Key.Should().Be(Testheaderkey);
                pgpInspectResult.MessageHeaders.Last().Value.Should().Be(Testheadervalue);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Encrypt_EncryptMessageAndOverwriteVersionHeader_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, headers: new Dictionary<string, string> { { "Version", Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Testheadervalue);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Encrypt_EncryptMessageWithOldFormat_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKeyStream, testFactory.PrivateKeyStream, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpEncrypt.Encrypt(testFactory.ContentStream, outputFileStream, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeFalse();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptAndSign_EncryptAndSignMessageWithDefaultProperties_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            testFactoryEncrypt.Arrange(keyType, FileType.Known);
            testFactorySign.Arrange(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            using (Stream outputFileStream = testFactoryEncrypt.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptAndSign(testFactoryEncrypt.ContentStream, outputFileStream);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptAndSign_EncryptAndSignMessageAsBinary_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            testFactoryEncrypt.Arrange(keyType, FileType.Known);
            testFactorySign.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            using (Stream outputFileStream = testFactoryEncrypt.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptAndSign(testFactoryEncrypt.ContentStream, outputFileStream, armor: false);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeFalse();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().NotBeNullOrEmpty();
                pgpInspectResult.MessageHeaders.Should().BeNullOrEmpty();
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptAndSign_EncryptAndSignMessageWithoutIntegrityCheck_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            testFactoryEncrypt.Arrange(keyType, FileType.Known);
            testFactorySign.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            using (Stream outputFileStream = testFactoryEncrypt.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptAndSign(testFactoryEncrypt.ContentStream, outputFileStream, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeFalse();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptAndSign_EncryptAndSignMessageWithName_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            testFactoryEncrypt.Arrange(keyType, FileType.Known);
            testFactorySign.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            using (Stream outputFileStream = testFactoryEncrypt.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptAndSign(testFactoryEncrypt.ContentStream, outputFileStream, name: Testname);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Testname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptAndSign_EncryptAndSignMessageWithHeaders_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            testFactoryEncrypt.Arrange(keyType, FileType.Known);
            testFactorySign.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            using (Stream outputFileStream = testFactoryEncrypt.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptAndSign(testFactoryEncrypt.ContentStream, outputFileStream, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(2);
                pgpInspectResult.MessageHeaders.First().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.First().Value.Should().Be(Version);
                pgpInspectResult.MessageHeaders.Last().Key.Should().Be(Testheaderkey);
                pgpInspectResult.MessageHeaders.Last().Value.Should().Be(Testheadervalue);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void EncryptAndSign_EncryptAndSignMessageWithOldFormat_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            testFactoryEncrypt.Arrange(keyType, FileType.Known);
            testFactorySign.Arrange(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            using (Stream outputFileStream = testFactoryEncrypt.EncryptedContentFileInfo.Create())
                pgpEncrypt.EncryptAndSign(testFactoryEncrypt.ContentStream, outputFileStream, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                testFactoryEncrypt.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(testFactoryEncrypt.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeTrue();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
                pgpInspectResult.IsIntegrityProtected.Should().BeTrue();
                pgpInspectResult.FileName.Should().Be(Defaultname);
                pgpInspectResult.MessageHeaders.Should().HaveCount(1);
                pgpInspectResult.MessageHeaders.Single().Key.Should().Be("Version");
                pgpInspectResult.MessageHeaders.Single().Value.Should().Be(Version);
            }

            // Teardown
            testFactoryEncrypt.Teardown();
            testFactorySign.Teardown();
        }
    }
}
