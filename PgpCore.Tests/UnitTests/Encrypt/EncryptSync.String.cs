using FluentAssertions.Execution;
using FluentAssertions;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using PgpCore.Models;

namespace PgpCore.Tests.UnitTests.Encrypt
{
    public class EncryptSync_String : TestBase
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(encryptedContent);
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
        public void Encrypt_EncryptMessageWithoutIntegrityCheck_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(encryptedContent);
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content, name: Testname);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(encryptedContent);
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(encryptedContent);
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content, headers: new Dictionary<string, string> { { "Version", Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(encryptedContent);
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
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = pgpEncrypt.Encrypt(testFactory.Content, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpEncrypt.Inspect(encryptedContent);
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
            string encryptedContent = pgpEncrypt.EncryptAndSign(testFactoryEncrypt.Content);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(encryptedContent);
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
            string encryptedContent = pgpEncrypt.EncryptAndSign(testFactoryEncrypt.Content, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(encryptedContent);
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
            string encryptedContent = pgpEncrypt.EncryptAndSign(testFactoryEncrypt.Content, name: Testname);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(encryptedContent);
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
            string encryptedContent = pgpEncrypt.EncryptAndSign(testFactoryEncrypt.Content, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(encryptedContent);
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
            string encryptedContent = pgpEncrypt.EncryptAndSign(testFactoryEncrypt.Content, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpInspect.Inspect(encryptedContent);
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
