using FluentAssertions.Execution;
using FluentAssertions;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using PgpCore.Models;

namespace PgpCore.Tests.UnitTests.Encrypt
{
    public class EncryptAsync_String : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task EncryptAsync_EncryptMessageWithDefaultProperties_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(encryptedContent);
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
        public async Task EncryptAsync_EncryptMessageWithoutIntegrityCheck_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(encryptedContent);
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
        public async Task EncryptAsync_EncryptMessageWithName_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content, name: Testname);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(encryptedContent);
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
        public async Task EncryptAsync_EncryptMessageWithHeaders_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(encryptedContent);
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
        public async Task EncryptAsync_EncryptMessageAndOverwriteVersionHeader_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content, headers: new Dictionary<string, string> { { "Version", Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(encryptedContent);
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
        public async Task EncryptAsync_EncryptMessageWithOldFormat_ShouldEncryptMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactory.PublicKey, testFactory.PrivateKey, testFactory.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAsync(testFactory.Content, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpEncrypt.InspectAsync(encryptedContent);
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
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithDefaultProperties_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);

            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.Content);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(encryptedContent);
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
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithoutIntegrityCheck_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.Content, withIntegrityCheck: false);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(encryptedContent);
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
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithName_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.Content, name: Testname);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(encryptedContent);
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
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithHeaders_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.Content, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(encryptedContent);
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
        public async Task EncryptAndSignAsync_EncryptAndSignMessageWithOldFormat_ShouldEncryptAndSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactoryEncrypt = new TestFactory();
            TestFactory testFactorySign = new TestFactory();
            await testFactoryEncrypt.ArrangeAsync(keyType, FileType.Known);
            await testFactorySign.ArrangeAsync(KeyType.Generated, FileType.Known);
            EncryptionKeys encryptionKeys = new EncryptionKeys(testFactoryEncrypt.PublicKeyFileInfo, testFactorySign.PrivateKeyFileInfo, testFactorySign.Password);
            EncryptionKeys inspectionKeys = new EncryptionKeys(testFactoryEncrypt.PrivateKeyFileInfo, testFactoryEncrypt.Password);
            Pgp pgpEncrypt = new Pgp(encryptionKeys);
            Pgp pgpInspect = new Pgp(inspectionKeys);

            // Act
            string encryptedContent = await pgpEncrypt.EncryptAndSignAsync(testFactoryEncrypt.Content, oldFormat: true);

            // Assert
            using (new AssertionScope())
            {
                encryptedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = await pgpInspect.InspectAsync(encryptedContent);
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
