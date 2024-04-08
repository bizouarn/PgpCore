using FluentAssertions.Execution;
using FluentAssertions;
using PgpCore.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Xunit;
using System.IO;

namespace PgpCore.Tests.UnitTests.Sign
{
    public class SignAsync_Stream : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task SignAsync_SignMessageWithDefaultProperties_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory.ContentStream, outputFileStream);

            bool verified = await pgpVerify.VerifyAsync(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
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
        public async Task SignAsync_SignMessageAsBinary_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory.ContentStream, outputFileStream, armor: false);

            bool verified = await pgpVerify.VerifyAsync(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeFalse();
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
        public async Task SignAsync_SignMessageWithName_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory.ContentStream, outputFileStream, name: Testname);

            bool verified = await pgpVerify.VerifyAsync(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
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
        public async Task SignAsync_SignMessageWithHeaders_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory.ContentStream, outputFileStream, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            bool verified = await pgpVerify.VerifyAsync(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
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
        public async Task SignAsync_SignMessageWithOldFormat_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.SignAsync(testFactory.ContentStream, outputFileStream, oldFormat: true);

            bool verified = await pgpVerify.VerifyAsync(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = await pgpSign.InspectAsync(testFactory.EncryptedContentFileInfo);
                pgpInspectResult.IsEncrypted.Should().BeFalse();
                pgpInspectResult.IsSigned.Should().BeTrue();
                pgpInspectResult.IsArmored.Should().BeTrue();
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
        public async Task ClearSignAsync_SignMessageWithDefaultProperties_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.ClearSignAsync(testFactory.ContentStream, outputFileStream);

            bool verified = await pgpVerify.VerifyClearAsync(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().Contain(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }

        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public async Task ClearSignAsync_SignMessageWithHeaders_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            await testFactory.ArrangeAsync(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                await pgpSign.ClearSignAsync(testFactory.ContentStream, outputFileStream, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            bool verified = await pgpVerify.VerifyClearAsync(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                File.ReadAllText(testFactory.EncryptedContentFileInfo.FullName).Should().Contain(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }
    }
}
