using FluentAssertions.Execution;
using FluentAssertions;
using PgpCore.Models;
using System.Collections.Generic;
using System.Linq;
using Xunit;
using System.IO;

namespace PgpCore.Tests.UnitTests.Sign
{
    public class SignSync_Stream : TestBase
    {
        [Theory]
        [InlineData(KeyType.Generated)]
        [InlineData(KeyType.Known)]
        [InlineData(KeyType.KnownGpg)]
        public void Sign_SignMessageWithDefaultProperties_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpSign.Sign(testFactory.ContentStream, outputFileStream);

            bool verified = pgpVerify.Verify(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(testFactory.EncryptedContentFileInfo);
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
        public void Sign_SignMessageAsBinary_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpSign.Sign(testFactory.ContentStream, outputFileStream, armor: false);

            bool verified = pgpVerify.Verify(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(testFactory.EncryptedContentFileInfo);
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
        public void Sign_SignMessageWithName_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpSign.Sign(testFactory.ContentStream, outputFileStream, name: Testname);

            bool verified = pgpVerify.Verify(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(testFactory.EncryptedContentFileInfo);
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
        public void Sign_SignMessageWithHeaders_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpSign.Sign(testFactory.ContentStream, outputFileStream, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            bool verified = pgpVerify.Verify(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(testFactory.EncryptedContentFileInfo);
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
        public void Sign_SignMessageWithOldFormat_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpSign.Sign(testFactory.ContentStream, outputFileStream, oldFormat: true);

            bool verified = pgpVerify.Verify(testFactory.EncryptedContentStream);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                testFactory.EncryptedContentFileInfo.Exists.Should().BeTrue();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(testFactory.EncryptedContentFileInfo);
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
        public void ClearSign_SignMessageWithDefaultProperties_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpSign.ClearSign(testFactory.ContentStream, outputFileStream);

            bool verified = pgpVerify.VerifyClear(testFactory.EncryptedContentStream);

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
        public void ClearSign_SignMessageWithHeaders_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKeyStream, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKeyStream);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            using (Stream outputFileStream = testFactory.EncryptedContentFileInfo.Create())
                pgpSign.ClearSign(testFactory.ContentStream, outputFileStream, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });

            bool verified = pgpVerify.VerifyClear(testFactory.EncryptedContentStream);

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
