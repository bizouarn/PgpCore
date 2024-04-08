using FluentAssertions.Execution;
using FluentAssertions;
using PgpCore.Models;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace PgpCore.Tests.UnitTests.Sign
{
    public class SignSync_String : TestBase
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
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            string signedContent = pgpSign.Sign(testFactory.Content);
            bool verified = pgpVerify.Verify(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(signedContent);
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
        public void Sign_SignMessageWithName_ShouldSignMessage(KeyType keyType)
        {
            // Arrange
            TestFactory testFactory = new TestFactory();
            testFactory.Arrange(keyType, FileType.Known);
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            string signedContent = pgpSign.Sign(testFactory.Content, name: Testname);
            bool verified = pgpVerify.Verify(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(signedContent);
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
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            string signedContent = pgpSign.Sign(testFactory.Content, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });
            bool verified = pgpVerify.Verify(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(signedContent);
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
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            string signedContent = pgpSign.Sign(testFactory.Content, oldFormat: true);
            bool verified = pgpVerify.Verify(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
            }

            using (new AssertionScope())
            {
                signedContent.Should().NotBeNullOrEmpty();
                PgpInspectResult pgpInspectResult = pgpSign.Inspect(signedContent);
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
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            string signedContent = pgpSign.ClearSign(testFactory.Content);
            bool verified = pgpVerify.VerifyClear(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                signedContent.Should().Contain(testFactory.Content);
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
            EncryptionKeys signingKeys = new EncryptionKeys(testFactory.PrivateKey, testFactory.Password);
            EncryptionKeys verificationKeys = new EncryptionKeys(testFactory.PublicKey);
            Pgp pgpSign = new Pgp(signingKeys);
            Pgp pgpVerify = new Pgp(verificationKeys);

            // Act
            string signedContent = pgpSign.ClearSign(testFactory.Content, headers: new Dictionary<string, string> { { Testheaderkey, Testheadervalue } });
            bool verified = pgpVerify.VerifyClear(signedContent);

            // Assert
            using (new AssertionScope())
            {
                verified.Should().BeTrue();
                signedContent.Should().Contain(testFactory.Content);
            }

            // Teardown
            testFactory.Teardown();
        }
    }
}
