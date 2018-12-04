// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.


namespace System.Security.Cryptography.Encryption.Gost3410.Tests
{

    using System.Linq;

    using Xunit;

    using System.Security.Cryptography;

    /// <summary>
    /// Since SHAxCryptoServiceProvider types wraps IncrementalHash from Algorithms assembly, we only test minimally here.
    /// </summary>
    public class Gost3410CryptoServiceProviderTests
    {
        const int Gost2001ProvType = 75;

        private static readonly byte[] bytesToHash =
            new byte[]
            {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            };

        private static readonly byte[] computedHash =
            new byte[]
            {
                0x67, 0x3F, 0x02, 0xB6, 0x97, 0xE0, 0xEC, 0xA2,
                0xC3, 0xEA, 0xA6, 0x48, 0xB5, 0x62, 0x9A, 0x27,
                0xC1, 0x5A, 0x79, 0x44, 0xB7, 0xE7, 0x10, 0xED,
                0x8A, 0x4C, 0xF8, 0xCE, 0xA9, 0x09, 0x9E, 0x0F
            };

        [Fact(DisplayName = "Тест PublicOnly проперти при пустом конструкторе")]
        public static void PublicOnlyDefaultKey()
        {
            using (var gost = new Gost3410CryptoServiceProvider())
            {
                // This will call the key into being, which should create a public/private pair,
                // therefore it should not be public-only.
                Assert.False(gost.PublicOnly);
            }
        }

        [Fact(DisplayName = "Тест создания и получения информации о ключе")]
        [PlatformSpecific(TestPlatforms.Windows)] // No support for CspParameters on Unix
        public static void CreateKey()
        {
            CspParameters cspParameters = new CspParameters(Gost2001ProvType);

            using (var gost = new Gost3410CryptoServiceProvider(cspParameters))
            {
                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;
                Assert.Equal(Gost2001ProvType, containerInfo.ProviderType);
            }
        }

        [Fact(DisplayName = "Импорт - экспорт блоба")]
        [PlatformSpecific(TestPlatforms.Windows)] // No support for CspParameters on Unix
        public static void CreateKeyRoundtripBlob()
        {
            const int KeySize = 512;

            CspParameters cspParameters = new CspParameters(Gost2001ProvType);
            byte[] blob;

            using (var gost = new Gost3410CryptoServiceProvider(cspParameters))
            {
                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;
                Assert.Equal(Gost2001ProvType, containerInfo.ProviderType);
                Assert.Equal(KeySize, gost.KeySize);

                blob = gost.ExportCspBlob(false);
            }

            using (var gost = new Gost3410CryptoServiceProvider())
            {
                gost.ImportCspBlob(blob);

                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;

                // The provider information is not persisted in the blob
                Assert.Equal(Gost2001ProvType, containerInfo.ProviderType);
                Assert.Equal(KeySize, gost.KeySize);
            }
        }

        [Fact(DisplayName = "Тест ошибки при проверке при неверном алгоритме хэширования")]
        public static void VerifyHashInvalidHashAlgorithmThrows()
        {
            byte[] hashVal;
            using (SHA1 sha1 = SHA1.Create())
            {
                hashVal = sha1.ComputeHash(bytesToHash);
            }

            using (var gost = new Gost3410CryptoServiceProvider())
            {
                byte[] signVal = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411);
                Assert.ThrowsAny<CryptographicException>(() => gost.VerifyHash(hashVal, signVal));
            }
        }

        //[Fact]
        //public static void SignHashDefaultAlgorithmSuccess()
        //{
        //    byte[] hashVal;
        //    using (Gost3411 gostHash = Gost3411.Create())
        //    {
        //        hashVal = gostHash.ComputeHash(bytesToHash);
        //    }

        //    using (var gost = new Gost3410CryptoServiceProvider())
        //    {
        //        byte[] signVal = gost.SignHash(hashVal);
        //        Assert.True(gost.VerifyHash(hashVal, signVal));
        //    }
        //}

        //[Fact]
        //public static void VerifyHashDefaultAlgorithmSuccess()
        //{
        //    byte[] hashVal;
        //    using (Gost3411 gostHash = Gost3411.Create())
        //    {
        //        hashVal = gostHash.ComputeHash(bytesToHash);
        //    }

        //    using (var gost = new Gost3410CryptoServiceProvider())
        //    {
        //        byte[] signVal = gost.SignData(hashVal);
        //        Assert.True(gost.VerifyHash(hashVal, signVal));
        //    }
        //}

        [Fact(DisplayName = "Тест ошибки при подписи при неверном алгоритме хэширования")]
        public static void SignHashInvalidHashAlgorithmThrows()
        {
            byte[] hashVal;
            using (Gost3411 gostHash = Gost3411.Create())
            {
                hashVal = gostHash.ComputeHash(bytesToHash);
            }

            using (var gost = new Gost3410CryptoServiceProvider())
            {
                Assert.ThrowsAny<CryptographicException>(() => gost.SignHash(hashVal, HashAlgorithmName.SHA256));
            }
        }

        //[Fact(DisplayName = "Тест метода Create и подписи массива данных")]
        //public void Gost3410CreateAndComputeSignatureOnData()
        //{
        //    var gost = Gost3410.Create() as Gost3410CryptoServiceProvider;
        //    gost.SignData(bytesToHash, HashAlgorithmName.Gost3411);
        //}

        [Fact(DisplayName = "Тест пустого конструктора и подписи массива данных")]
        public void Gost3410ConstructorAndComputeSignatureOnData()
        {
            var gost = new Gost3410CryptoServiceProvider();
            gost.SignData(bytesToHash, HashAlgorithmName.Gost3411);
        }

        [Fact(DisplayName = "Тест пустого конструктора и подписи хэш значения")]
        public void Gost3410ConstructorAndComputeSignatureOnHash()
        {
            var gost = new Gost3410CryptoServiceProvider();
            gost.SignHash(computedHash, HashAlgorithmName.Gost3411);
        }
    }
}
