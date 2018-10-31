// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Encryption.Gost3411.Tests
{
    using System.Linq;

    using Gost3411 = System.Security.Cryptography.Gost3411;

    /// <summary>
    /// Since SHAxCryptoServiceProvider types wraps IncrementalHash from Algorithms assembly, we only test minimally here.
    /// </summary>
    public class Gost3411CryptoServiceProviderTests
    {
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


        [Fact]
        public void Gost3411CreateAndComputeHash()
        {
            var gost = Gost3411.Create();
            var hash = gost.ComputeHash(bytesToHash);
            var isValidHash = hash.SequenceEqual(computedHash);

            Assert.True(isValidHash);
        }

        [Fact]
        public void Gost3411ConstructorAndHash()
        {
            Gost3411 gost = new Gost3411CryptoServiceProvider();
            var hash = gost.ComputeHash(bytesToHash);
            var isValidHash = hash.SequenceEqual(computedHash);

            Assert.True(isValidHash);
        }

        [Fact]
        public void Gost3411ComputeHashTwice()
        {
            Gost3411 gost = Gost3411.Create("GOST3411");
            gost.ComputeHash(gost.ComputeHash(bytesToHash));
        }

        private void Verify<T>(string rawText, string expected) where T:HashAlgorithm, new()
        {
            byte[] inputBytes = ByteUtils.AsciiBytes(rawText);
            byte[] expectedBytes = ByteUtils.HexToByteArray(expected);

            using (HashAlgorithm hash = new T())
            {
                Assert.True(hash.HashSize > 0);
                byte[] actual = hash.ComputeHash(inputBytes, 0, inputBytes.Length);

                Assert.Equal(expectedBytes, actual);

                actual = hash.Hash;
                Assert.Equal(expectedBytes, actual);
            }
        }
    }
}
