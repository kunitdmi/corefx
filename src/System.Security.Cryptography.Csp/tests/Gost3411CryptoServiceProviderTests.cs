// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Encryption.Gost3411.Tests
{
    using System.Linq;

    /// <summary>
    /// Since Gost3411xCryptoServiceProvider types wraps IncrementalHash from Algorithms assembly, we only test minimally here.
    /// </summary>
    public class Gost3411CryptoServiceProviderTests
    {
        [Fact]
        public void GOST3411_Empty()
        {
            Verify<Gost3411CryptoServiceProvider>(string.Empty, "981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0");
        }

        [Fact]
        public void GOST3411_2012_256_Empty()
        {
            Verify<Gost3411_2012_256CryptoServiceProvider>(string.Empty, "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB");
        }

        [Fact]
        public void GOST3411_2012_512_Empty()
        {
            Verify<Gost3411_2012_512CryptoServiceProvider>(string.Empty, "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A");
        }

        [Fact]
        public void GOST3411()
        {
            Verify<Gost3411CryptoServiceProvider>(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "FA0F6806E76264FEF2735DDA4232C9C54DEE4CEC82278B50FF76560AD2C61A3E");
        }

        [Fact]
        public void GOST3411_2012_256()
        {
            Verify<Gost3411_2012_256CryptoServiceProvider>(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "47440B6CA733F24C7B80DADA8055796A2742CB729F92CB7FEDF5188F5F3F1CFC");
        }

        [Fact]
        public void GOST3411_2012_512()
        {
            Verify<Gost3411_2012_512CryptoServiceProvider>(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "859190F728250159B34A08B1D3262279A19668C571FC7A7E724C0910318FD4A251974E67592DBC96919D282DE2DA875488D59DC37A2876296F633F451A488E24");
        }


        private void Verify<T>(string rawText, string expected) where T:HashAlgorithm, new()
        {
            byte[] inputBytes = ByteUtils.AsciiBytes(rawText);
            byte[] expectedBytes = ByteUtils.HexToByteArray(expected);

            using (HashAlgorithm hash = new T())
            {
                Assert.True(hash.HashSize > 0);
                byte[] actual = hash.ComputeHash(inputBytes, 0, inputBytes.Length);
                byte[] actual_second = hash.ComputeHash(inputBytes);

                Assert.Equal(expectedBytes, actual);
                Assert.Equal(expectedBytes, actual_second);

                actual = hash.Hash;
                Assert.Equal(expectedBytes, actual);
            }
        }
    }
}
