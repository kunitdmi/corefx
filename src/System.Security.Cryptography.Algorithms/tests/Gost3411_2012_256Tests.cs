// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Security.Cryptography.Hashing.Algorithms.Tests
{
    public class Gost3411_2012_256Tests : HashAlgorithmTest
    {
        protected override HashAlgorithm Create()
        {
            return Gost3411_2012_256.Create();
        }

        [Fact]
        public void Gost3411_2012_256_Empty()
        {
            Verify(Array.Empty<byte>(), "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB");
        }

        [Fact]
        public void Gost3411_2012_256_abc()
        {
            Verify("abc", "4E2919CF137ED41EC4FB6270C61826CC4FFFB660341E0AF3688CD0626D23B481");
        }

        [Fact]
        public void Gost3411_2012_256_MultiBlock()
        {
            VerifyMultiBlock("ab", "c",
                             "4E2919CF137ED41EC4FB6270C61826CC4FFFB660341E0AF3688CD0626D23B481",
                             "3F539A213E97C802CC229D474C6AA32A825A360B2A933A949FD925208D9CE1BB");
        }

        [Fact]
        public void Gost3411_2012_256_String()
        {
            Verify("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "47440B6CA733F24C7B80DADA8055796A2742CB729F92CB7FEDF5188F5F3F1CFC");
        }

        [Fact]
        public void Gost3411_2012_256_Repeating()
        {
            VerifyRepeating("a", 1000000, "841AF1A0B2F92A800FB1B7E4AABC8E48763153C448A0FC57C90BA830E130F152");
        }

        [Fact]
        public void Gost3411_2012_256_Repeating_1()
        {
            VerifyRepeating("0123456701234567012345670123456701234567012345670123456701234567", 10,
                            "9329C87431C0D732A8950CB60BC7C85FE423E6F61E87FDA9EFFAAC921CA7EA2D");
        }
    }
}
