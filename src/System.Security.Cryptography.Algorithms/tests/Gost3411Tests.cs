// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Security.Cryptography.Hashing.Algorithms.Tests
{
    public class Gost3411Tests : HashAlgorithmTest
    {
        protected override HashAlgorithm Create()
        {
            return Gost3411.Create();
        }

        [Fact]
        public void Gost3411_Empty()
        {
            Verify(Array.Empty<byte>(), "981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0");
        }

        [Fact]
        public void Gost3411_abc()
        {
            Verify("abc", "B285056DBF18D7392D7677369524DD14747459ED8143997E163B2986F92FD42C");
        }

        [Fact]
        public void Gost3411_MultiBlock()
        {
            VerifyMultiBlock("ab", "c", "B285056DBF18D7392D7677369524DD14747459ED8143997E163B2986F92FD42C", "981E5F3CA30C841487830F84FB433E13AC1101569B9C13584AC483234CD656C0");
        }

        [Fact]
        public void Gost3411_String()
        {
            Verify("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "FA0F6806E76264FEF2735DDA4232C9C54DEE4CEC82278B50FF76560AD2C61A3E");
        }

        [Fact]
        public void Gost3411_Repeating()
        {
            VerifyRepeating("a", 1000000, "8693287AA62F9478F7CB312EC0866B6C4E4A0F11160441E8F4FFCD2715DD554F");
        }

        [Fact]
        public void Gost3411_Repeating_1()
        {
            VerifyRepeating("0123456701234567012345670123456701234567012345670123456701234567", 10, "743E4B990E0C85B37919214FADFA74F2A3DC9C02920DEDCE29895339ABAB4DDC");
        }
    }
}
