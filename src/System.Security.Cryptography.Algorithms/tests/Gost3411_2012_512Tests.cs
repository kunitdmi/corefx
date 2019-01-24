// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Security.Cryptography.Hashing.Algorithms.Tests
{
    public class Gost3411_2012_512Tests : HashAlgorithmTest
    {
        protected override HashAlgorithm Create()
        {
            return Gost3411_2012_512.Create();
        }

        [Fact]
        public void Gost3411_2012_512_Empty()
        {
            Verify(Array.Empty<byte>(),
                   "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A");
        }

        [Fact]
        public void Gost3411_2012_512_abc()
        {
            Verify("abc",
                   "28156E28317DA7C98F4FE2BED6B542D0DAB85BB224445FCEDAF75D46E26D7EB8D5997F3E0915DD6B7F0AAB08D9C8BEB0D8C64BAE2AB8B3C8C6BC53B3BF0DB728");
        }

        [Fact]
        public void Gost3411_2012_512_MultiBlock()
        {
            VerifyMultiBlock("ab", "c",
                             "28156E28317DA7C98F4FE2BED6B542D0DAB85BB224445FCEDAF75D46E26D7EB8D5997F3E0915DD6B7F0AAB08D9C8BEB0D8C64BAE2AB8B3C8C6BC53B3BF0DB728",
                             "8E945DA209AA869F0455928529BCAE4679E9873AB707B55315F56CEB98BEF0A7362F715528356EE83CDA5F2AAC4C6AD2BA3A715C1BCD81CB8E9F90BF4C1C1A8A");
        }

        [Fact]
        public void Gost3411_2012_512_String()
        {
            Verify("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                   "859190F728250159B34A08B1D3262279A19668C571FC7A7E724C0910318FD4A251974E67592DBC96919D282DE2DA875488D59DC37A2876296F633F451A488E24");
        }

        [Fact]
        public void Gost3411_2012_512_Repeating()
        {
            VerifyRepeating("a", 1000000,
                            "D396A40B126B1F324465BFA7AA159859AB33FAC02DCDD4515AD231206396A266D0102367E4C544EF47D2294064E1A25342D0CD25AE3D904B45ABB1425AE41095");
        }

        [Fact]
        public void Gost3411_2012_512_Repeating_1()
        {
            VerifyRepeating("0123456701234567012345670123456701234567012345670123456701234567", 10,
                            "8D93346839BF36AA32ED537E554D369F2CAF0528AFAF2378D17CF61C30CC7CD0485A6294B5D2F9BC3911CEFFFF179C8C6CAFFB2C27D1E98DACD6B5E4F881AD59");
        }
    }
}
