// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IO;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class Gost3410Implementation
    {
#endif
    public sealed partial class Gost3410Cng : Gost3410
    {
        /// <summary>
        ///     Create an Gost3410Cng algorithm with a random 512 bit key pair.
        /// </summary>
        public Gost3410Cng()
            : this(512)
        {
        }

        /// <summary>
        ///     Creates a new Gost3410Cng object that will use a randomly generated key of the specified size.
        ///     Valid key size 512 bits.
        /// </summary>
        /// <param name="keySize">Size of the key to generate, in bits.</param>
        /// <exception cref="CryptographicException">if <paramref name="keySize" /> is not valid</exception>
        public Gost3410Cng(int keySize)
        {
            // Set the property directly so that it gets validated against LegalKeySizes.
            KeySize = keySize;
        }

        public override KeySizes[] LegalKeySizes
        {
            get
            {
                // Оставил для реализации других алгоритмов 3410 и 3411
                return new KeySizes[]
                {
                    // All values are in bits.
                    new KeySizes(minSize: 512, maxSize: 512, skipSize: 512),
                };
            }
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
            CngCommon.HashData(data, offset, count, hashAlgorithm);

        protected override bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
            CngCommon.TryHashData(data, destination, hashAlgorithm, out bytesWritten);

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
            CngCommon.HashData(data, hashAlgorithm);

    }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
