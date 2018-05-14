// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;

using Internal.Cryptography;

using ErrorCode = Interop.NCrypt.ErrorCode;
using BCRYPT_GOSTKEY_BLOB = Interop.BCrypt.BCRYPT_GOSTKEY_BLOB;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class RSAImplementation
    {
#endif
    public sealed partial class Gost3410Cng : Gost3410
    {
        /// <summary>
        ///     <para>
        ///         ImportParameters will replace the existing key that Gost3410Cng is working with by creating a
        ///         new CngKey for the parameters structure.
        ///     </para>
        /// </summary>
        /// <exception cref="ArgumentException">
        ///     if <paramref name="parameters" /> contains neither an exponent nor a modulus.
        /// </exception>
        /// <exception cref="CryptographicException">
        ///     if <paramref name="parameters" /> is not a valid RSA key or if <paramref name="parameters"
        ///     /> is a full key pair and the default KSP is used.
        /// </exception>
        public override void ImportParameters(Gost3410Parameters parameters) ///!!!!!!
        {
            unsafe
            {
                bool includePrivate = true;
                int blobSize = sizeof(BCRYPT_GOSTKEY_BLOB);
                
                byte[] gostBlob = new byte[blobSize];
                fixed (byte* pgostBlob = &gostBlob[0])
                {
                    // Build the header
                    BCRYPT_GOSTKEY_BLOB* pBcryptBlob = (BCRYPT_GOSTKEY_BLOB*)pgostBlob;
                    pBcryptBlob->PublicKeyParamSet = parameters.PublicKeyParamSet.Length;
                    pBcryptBlob->DigestParamSet = parameters.DigestParamSet.Length;
                    pBcryptBlob->EncryptionParamSet = parameters.EncryptionParamSet.Length;
                    pBcryptBlob->PublicKey = parameters.PublicKey.Length * 8;
                    pBcryptBlob->PrivateKey = parameters.PrivateKey.Length * 8;

                    int offset = sizeof(BCRYPT_GOSTKEY_BLOB);

                    Interop.BCrypt.Emit(gostBlob, ref offset, parameters.PublicKeyParamSet);
                    Interop.BCrypt.Emit(gostBlob, ref offset, parameters.DigestParamSet);
                    Interop.BCrypt.Emit(gostBlob, ref offset, parameters.EncryptionParamSet);
                    Interop.BCrypt.Emit(gostBlob, ref offset, parameters.PublicKey);
                    Interop.BCrypt.Emit(gostBlob, ref offset, parameters.PrivateKey);

                    // We better have computed the right allocation size above!
                    Debug.Assert(offset == blobSize, "offset == blobSize");
                }

                ImportKeyBlob(gostBlob, includePrivate);
            }


        }

        public override Gost3410Parameters ExportParameters(bool includePrivateParameters) ///!!!!!!
        {
            byte[] gostBlob = ExportKeyBlob(includePrivateParameters);
            Gost3410Parameters gostParams = new Gost3410Parameters();
            ExportParameters(ref gostParams, gostBlob, includePrivateParameters);
            return gostParams;
        }

        private static void ExportParameters(ref Gost3410Parameters gostParams, byte[] gostBlob, bool includePrivateParameters)
        {
            unsafe
            {
                // Fail-fast if a rogue provider gave us a blob that isn't even the size of the blob header.
                if (gostBlob.Length < sizeof(BCRYPT_GOSTKEY_BLOB))
                    throw new CryptographicException(ErrorCode.E_FAIL.ToString());

                fixed (byte* pGostBlob = &gostBlob[0])
                {
                    BCRYPT_GOSTKEY_BLOB* pBcryptBlob = (BCRYPT_GOSTKEY_BLOB*)pGostBlob;

                    int offset = sizeof(BCRYPT_GOSTKEY_BLOB);

                    gostParams.PublicKeyParamSet = Interop.BCrypt.Consume(gostBlob, ref offset, pBcryptBlob->PublicKeyParamSet);
                    gostParams.DigestParamSet = Interop.BCrypt.Consume(gostBlob, ref offset, pBcryptBlob->DigestParamSet);
                    gostParams.EncryptionParamSet = Interop.BCrypt.Consume(gostBlob, ref offset, pBcryptBlob->EncryptionParamSet);
                    gostParams.PublicKey = Interop.BCrypt.Consume(gostBlob, ref offset, pBcryptBlob->PublicKey);
                    gostParams.PrivateKey = Interop.BCrypt.Consume(gostBlob, ref offset, pBcryptBlob->PrivateKey);

                }
            }
        }
    }

#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
