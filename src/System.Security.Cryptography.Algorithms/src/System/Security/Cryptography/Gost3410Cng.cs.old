// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;

using Microsoft.Win32.SafeHandles;


using ErrorCode = Interop.NCrypt.ErrorCode;
using BCRYPT_GOSTKEY_BLOB = Interop.BCrypt.BCRYPT_GOSTKEY_BLOB;

namespace System.Security.Cryptography
{
    public partial class Gost3410 : AsymmetricAlgorithm
    {
        public static new Gost3410 Create()
        {
            return new Gost3410Implementation.Gost3410Cng();
        }
    }

    internal static partial class Gost3410Implementation
    {
        public sealed partial class Gost3410Cng : Gost3410
        {
            private SafeNCryptKeyHandle _keyHandle;
            private int _lastKeySize;

            private SafeNCryptKeyHandle GetDuplicatedKeyHandle()
            {
                int keySize = KeySize;

                if (_lastKeySize != keySize)
                {
                    if (_keyHandle != null)
                    {
                        _keyHandle.Dispose();
                    }

                    const string BCRYPT_GOST_ALGORITHM = "Gost3410"; ///!!!!!!

                    _keyHandle = CngKeyLite.GenerateNewExportableKey(BCRYPT_GOST_ALGORITHM, keySize);
                    _lastKeySize = keySize;
                }

                return new DuplicateSafeNCryptKeyHandle(_keyHandle);
            }

            private byte[] ExportKeyBlob(bool includePrivateParameters)
            {
                string blobType = includePrivateParameters ?
                    Interop.BCrypt.KeyBlobType.BCRYPT_PRIVATE_KEY_BLOB :
                    Interop.BCrypt.KeyBlobType.BCRYPT_PUBLIC_KEY_BLOB;

                using (SafeNCryptKeyHandle keyHandle = GetDuplicatedKeyHandle())
                {
                    return CngKeyLite.ExportKeyBlob(keyHandle, blobType);
                }
            }

            private void ImportKeyBlob(byte[] gostBlob, bool includePrivate)
            {
                string blobType = includePrivate ?
                    Interop.BCrypt.KeyBlobType.BCRYPT_PRIVATE_KEY_BLOB :
                    Interop.BCrypt.KeyBlobType.BCRYPT_PUBLIC_KEY_BLOB;

                SafeNCryptKeyHandle keyHandle = CngKeyLite.ImportKeyBlob(blobType, gostBlob);

                Debug.Assert(!keyHandle.IsInvalid);

                _keyHandle = keyHandle;

                int newKeySize = CngKeyLite.GetKeyLength(keyHandle);

                // Our LegalKeySizes value stores the values that we encoded as being the correct
                // legal key size limitations for this algorithm, as documented on MSDN.
                //
                // But on a new OS version we might not question if our limit is accurate, or MSDN
                // could have been inaccurate to start with.
                //
                // Since the key is already loaded, we know that Windows thought it to be valid;
                // therefore we should set KeySizeValue directly to bypass the LegalKeySizes conformance
                // check.
                //
                // For RSA there are known cases where this change matters. RSACryptoServiceProvider can
                // create a 384-bit RSA key, which we consider too small to be legal. It can also create
                // a 1032-bit RSA key, which we consider illegal because it doesn't match our 64-bit
                // alignment requirement. (In both cases Windows loads it just fine)
                //ForceSetKeySize(newKeySize);
                _lastKeySize = newKeySize;
            }
        }
    }
}
