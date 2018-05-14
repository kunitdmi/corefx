//// Licensed to the .NET Foundation under one or more agreements.
//// The .NET Foundation licenses this file to you under the MIT license.
//// See the LICENSE file in the project root for more information.

using System.Diagnostics;

using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    public sealed partial class Gost3410Cng : Gost3410
    {
        /// <summary>
        ///     Gets the key that will be used by the Gost3410 object for any cryptographic operation that it uses.
        ///     This key object will be disposed if the key is reset, for instance by changing the KeySize
        ///     property, using ImportParamers to create a new key, or by Disposing of the parent Gost3410 object.
        ///     Therefore, you should make sure that the key object is no longer used in these scenarios. This
        ///     object will not be the same object as the CngKey passed to the Gost3410Cng constructor if that
        ///     constructor was used, however it will point at the same CNG key.
        /// </summary>
        public CngKey Key
        {
            get
            {
                CngKey key = _core.GetOrGenerateKey(KeySize, CngAlgorithm.Gost3410);
                return key;
            }

            private set
            {
                CngKey key = value;
                Debug.Assert(key != null, "key != null");
                if (key.AlgorithmGroup != CngAlgorithmGroup.Gost3410)
                    throw new ArgumentException(SR.Cryptography_CngKeyWrongAlgorithm, nameof(value));
                _core.SetKey(key);
                ForceSetKeySize(key.KeySize);
            }
        }

        private SafeNCryptKeyHandle GetDuplicatedKeyHandle()
        {
            return Key.Handle;
        }
    }
}

