// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Алгоритм зашифрования секретного ключа.
    /// </summary>
    public enum GostKeyWrapMethod
    {
        /// <summary>
        /// Простой экспорт ключа по ГОСТ 28147-89.
        /// </summary>
        GostKeyWrap,

        /// <summary>
        /// Защищённый экспорт ключа по алгоритму КриптоПро.
        /// </summary>
        CryptoProKeyWrap,

        /// <summary>
        /// Защищённый экспорт ключа по алгоритму КриптоПро12.
        /// </summary>
        CryptoPro12KeyWrap,
    }
}
