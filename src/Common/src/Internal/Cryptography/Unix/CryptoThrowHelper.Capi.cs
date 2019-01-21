// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static class CryptoThrowHelper
    {
        public static CryptographicException ToCryptographicException(this int hr)
        {
            //TODO: may be use GetErrorMessage?
            // string message = Interop.CPCSP.GetErrorMessage(hr);
            return new WindowsCryptographicException(hr, "Cryptography error");
        }

        private sealed class WindowsCryptographicException : CryptographicException
        {
            public WindowsCryptographicException(int hr, string message)
                : base(message)
            {
                HResult = hr;
            }
        }        
    }
}
