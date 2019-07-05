// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography.Pal.Native;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using NTSTATUS = Interop.BCrypt.NTSTATUS;
using SafeBCryptKeyHandle = System.Security.Cryptography.SafeBCryptKeyHandle;

using static Interop.Crypt32;

namespace Internal.Cryptography.Pal
{
    /// <summary>
    /// A singleton class that encapsulates the native implementation of various X509 services. (Implementing this as a singleton makes it
    /// easier to split the class into abstract and implementation classes if desired.)
    /// </summary>
    internal sealed partial class X509Pal : IX509Pal
    {
        private static byte[] ExportKeyBlob(SafeBCryptKeyHandle bCryptKeyHandle, CngKeyBlobFormat blobFormat)
        {
            string blobFormatString = blobFormat.Format;

            int numBytesNeeded = 0;
            NTSTATUS ntStatus = Interop.BCrypt.BCryptExportKey(bCryptKeyHandle, IntPtr.Zero, blobFormatString, null, 0, out numBytesNeeded, 0);
            if (ntStatus != NTSTATUS.STATUS_SUCCESS)
                throw new CryptographicException(Interop.Kernel32.GetMessage((int)ntStatus));

            byte[] keyBlob = new byte[numBytesNeeded];
            ntStatus = Interop.BCrypt.BCryptExportKey(bCryptKeyHandle, IntPtr.Zero, blobFormatString, keyBlob, keyBlob.Length, out numBytesNeeded, 0);
            if (ntStatus != NTSTATUS.STATUS_SUCCESS)
                throw new CryptographicException(Interop.Kernel32.GetMessage((int)ntStatus));

            Array.Resize(ref keyBlob, numBytesNeeded);
            return keyBlob;
        }
        
        private static void ExportNamedCurveParameters(ref ECParameters ecParams, byte[] ecBlob, bool includePrivateParameters)
        {
            // We now have a buffer laid out as follows:
            //     BCRYPT_ECCKEY_BLOB   header
            //     byte[cbKey]          Q.X
            //     byte[cbKey]          Q.Y
            //     -- Private only --
            //     byte[cbKey]          D

            unsafe
            {
                Debug.Assert(ecBlob.Length >= sizeof(Interop.BCrypt.BCRYPT_ECCKEY_BLOB));

                fixed (byte* pEcBlob = &ecBlob[0])
                {
                    Interop.BCrypt.BCRYPT_ECCKEY_BLOB* pBcryptBlob = (Interop.BCrypt.BCRYPT_ECCKEY_BLOB*)pEcBlob;

                    int offset = sizeof(Interop.BCrypt.BCRYPT_ECCKEY_BLOB);

                    ecParams.Q = new ECPoint
                    {
                        X = Interop.BCrypt.Consume(ecBlob, ref offset, pBcryptBlob->cbKey),
                        Y = Interop.BCrypt.Consume(ecBlob, ref offset, pBcryptBlob->cbKey)
                    };

                    if (includePrivateParameters)
                    {
                        ecParams.D = Interop.BCrypt.Consume(ecBlob, ref offset, pBcryptBlob->cbKey);
                    }
                }
            }
        }

        private static byte[] GetProperty(SafeBCryptKeyHandle cryptHandle, string propertyName)
        {
            Debug.Assert(!cryptHandle.IsInvalid);
            unsafe
            {
                int numBytesNeeded;
                NTSTATUS errorCode = Interop.BCrypt.BCryptGetProperty(cryptHandle, propertyName, null, 0, out numBytesNeeded, 0);
                if (errorCode != NTSTATUS.STATUS_SUCCESS)
                    return null;

                byte[] propertyValue = new byte[numBytesNeeded];
                fixed (byte* pPropertyValue = propertyValue)
                {
                    errorCode = Interop.BCrypt.BCryptGetProperty(cryptHandle, propertyName, pPropertyValue, propertyValue.Length, out numBytesNeeded, 0);
                }
                if (errorCode != NTSTATUS.STATUS_SUCCESS)
                    return null;

                Array.Resize(ref propertyValue, numBytesNeeded);
                return propertyValue;
            }
        }
    }
}

