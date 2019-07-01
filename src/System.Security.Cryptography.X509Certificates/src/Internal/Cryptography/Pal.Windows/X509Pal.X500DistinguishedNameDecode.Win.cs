// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Text;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;

using Internal.Cryptography;
using Internal.Cryptography.Pal.Native;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
    /// <summary>
    /// A singleton class that encapsulates the native implementation of various X509 services. (Implementing this as a singleton makes it
    /// easier to split the class into abstract and implementation classes if desired.)
    /// </summary>
    internal sealed partial class X509Pal : IX509Pal
    {
        public string X500DistinguishedNameDecode(byte[] encodedDistinguishedName, X500DistinguishedNameFlags flag)
        {
            int dwStrType = (int)(CertNameStrTypeAndFlags.CERT_X500_NAME_STR | MapNameToStrFlag(flag));
            unsafe
            {
                fixed (byte* pbEncoded = encodedDistinguishedName)
                {
                    CRYPTOAPI_BLOB nameBlob;
                    nameBlob.cbData = encodedDistinguishedName.Length;
                    nameBlob.pbData = pbEncoded;

                    int cchDecoded = Interop.Crypt32.CertNameToStr((int)CertEncodingType.All, &nameBlob, dwStrType, null, 0);
                    if (cchDecoded == 0)
                        throw ErrorCode.CERT_E_INVALID_NAME.ToCryptographicException();

                    Span<char> buffer = cchDecoded <= 256 ? stackalloc char[cchDecoded] : new char[cchDecoded];
                    fixed (char* ptr = buffer)
                    {
                        if (Interop.Crypt32.CertNameToStr((int)CertEncodingType.All, &nameBlob, dwStrType, ptr, cchDecoded) == 0)
                            throw ErrorCode.CERT_E_INVALID_NAME.ToCryptographicException();
                    }

                    return new string(buffer.Slice(0, cchDecoded - 1));
                }
            }
        }
    }
}