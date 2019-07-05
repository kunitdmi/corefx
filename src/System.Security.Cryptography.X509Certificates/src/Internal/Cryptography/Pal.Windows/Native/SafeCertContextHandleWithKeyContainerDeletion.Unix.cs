// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Win32.SafeHandles;
using System;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Internal.Cryptography.Pal.Native
{
    /// <summary>
    /// SafeHandle for the CERT_CONTEXT structure defined by crypt32. Unlike SafeCertContextHandle, disposition already deletes any associated key containers.
    /// </summary>
    internal sealed class SafeCertContextHandleWithKeyContainerDeletion : SafeCertContextHandle
    {
        protected sealed override bool ReleaseHandle()
        {
            using (SafeCertContextHandle certContext = Interop.crypt32.CertDuplicateCertificateContext(handle))
            {
                DeleteKeyContainer(certContext);
            }
            base.ReleaseHandle();
            return true;
        }

        public static void DeleteKeyContainer(SafeCertContextHandle pCertContext)
        {
            if (pCertContext.IsInvalid)
                return;

            int cb = 0;
            bool containsPrivateKey = Interop.crypt32.CertGetCertificateContextProperty(pCertContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, null, ref cb);
            if (!containsPrivateKey)
                return;

            byte[] provInfoAsBytes = new byte[cb];
            if (!Interop.crypt32.CertGetCertificateContextProperty(pCertContext, CertContextPropId.CERT_KEY_PROV_INFO_PROP_ID, provInfoAsBytes, ref cb))
                return;

            unsafe
            {
                fixed (byte* pProvInfoAsBytes = provInfoAsBytes)
                {
                    CRYPT_KEY_PROV_INFO* pProvInfo = (CRYPT_KEY_PROV_INFO*)pProvInfoAsBytes;

                    string providerName = pwszToString((IntPtr)(pProvInfo->pwszProvName));
                    string keyContainerName = pwszToString((IntPtr)(pProvInfo->pwszContainerName));
                    if (pProvInfo->dwProvType == 0)
                    {
                        // dwProvType being 0 indicates that the key is stored in CNG.
                        // dwProvType being non-zero indicates that the key is stored in CAPI.
                        try
                        {
                            using (CngKey cngKey = CngKey.Open(keyContainerName, new CngProvider(providerName)))
                            {
                                cngKey.Delete();
                            }
                        }
                        catch (CryptographicException)
                        {
                            // While leaving the file on disk is undesirable, an inability to perform this cleanup
                            // should not manifest itself to a user.
                        }
                    }
                    else
                    {
                        CryptAcquireContextFlags flags = (pProvInfo->dwFlags & CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET) | CryptAcquireContextFlags.CRYPT_DELETEKEYSET;
                        IntPtr hProv;
                        bool success = Interop.cryptoapi.CryptAcquireContext(out hProv, keyContainerName, providerName, pProvInfo->dwProvType, flags);

                        // Called CryptAcquireContext solely for the side effect of deleting the key containers. When called with these flags, no actual
                        // hProv is returned (so there's nothing to clean up.)
                        Debug.Assert(hProv == IntPtr.Zero);
                    }
                }
            }
        }
        private static unsafe string pwszToString(IntPtr pwszName) {
            const int sizeof_wchar_t = 4;
            int len = 0;
            var curr = (byte*)pwszName;
            while(*curr != 0 || *(curr + 1) != 0 || *(curr + 2) != 0 || *(curr + 3) != 0) {
                len++;
                curr+=sizeof_wchar_t;
            }
            var buf = new byte[len*sizeof_wchar_t];
            Marshal.Copy(pwszName, buf, 0, len*sizeof_wchar_t);
            return Encoding.UTF32.GetString(buf);
        }
    }
}