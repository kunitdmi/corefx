using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

using Internal.Cryptography;
using Internal.Cryptography.Pal.Native;


internal static partial class Interop
{
    public static partial class crypt32
    {
        public static unsafe string CertGetNameString(
            SafeCertContextHandle certContext,
            CertNameType certNameType,
            CertNameFlags certNameFlags,
            CertNameStringType strType)
        {
            int cchCount = CertGetNameString(certContext, certNameType, certNameFlags, strType, null, 0);
            if (cchCount == 0)
            {
                throw Marshal.GetLastWin32Error().ToCryptographicException();
            }

            Span<char> buffer = cchCount <= 256 ? stackalloc char[cchCount] : new char[cchCount];
            fixed (char* ptr = &MemoryMarshal.GetReference(buffer))
            {
                if (CertGetNameString(certContext, certNameType, certNameFlags, strType, ptr, cchCount) == 0)
                {
                    throw Marshal.GetLastWin32Error().ToCryptographicException();
                }

                Debug.Assert(buffer[cchCount - 1] == '\0');
                return new string(buffer.Slice(0, cchCount - 1));
            }
        }

        [DllImport(Libraries.Crypt32, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CertGetNameStringW")]
        private static extern unsafe int CertGetNameString(SafeCertContextHandle pCertContext, CertNameType dwType, CertNameFlags dwFlags, in CertNameStringType pvTypePara, char* pszNameString, int cchNameString);
    }
}