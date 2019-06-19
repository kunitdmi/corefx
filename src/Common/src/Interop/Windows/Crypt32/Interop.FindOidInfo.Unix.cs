// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal static partial class Interop
{
    internal static partial class Crypt32
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_OID_INFO
        {
            public int cbSize;
            public IntPtr pszOID;
            public IntPtr pwszName;
            public OidGroup dwGroupId;
            public int AlgId;
            public int cbData;
            public IntPtr pbData;

            public string OID
            {
                get
                {
                    return Marshal.PtrToStringAnsi(pszOID);
                }
            }

            public unsafe string Name
            {
                get
                {
                    int len = 0;
                    var curr = (byte*)pwszName;
                    while(*curr != 0 || *(curr++) != 0 || *(curr++) != 0 || *(curr++) != 0) {
                        len++;
                        curr++;
                    }
                    var buf = new byte[len*4];
                    Marshal.Copy(pwszName, buf, 0, len*4);
                    return System.Text.Encoding.Unicode.GetString(buf);
                }
            }
        }
    }
}