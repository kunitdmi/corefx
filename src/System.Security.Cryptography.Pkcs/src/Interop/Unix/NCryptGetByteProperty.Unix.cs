// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Diagnostics;

using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class NCrypt
    {

        internal static ErrorCode NCryptGetByteProperty(SafeNCryptHandle hObject, string pszProperty, ref byte result, CngPropertyOptions options = CngPropertyOptions.None)
        {
            throw new System.PlatformNotSupportedException("NCryptGetByteProperty not supported on Unix platform");
        }
    }
}
