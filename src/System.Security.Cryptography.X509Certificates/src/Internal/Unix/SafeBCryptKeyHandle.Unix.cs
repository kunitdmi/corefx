// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Microsoft.Win32.SafeHandles
{
    internal sealed class SafeBCryptKeyHandle : SafeHandle, IDisposable
    {
        private SafeBCryptKeyHandle()
            : base(IntPtr.Zero, true)
        {
        }

        protected sealed override bool ReleaseHandle()
        {
            bool successfullyFreed = Interop.Advapi32.CryptDestroyKey(handle);
            Debug.Assert(successfullyFreed);

            return successfullyFreed;
        }

        public sealed override bool IsInvalid
        {
            get
            {
                return handle == IntPtr.Zero;
            }
        }
    }
}
