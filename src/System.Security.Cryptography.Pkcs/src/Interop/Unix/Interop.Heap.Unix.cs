// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

internal partial class Interop
{
    internal partial class Kernel32
    {
        internal static IntPtr GetProcessHeap()
        {
            return IntPtr.Zero;
        }

        [Flags]
        internal enum HeapAllocFlags : int
        {
            None = 0x00000000,
            HEAP_NO_SERIALIZE = 0x00000001,
            HEAP_ZERO_MEMORY = 0x00000008,
            HEAP_GENERATE_EXCEPTIONS = 0x00000004,
        }

        internal static SafeHeapAllocHandle HeapAlloc(IntPtr hHeap, HeapAllocFlags dwFlags, int dwBytes)
        {
            return CP_malloc(dwBytes);
        }

        internal static bool HeapFree(IntPtr hHeap, HeapAllocFlags dwFlags, IntPtr lpMem)
        {
            CP_free(lpMem);
            return true;
        }

        [DllImport(Libraries.CPalloc, CharSet = CharSet.Unicode)]
        private static extern SafeHeapAllocHandle CP_malloc(int dwBytes);

        [DllImport(Libraries.CPalloc, CharSet = CharSet.Unicode)]
        internal static extern bool CP_free(IntPtr lpMem);
    }
}
