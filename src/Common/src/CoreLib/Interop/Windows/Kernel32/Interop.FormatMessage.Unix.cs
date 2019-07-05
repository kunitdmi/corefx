// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;

internal partial class Interop
{
    internal partial class Kernel32
    {
        private const int FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
        private const int FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
        private const int FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
        private const int FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000;
        private const int FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100;
        private const int ERROR_INSUFFICIENT_BUFFER = 0x7A;

        [DllImport(Libraries.Kernel32, CharSet = CharSet.Unicode, EntryPoint = "FormatMessageW", SetLastError = true, BestFitMapping = true)]
        private static extern unsafe int FormatMessage(
            int dwFlags,
            IntPtr lpSource,
            uint dwMessageId,
            int dwLanguageId,
            void* lpBuffer,
            int nSize,
            IntPtr arguments);

        /// <summary>
        ///     Returns a string message for the specified Win32 error code.
        /// </summary>
        internal static string GetMessage(int errorCode) =>
            GetMessage(errorCode, IntPtr.Zero);

        internal static unsafe string GetMessage(int errorCode, IntPtr moduleHandle)
        {
            const int sizeof_wchar_t = 4;
            int flags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY;
            if (moduleHandle != IntPtr.Zero)
            {
                flags |= FORMAT_MESSAGE_FROM_HMODULE;
            }

            // First try to format the message into the stack based buffer.  Most error messages willl fit.
            Span<byte> stackBuffer = stackalloc byte[256]; // arbitrary stack limit
            fixed (byte* bufferPtr = stackBuffer)
            {
                int length = FormatMessage(flags, moduleHandle, unchecked((uint)errorCode), 0, bufferPtr, stackBuffer.Length/sizeof_wchar_t, IntPtr.Zero);
                if (length > 0)
                {
                    return GetString(stackBuffer.Slice(0, length * sizeof_wchar_t));
                }
            }

            // We got back an error.  If the error indicated that there wasn't enough room to store
            // the error message, then call FormatMessage again, but this time rather than passing in
            // a buffer, have the method allocate one, which we then need to free.
            if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER)
            {
                IntPtr nativeMsgPtr = default;
                try
                {
                    int length = FormatMessage(flags | FORMAT_MESSAGE_ALLOCATE_BUFFER, moduleHandle, unchecked((uint)errorCode), 0, &nativeMsgPtr, 0, IntPtr.Zero);
                    if (length > 0)
                    {
                        return GetString(new Span<byte>((byte*)nativeMsgPtr, length * sizeof_wchar_t));
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(nativeMsgPtr);
                }
            }

            // Couldn't get a message, so manufacture one.
            return string.Format("Unknown error (0x{0:x})", errorCode);
        }

        private static string GetString(Span<byte> buffer)
        {
            return System.Text.Encoding.UTF32.GetString(buffer.ToArray());
        }
    }
}
