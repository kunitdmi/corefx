// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Internal.Cryptography
{
    internal static partial class HashProviderDispenser
    {
        private sealed class CryptoApiHmacProvider : HashProvider
        {
            // private readonly byte[] _key;
            // private readonly SafeCAPIHashHandle _ctx(1);

            // private bool _running;

            public override int HashSizeInBytes { get; }

            internal CryptoApiHmacProvider(int providerType, int calgHash, byte[] key)
            {
                // _key = key.CloneByteArray();
                // int hashSizeInBytes = 0;
                // _ctx = Interop.AppleCrypto.HmacCreate(algorithm, ref hashSizeInBytes);

                // if (hashSizeInBytes < 0)
                // {
                //     _ctx.Dispose();
                //     throw new PlatformNotSupportedException(
                //         SR.Format(
                //             SR.Cryptography_UnknownHashAlgorithm,
                //             Enum.GetName(typeof(Interop.AppleCrypto.PAL_HashAlgorithm), algorithm)));
                // }

                // if (_ctx.IsInvalid)
                // {
                //     _ctx.Dispose();
                //     throw new CryptographicException();
                // }

                // HashSizeInBytes = hashSizeInBytes;
                throw new PlatformNotSupportedException();
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                // if (!_running)
                // {
                //     SetKey();
                // }

                // if (Interop.AppleCrypto.HmacUpdate(_ctx, data, data.Length) != 1)
                // {
                //     throw new CryptographicException();
                // }
            }

            private void SetKey()
            {
                // if (Interop.AppleCrypto.HmacInit(_ctx, _key, _key.Length) != 1)
                // {
                //     throw new CryptographicException();
                // }

                // _running = true;
            }

            public override unsafe byte[] FinalizeHashAndReset()
            {
                var output = new byte[HashSizeInBytes];
                // bool success = TryFinalizeHashAndReset(output, out int bytesWritten);
                // Debug.Assert(success);
                // Debug.Assert(bytesWritten == output.Length);
                return output;
            }

            public override bool TryFinalizeHashAndReset(Span<byte> destination, out int bytesWritten)
            {
                // if (destination.Length < HashSizeInBytes)
                // {
                //     bytesWritten = 0;
                //     return false;
                // }

                // if (!_running)
                // {
                //     SetKey();
                // }

                // if (Interop.AppleCrypto.HmacFinal(_ctx, destination, destination.Length) != 1)
                // {
                //     throw new CryptographicException();
                // }

                // bytesWritten = HashSizeInBytes;
                // _running = false;
                bytesWritten = 0;
                return true;
            }

            public override void Dispose(bool disposing)
            {
                // if (disposing)
                // {
                //     _ctx?.Dispose();
                //     Array.Clear(_key, 0, _key.Length);
                // }
            }
        }

        private sealed class CryptoApiHashProvider : HashProvider
        {
            private SafeHashHandle _hHash;
            private readonly SafeProvHandle _hProv;
            private readonly int _calgHash;

            public override int HashSizeInBytes { get; }

            internal CryptoApiHashProvider(int providerType, int calgHash)
            {
                SafeProvHandle hProv;
                if (!Interop.Advapi32.CryptAcquireContext(out hProv, null, null, providerType, (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                SafeHashHandle hHash;
                if (!Interop.Advapi32.CryptCreateHash(hProv, calgHash, SafeKeyHandle.InvalidHandle, (int)Interop.Advapi32.CryptCreateHashFlags.None, out hHash))
                {
                    hProv.Dispose();
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                hHash.SetParent(hProv);

                int dwHashSize = 0;
                int cbHashSize = sizeof(int);
                if (!Interop.Advapi32.CryptGetHashParam(hHash, Interop.Advapi32.CryptHashProperty.HP_HASHSIZE, out dwHashSize, ref cbHashSize, 0))
                {
                    hHash.Dispose();
                    hProv.Dispose();
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (dwHashSize < 0)
                {
                    hHash.Dispose();
                    hProv.Dispose();
                    throw new PlatformNotSupportedException(
                        SR.Format(
                            SR.Cryptography_UnknownHashAlgorithm, providerType, calgHash));
                }
                HashSizeInBytes = dwHashSize;
                _calgHash = calgHash;
                _hHash = hHash;
                _hProv = hProv;
            }

            public override void AppendHashData(ReadOnlySpan<byte> data)
            {
                bool ret = Interop.Advapi32.CryptHashData(_hHash, data.ToArray(), data.Length, 0);
                if (!ret)
                    throw new CryptographicException(Marshal.GetLastWin32Error());
            }

            public override byte[] FinalizeHashAndReset()
            {
                var hash = new byte[HashSizeInBytes];
                bool success = TryFinalizeHashAndReset(hash, out int bytesWritten);
                Debug.Assert(success);
                Debug.Assert(bytesWritten == hash.Length);
                return hash;
            }

            public override bool TryFinalizeHashAndReset(Span<byte> destination, out int bytesWritten)
            {
                int hashSize = HashSizeInBytes;
                if (!Interop.Advapi32.CryptGetHashParam(_hHash, Interop.Advapi32.CryptHashProperty.HP_HASHVAL, destination, ref hashSize, 0))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                //reinitialize
                _hHash.Dispose();
                if (!Interop.Advapi32.CryptCreateHash(_hProv, _calgHash, SafeKeyHandle.InvalidHandle, (int)Interop.Advapi32.CryptCreateHashFlags.None, out _hHash))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                bytesWritten = hashSize;
                return true;
            }

            public override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _hHash?.Dispose();
                    _hProv?.Dispose();
                }
            }
        }
    }
}
