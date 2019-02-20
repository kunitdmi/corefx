// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using Internal.Cryptography;
using Libraries = Interop.Libraries;
using CryptProvParam = global::Interop.CapiLite.CryptProvParam;


namespace Internal.NativeCrypto
{
    internal static partial class CapiHelper
    {
        internal enum CspAlgorithmType
        {
            PROV_GOST_2001_DH = 75,
            PROV_GOST_2012_256 = 80,
            PROV_GOST_2012_512 = 81
        }

        internal enum GetDefaultProviderFlags : int
        {
            CRYPT_MACHINE_DEFAULT = 0x00000001,
            CRYPT_USER_DEFAULT = 0x00000002
        }

        internal enum CryptGetKeyParamFlags : int
        {
            CRYPT_EXPORT = 0x0004,
            KP_IV = 1,
            KP_PERMISSIONS = 6,
        }

        [Flags]
        internal enum CryptGetProvParamPPImpTypeFlags : int
        {
            CRYPT_IMPL_HARDWARE = 0x1,
            CRYPT_IMPL_SOFTWARE = 0x2,
            CRYPT_IMPL_MIXED = 0x3,
            CRYPT_IMPL_UNKNOWN = 0x4,
            CRYPT_IMPL_REMOVABLE = 0x8
        }
        //All the flags are capture here
        [Flags]
        internal enum CryptAcquireContextFlags : uint
        {
            None = 0x00000000,
            CRYPT_NEWKEYSET = 0x00000008,                         // CRYPT_NEWKEYSET
            CRYPT_DELETEKEYSET = 0x00000010,                      // CRYPT_DELETEKEYSET
            CRYPT_MACHINE_KEYSET = 0x00000020,                     // CRYPT_MACHINE_KEYSET
            CRYPT_SILENT = 0x00000040,                            // CRYPT_SILENT
            CRYPT_VERIFYCONTEXT = 0xF0000000      // CRYPT_VERIFYCONTEXT
        }

        internal enum CryptGetKeyParamQueryType : int
        {
            KP_IV = 1,
            KP_MODE = 4,
            KP_MODE_BITS = 5,
            KP_EFFECTIVE_KEYLEN = 19,
            KP_KEYLEN = 9,  // Length of key in bits
            KP_ALGID = 7 // Key algorithm
        }
        internal enum CryptGenKeyFlags : int
        {
            // dwFlag definitions for CryptGenKey
            CRYPT_EXPORTABLE = 0x00000001,
            CRYPT_USER_PROTECTED = 0x00000002,
            CRYPT_CREATE_SALT = 0x00000004,
            CRYPT_UPDATE_KEY = 0x00000008,
            CRYPT_NO_SALT = 0x00000010,
            CRYPT_PREGEN = 0x00000040,
            CRYPT_RECIPIENT = 0x00000010,
            CRYPT_INITIATOR = 0x00000040,
            CRYPT_ONLINE = 0x00000080,
            CRYPT_SF = 0x00000100,
            CRYPT_CREATE_IV = 0x00000200,
            CRYPT_KEK = 0x00000400,
            CRYPT_DATA_KEY = 0x00000800,
            CRYPT_VOLATILE = 0x00001000,
            CRYPT_SGCKEY = 0x00002000,
            CRYPT_ARCHIVABLE = 0x00004000
        }

        [Flags]
        internal enum CryptCreateHashFlags : int
        {
            None = 0,
        }

        internal enum CryptHashProperty : int
        {
            HP_ALGID = 0x0001,  // Hash algorithm
            HP_HASHVAL = 0x0002,  // Hash value
            HP_HASHSIZE = 0x0004,  // Hash value size
            HP_HMAC_INFO = 0x0005,  // information for creating an HMAC
            HP_TLS1PRF_LABEL = 0x0006,  // label for TLS1 PRF
            HP_TLS1PRF_SEED = 0x0007,  // seed for TLS1 PRF
        }

        internal enum KeySpec : int
        {
            AT_KEYEXCHANGE = 1,
            AT_SIGNATURE = 2,
        }

        [Flags]
        internal enum CryptSignAndVerifyHashFlags : int
        {
            None = 0x00000000,
            CRYPT_NOHASHOID = 0x00000001,
            CRYPT_TYPE2_FORMAT = 0x00000002,  // Not supported
            CRYPT_X931_FORMAT = 0x00000004,  // Not supported
        }

    }

    /// <summary>
    /// Following part of CAPIHelper keeps the wrappers for all the PInvoke calls
    /// </summary>
    internal static partial class CapiHelper
    {
        /// <summary>
        /// Helper for Gost3410CryptoServiceProvider.SignData/SignHash apis.
        /// </summary>
        public static byte[] SignValue(SafeProvHandle hProv, SafeKeyHandle hKey, int keyNumber, int calgKey, int calgHash, byte[] hash)
        {
            using (SafeHashHandle hHash = hProv.CreateHashHandle(hash, calgHash))
            {
                int cbSignature = 0;
                if (!Interop.CryptSignHash(hHash, (KeySpec)keyNumber, null, CryptSignAndVerifyHashFlags.None, null, ref cbSignature))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }

                byte[] signature = new byte[cbSignature];
                if (!Interop.CryptSignHash(hHash, (KeySpec)keyNumber, null, CryptSignAndVerifyHashFlags.None, signature, ref cbSignature))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }

                switch (calgKey)
                {
                    case CALG_RSA_SIGN:
                        Array.Reverse(signature);
                        break;

                    default:
                        throw new InvalidOperationException();
                }
                return signature;
            }
        }
        /// <summary>
        /// Find the default provider name to be used in the case that we
        /// were not actually passed in a provider name. The main purpose
        /// of this code is really to deal with the enhanced/default provider
        /// problems given to us by CAPILite.
        /// </summary>
        /// <param name="dwType">Type of the provider</param>
        /// <returns>Name of the provider to be used</returns>
        internal static string GetDefaultProvider(int dwType)
        {
            int sizeofProviderName = 0;
            //Get the size of the provider name
            if (!Interop.CryptGetDefaultProvider(dwType, IntPtr.Zero,
                                                (int)GetDefaultProviderFlags.CRYPT_MACHINE_DEFAULT,
                                                null, ref sizeofProviderName))
            {
                throw new CryptographicException(GetErrorCode());

            }
            //allocate memory for the provider name
            StringBuilder providerName = new StringBuilder((int)sizeofProviderName);

            //Now call the function CryptGetDefaultProvider again to get the name of the provider             
            if (!Interop.CryptGetDefaultProvider(dwType, IntPtr.Zero,
                                                (int)GetDefaultProviderFlags.CRYPT_MACHINE_DEFAULT,
                                                providerName, ref sizeofProviderName))
            {
                throw new CryptographicException(GetErrorCode());
            }
            // check to see if there are upgrades available for the requested CSP
            string wszUpgrade = null;
            //if (dwType == (int)ProviderType.PROV_RSA_FULL)
            //{
            //    wszUpgrade = UpgradeRSA(dwType, providerName.ToString());
            //}
            //else if (dwType == (int)ProviderType.PROV_DSS_DH)
            //{
            //    wszUpgrade = UpgradeDSS(dwType, providerName.ToString());
            //}
            if (null != wszUpgrade)
            {
                //Overwrite the provider name with the upgraded provider name
                providerName = new StringBuilder(wszUpgrade);
            }
            return providerName.ToString();
        }

        /// <summary>
        /// Creates a new key container
        /// </summary>
        private static void CreateCSP(CspParameters parameters, bool randomKeyContainer, out SafeProvHandle safeProvHandle)
        {
            uint dwFlags = (uint)CryptAcquireContextFlags.CRYPT_NEWKEYSET;
            switch (parameters.ProviderType)
            {
                case (int)CspAlgorithmType.PROV_GOST_2001_DH:
                case (int)CspAlgorithmType.PROV_GOST_2012_256:
                case (int)CspAlgorithmType.PROV_GOST_2012_512:
                {
                    // Gost does not support creating and using new keys in CRYPT_VERIFYCONTEXT
                    break;
                }
                default:
                {
                    if (randomKeyContainer)
                    {
                        dwFlags |= (uint)CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT;
                    }
                    break;
                }
            }

            SafeProvHandle hProv;
            int ret = OpenCSP(parameters, dwFlags, out hProv);
            if (S_OK != ret)
            {
                hProv.Dispose();
                throw new CryptographicException(ret);
            }
            safeProvHandle = hProv;
        }

        /// <summary>
        /// Acquire a handle to a crypto service provider and optionally a key container
        /// This function implements the WszCryptAcquireContext_SO_TOLERANT
        /// </summary>
        private static int AcquireCryptContext(out SafeProvHandle safeProvHandle, string keyContainer,
                                                string providerName, int providerType, uint flags)
        {
            const uint VerifyContextFlag = (uint)CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT;
            const uint MachineContextFlag = (uint)CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET;

            int ret = S_OK;
            // Specifying both verify context (for an ephemeral key) and machine keyset (for a persisted machine key)
            // does not make sense.  Additionally, Windows is beginning to lock down against uses of MACHINE_KEYSET
            // (for instance in the app container), even if verify context is present.   Therefore, if we're using
            // an ephemeral key, strip out MACHINE_KEYSET from the flags.
            if (((flags & VerifyContextFlag) == VerifyContextFlag) &&
                ((flags & MachineContextFlag) == MachineContextFlag))
            {
                flags &= ~MachineContextFlag;
            }
            //Do not throw in this function. Just return the error code
            if (!Interop.CryptAcquireContext(out safeProvHandle, keyContainer, providerName, providerType, flags))
            {
                ret = GetErrorCode();
            }

            return ret;
        }

        /// <summary>
        /// Acquire a handle to a crypto service provider and optionally a key container
        /// </summary>
        public static bool CryptAcquireContext(out SafeProvHandle psafeProvHandle, string pszContainer, string pszProvider, int dwProvType, uint dwFlags)
        {
            return Interop.CryptAcquireContext(out psafeProvHandle, pszContainer, pszProvider, dwProvType, dwFlags);
        }

        /// <summary>
        /// This method opens the CSP using CRYPT_VERIFYCONTEXT
        /// KeyContainer must be null for the flag CRYPT_VERIFYCONTEXT
        /// This method asserts if keyContainer is not null
        /// </summary>
        /// <param name="cspParameters">CSPParameter to use</param>
        /// <param name="safeProvHandle">Safe provider handle</param>
        internal static void AcquireCsp(CspParameters cspParameters, out SafeProvHandle safeProvHandle)
        {
            SafeProvHandle hProv;

            // We want to just open this CSP.  Passing in verify context will
            // open it and, if a container is given, map to open the container.
            //
            int ret = OpenCSP(cspParameters, (uint)CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT, out hProv);
            if (S_OK != ret)
            {
                hProv.Dispose();
                throw new CryptographicException(ret);
            }

            safeProvHandle = hProv;
        }

        /// <summary>
        /// OpenCSP performs the core work of opening and creating CSPs and containers in CSPs
        /// </summary>
        public static int OpenCSP(CspParameters cspParameters, uint flags, out SafeProvHandle safeProvHandle)
        {
            string providerName = null;
            string containerName = null;
            if (null == cspParameters)
            {
                throw new ArgumentException(SR.Format(SR.CspParameter_invalid, nameof(cspParameters)));
            }

            //look for provider type in the cspParameters
            int providerType = cspParameters.ProviderType;

            //look for provider name in the cspParamters 
            //if CSP provider is not null then use the provider name from cspParameters
            if (null != cspParameters.ProviderName)
            {
                providerName = cspParameters.ProviderName;
            }
            else //Get the default provider name
            {
                providerName = GetDefaultProvider(providerType);
                cspParameters.ProviderName = providerName;
            }
            // look to see if the user specified that we should pass
            // CRYPT_MACHINE_KEYSET to CAPI to use machine key storage instead
            // of user key storage
            int cspProviderFlags = (int)cspParameters.Flags;

            // If the user specified CSP_PROVIDER_FLAGS_USE_DEFAULT_KEY_CONTAINER,
            // then ignore the key container name and hand back the default container
            if (!IsFlagBitSet((uint)cspProviderFlags, (uint)CspProviderFlags.UseDefaultKeyContainer))
            {
                //look for key container name in the cspParameters 
                if (null != cspParameters.KeyContainerName)
                {
                    containerName = cspParameters.KeyContainerName;
                }
            }

            SafeProvHandle hProv;

            // Go ahead and try to open the CSP.  If we fail, make sure the CSP
            // returned is 0 as that is going to be the error check in the caller.
            flags |= MapCspProviderFlags((int)cspParameters.Flags);
            int hr = AcquireCryptContext(out hProv, containerName, providerName, providerType, flags);
            if (hr != S_OK)
            {
                hProv.Dispose();
                safeProvHandle = SafeProvHandle.InvalidHandle;
                return hr;
            }

            hProv.ContainerName = containerName;
            hProv.ProviderName = providerName;
            hProv.Types = providerType;
            hProv.Flags = flags;

            // We never want to delete a key container if it's already there.
            if (IsFlagBitSet(flags, (uint)CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
            {
                hProv.PersistKeyInCsp = false;
            }

            safeProvHandle = hProv;
            return S_OK;
        }

        /// <summary>
        /// This method acquires CSP and returns the handle of CSP 
        /// </summary>
        /// <param name="parameters">Accepts the CSP Parameters</param>
        /// <param name="randomKeyContainer">Bool to indicate if key needs to be persisted</param>
        /// <returns>Returns the safehandle of CSP </returns>
        internal static SafeProvHandle CreateProvHandle(CspParameters parameters, bool randomKeyContainer)
        {
            SafeProvHandle safeProvHandle;
            uint flag = 0;
            uint hr = unchecked((uint)OpenCSP(parameters, flag, out safeProvHandle));
            //Open container failed 
            if (hr != S_OK)
            {
                safeProvHandle.Dispose();
                // If UseExistingKey flag is used and the key container does not exist
                // throw an exception without attempting to create the container.
                if (IsFlagBitSet((uint)parameters.Flags, (uint)CspProviderFlags.UseExistingKey) ||
                                                        ((hr != (uint)CryptKeyError.NTE_KEYSET_NOT_DEF && hr !=
                                                        (uint)CryptKeyError.NTE_BAD_KEYSET && hr !=
                                                        (uint)CryptKeyError.NTE_FILENOTFOUND && hr !=
                                                        // add: sk
                                                        unchecked((uint)GostConstants.SCARD_W_CANCELLED_BY_USER))))
                                                        // end: sk
                {
                    throw new CryptographicException((int)hr);
                }

                //Create a new CSP. This method throws exception on failure
                CreateCSP(parameters, randomKeyContainer, out safeProvHandle);
            }

            if (parameters.ParentWindowHandle != IntPtr.Zero)
            {
                IntPtr parentWindowHandle = parameters.ParentWindowHandle;

                if (!Interop.CryptSetProvParamIndirectPtr(safeProvHandle, CryptProvParam.PP_CLIENT_HWND, ref parentWindowHandle, 0))
                {
                    throw new CryptographicException(GetErrorCode());
                }
            }

            if (parameters.KeyPassword != null)
            {
                IntPtr password = Marshal.SecureStringToCoTaskMemAnsi(parameters.KeyPassword);
                try
                {
                    CryptProvParam param =
                        (parameters.KeyNumber == (int)KeySpec.AT_SIGNATURE) ?
                            CryptProvParam.PP_SIGNATURE_PIN :
                            CryptProvParam.PP_KEYEXCHANGE_PIN;
                    if (!Interop.CryptSetProvParam(safeProvHandle, param, password, 0))
                    {
                        throw new CryptographicException(GetErrorCode());
                    }
                }
                finally
                {
                    if (password != IntPtr.Zero)
                    {
                        Marshal.ZeroFreeCoTaskMemAnsi(password);
                    }
                }
            }

            return safeProvHandle;
        }

        /// <summary>
        /// This method validates the flag bits set or not. Only works for flags with just one bit set
        /// </summary>
        /// <param name="dwImp">int where you want to check the flag bits</param>
        /// <param name="flag">Actual flag</param>
        /// <returns>true if bits are set or false</returns>
        internal static bool IsFlagBitSet(uint dwImp, uint flag)
        {
            return (dwImp & flag) == flag;
        }

        //    /// <summary>
        //    /// This method helps reduce the duplicate code in the GetProviderParameter method
        //    /// </summary>
        //    internal static int GetProviderParameterWorker(SafeProvHandle safeProvHandle, byte[] impType, ref int cb, CryptProvParam flags)
        //    {
        //        int impTypeReturn = 0;
        //        if (!Interop.CryptGetProvParam(safeProvHandle, flags, impType, ref cb, 0))
        //        {
        //            throw GetErrorCode().ToCryptographicException();
        //        }
        //        if (null != impType && cb == Constants.SIZE_OF_DWORD)
        //        {
        //            impTypeReturn = BitConverter.ToInt32(impType, 0);
        //        }
        //        return impTypeReturn;
        //    }

        //    /// <summary>
        //    /// This method queries the key container and get some of it's properties. 
        //    /// Those properties should never cause UI to display. 
        //    /// </summary>                
        //    public static object GetProviderParameter(SafeProvHandle safeProvHandle, int keyNumber, int keyParam)
        //    {
        //        VerifyValidHandle(safeProvHandle);
        //        byte[] impType = new byte[Constants.SIZE_OF_DWORD];
        //        int cb = sizeof(byte) * Constants.SIZE_OF_DWORD;
        //        SafeKeyHandle safeKeyHandle = SafeKeyHandle.InvalidHandle;
        //        int impTypeReturn = 0;
        //        int returnType = 0; //using 0 for bool and 1 for string return types
        //        bool retVal = false;
        //        string retStr = null;

        //        try
        //        {
        //            switch (keyParam)
        //            {
        //                case Constants.CLR_EXPORTABLE:
        //                    {
        //                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, impType, ref cb, CryptProvParam.PP_IMPTYPE);
        //                        //If implementation type is not HW
        //                        if (!IsFlagBitSet((uint)impTypeReturn, (uint)CryptGetProvParamPPImpTypeFlags.CRYPT_IMPL_HARDWARE))
        //                        {
        //                            if (!Interop.CryptGetUserKey(safeProvHandle, keyNumber, out safeKeyHandle))
        //                            {
        //                                throw GetErrorCode().ToCryptographicException();
        //                            }
        //                            byte[] permissions = null;
        //                            int permissionsReturn = 0;
        //                            permissions = new byte[Constants.SIZE_OF_DWORD];
        //                            cb = sizeof(byte) * Constants.SIZE_OF_DWORD;
        //                            if (!Interop.CryptGetKeyParam(safeKeyHandle, (int)CryptGetKeyParamFlags.KP_PERMISSIONS, permissions, ref cb, 0))
        //                            {
        //                                throw GetErrorCode().ToCryptographicException();
        //                            }
        //                            permissionsReturn = BitConverter.ToInt32(permissions, 0);
        //                            retVal = IsFlagBitSet((uint)permissionsReturn, (uint)CryptGetKeyParamFlags.CRYPT_EXPORT);
        //                        }
        //                        else
        //                        {
        //                            //Assumption HW keys are not exportable.
        //                            retVal = false;
        //                        }

        //                        break;
        //                    }
        //                case Constants.CLR_REMOVABLE:
        //                    {
        //                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, impType, ref cb, CryptProvParam.PP_IMPTYPE);
        //                        retVal = IsFlagBitSet((uint)impTypeReturn, (uint)CryptGetProvParamPPImpTypeFlags.CRYPT_IMPL_REMOVABLE);
        //                        break;
        //                    }
        //                case Constants.CLR_HARDWARE:
        //                case Constants.CLR_PROTECTED:
        //                    {
        //                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, impType, ref cb, CryptProvParam.PP_IMPTYPE);
        //                        retVal = IsFlagBitSet((uint)impTypeReturn, (uint)CryptGetProvParamPPImpTypeFlags.CRYPT_IMPL_HARDWARE);
        //                        break;
        //                    }
        //                case Constants.CLR_ACCESSIBLE:
        //                    {
        //                        retVal = Interop.CryptGetUserKey(safeProvHandle, keyNumber, out safeKeyHandle) ? true : false;
        //                        break;
        //                    }
        //                case Constants.CLR_UNIQUE_CONTAINER:
        //                    {
        //                        returnType = 1;
        //                        byte[] pb = null;
        //                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, pb, ref cb, CryptProvParam.PP_UNIQUE_CONTAINER);
        //                        pb = new byte[cb];
        //                        impTypeReturn = GetProviderParameterWorker(safeProvHandle, pb, ref cb, CryptProvParam.PP_UNIQUE_CONTAINER);
        //                        // GetProviderParameterWorker allocated the null character, we want to not interpret that.
        //                        Debug.Assert(cb > 0);
        //                        Debug.Assert(pb[cb - 1] == 0);
        //                        retStr = Encoding.ASCII.GetString(pb, 0, cb - 1);
        //                        break;
        //                    }
        //                default:
        //                    {
        //                        Debug.Assert(false);
        //                        break;
        //                    }
        //            }
        //        }
        //        finally
        //        {
        //            safeKeyHandle.Dispose();
        //        }

        //        Debug.Assert(returnType == 0 || returnType == 1);
        //        return returnType == 0 ? (object)retVal : retStr;
        //    }

        /// <summary>
        /// Retrieves the handle for user public / private key pair. 
        /// </summary>
        internal static int GetUserKey(SafeProvHandle safeProvHandle, int keySpec, out SafeKeyHandle safeKeyHandle)
        {
            int hr = S_OK;
            VerifyValidHandle(safeProvHandle);
            if (!Interop.CryptGetUserKey(safeProvHandle, keySpec, out safeKeyHandle))
            {
                hr = GetErrorCode();
            }
            if (hr == S_OK)
            {
                safeKeyHandle.KeySpec = keySpec;
            }
            return hr;
        }

        /// <summary>
        /// Generates the key if provided CSP handle is valid 
        /// </summary>
        internal static int GenerateKey(SafeProvHandle safeProvHandle, int algID, int flags, uint keySize, out SafeKeyHandle safeKeyHandle)
        {
            int hr = S_OK;
            VerifyValidHandle(safeProvHandle);
            int capiFlags = (int)((uint)MapCspKeyFlags(flags) | ((uint)keySize << 16));
            if (!Interop.CryptGenKey(safeProvHandle, algID, capiFlags, out safeKeyHandle))
            {
                hr = GetErrorCode();
            }
            if (hr != S_OK)
            {
                throw new CryptographicException(GetErrorCode());
            }

            safeKeyHandle.KeySpec = algID;
            return hr;
        }

        /// <summary>
        /// Maps CspProviderFlags enumeration into CAPI flags.
        /// </summary>
        internal static int MapCspKeyFlags(int flags)
        {
            int capiFlags = 0;
            if (!IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseNonExportableKey))
            {
                capiFlags |= (int)CryptGenKeyFlags.CRYPT_EXPORTABLE;
            }
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseArchivableKey))
            {
                capiFlags |= (int)CryptGenKeyFlags.CRYPT_ARCHIVABLE;
            }
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseUserProtectedKey))
            {
                capiFlags |= (int)CryptGenKeyFlags.CRYPT_USER_PROTECTED;
            }
            return capiFlags;
        }

        /// <summary>
        ///Maps CspProviderFlags enumeration into CAPI flags
        /// </summary>
        internal static uint MapCspProviderFlags(int flags)
        {
            uint cspFlags = 0;

            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseMachineKeyStore))
            {
                cspFlags |= (uint)CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET;
            }
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.NoPrompt))
            {
                cspFlags |= (uint)CryptAcquireContextFlags.CRYPT_SILENT;
            }
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.CreateEphemeralKey))
            {
                cspFlags |= (uint)CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT;
            }
            return cspFlags;
        }

        /// <summary>
        /// This method checks if the handle is invalid then it throws error
        /// </summary>
        /// <param name="handle">Accepts handle</param>
        internal static void VerifyValidHandle(SafeHandleZeroOrMinusOneIsInvalid handle)
        {
            if (handle.IsInvalid)
            {
                throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
            }
        }

        //    /// <summary>
        //    ///Method helps get the different key properties
        //    /// </summary>
        //    /// <param name="safeKeyHandle">Key handle</param>
        //    /// <param name="keyParam"> Key property you want to get</param>
        //    /// <returns>Returns the key property</returns>
        //    internal static byte[] GetKeyParameter(SafeKeyHandle safeKeyHandle, int keyParam)
        //    {
        //        byte[] pb = null;
        //        int cb = 0;
        //        VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

        //        switch (keyParam)
        //        {
        //            case Constants.CLR_KEYLEN:
        //                {
        //                    if (!Interop.CryptGetKeyParam(safeKeyHandle, (int)CryptGetKeyParamQueryType.KP_KEYLEN, null, ref cb, 0))
        //                    {
        //                        throw GetErrorCode().ToCryptographicException();
        //                    }
        //                    pb = new byte[cb];
        //                    if (!Interop.CryptGetKeyParam(safeKeyHandle, (int)CryptGetKeyParamQueryType.KP_KEYLEN, pb, ref cb, 0))
        //                    {
        //                        throw GetErrorCode().ToCryptographicException();
        //                    }
        //                    break;
        //                }
        //            case Constants.CLR_PUBLICKEYONLY:
        //                {
        //                    pb = new byte[1];
        //                    pb[0] = safeKeyHandle.PublicOnly ? (byte)1 : (byte)0;
        //                    break;
        //                }
        //            case Constants.CLR_ALGID:
        //                {
        //                    // returns the algorithm ID for the key
        //                    if (!Interop.CryptGetKeyParam(safeKeyHandle, (int)CryptGetKeyParamQueryType.KP_ALGID, null, ref cb, 0))
        //                    {
        //                        throw GetErrorCode().ToCryptographicException();
        //                    }
        //                    pb = new byte[cb];
        //                    if (!Interop.CryptGetKeyParam(safeKeyHandle, (int)CryptGetKeyParamQueryType.KP_ALGID, pb, ref cb, 0))
        //                    {
        //                        throw GetErrorCode().ToCryptographicException();
        //                    }
        //                    break;
        //                }
        //            default:
        //                {
        //                    Debug.Assert(false);
        //                    break;
        //                }
        //        }
        //        return pb;
        //    }

        //    /// <summary>
        //    /// Set a key property which is based on byte[]
        //    /// </summary>
        //    /// <param name="safeKeyHandle">Key handle</param>
        //    /// <param name="keyParam"> Key property you want to set</param>
        //    /// <param name="value"> Key property value you want to set</param>
        //    internal static void SetKeyParameter(SafeKeyHandle safeKeyHandle, CryptGetKeyParamQueryType keyParam, byte[] value)
        //    {
        //        VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

        //        switch (keyParam)
        //        {
        //            case CryptGetKeyParamQueryType.KP_IV:
        //                if (!Interop.CryptSetKeyParam(safeKeyHandle, (int)keyParam, value, 0))
        //                    throw new CryptographicException(SR.CryptSetKeyParam_Failed, Convert.ToString(GetErrorCode()));

        //                break;
        //            default:
        //                Debug.Fail("Unknown param in SetKeyParameter");
        //                break;
        //        }
        //    }

        //    /// <summary>
        //    /// Set a key property which is based on int
        //    /// </summary>
        //    /// <param name="safeKeyHandle">Key handle</param>
        //    /// <param name="keyParam"> Key property you want to set</param>
        //    /// <param name="value"> Key property value you want to set</param>
        //    internal static void SetKeyParameter(SafeKeyHandle safeKeyHandle, CryptGetKeyParamQueryType keyParam, int value)
        //    {
        //        VerifyValidHandle(safeKeyHandle); //This will throw if handle is invalid

        //        switch (keyParam)
        //        {
        //            case CryptGetKeyParamQueryType.KP_MODE:
        //            case CryptGetKeyParamQueryType.KP_MODE_BITS:
        //            case CryptGetKeyParamQueryType.KP_EFFECTIVE_KEYLEN:
        //                if (!Interop.CryptSetKeyParamInt(safeKeyHandle, (int)keyParam, ref value, 0))
        //                    throw new CryptographicException(SR.CryptSetKeyParam_Failed, Convert.ToString(GetErrorCode()));

        //                break;
        //            default:
        //                Debug.Fail("Unknown param in SetKeyParameter");
        //                break;
        //        }
        //    }

        /// <summary>
        /// Helper method to save the CSP parameters. 
        /// </summary>
        /// <param name="keyType">CSP algorithm type</param>
        /// <param name="userParameters">CSP Parameters passed by user</param>
        /// <param name="defaultFlags">flags </param>
        /// <param name="randomKeyContainer">identifies if it is random key container</param>
        /// <returns></returns>
        internal static CspParameters SaveCspParameters(
            CspAlgorithmType keyType,
            CspParameters userParameters,
            CspProviderFlags defaultFlags,
            out bool randomKeyContainer)
        {
            CspParameters parameters;
            //add: sk
            if (userParameters != null && userParameters.ProviderType != (int)keyType)
            {
                switch (keyType)
                {
                    //case CspAlgorithmType.Dss:
                    //    userParameters.ProviderType = DefaultDssProviderType;
                    //    break;
                    case CspAlgorithmType.PROV_GOST_2001_DH:
                    case CspAlgorithmType.PROV_GOST_2012_256:
                    case CspAlgorithmType.PROV_GOST_2012_512:
                        userParameters.ProviderType = (int)keyType;
                        break;
                    //case CspAlgorithmType.Rsa:
                    default:
                        userParameters.ProviderType = DefaultRsaProviderType;
                        break;
                }
            }
            //end: sk

            if (userParameters == null)
            {
                //add: sk
                switch (keyType)
                {
                    //case CspAlgorithmType.Dss:
                    //    parameters = new CspParameters(DefaultDssProviderType, null, null, defaultFlags);
                    //    break;
                    case CspAlgorithmType.PROV_GOST_2001_DH:
                    case CspAlgorithmType.PROV_GOST_2012_256:
                    case CspAlgorithmType.PROV_GOST_2012_512:
                        parameters = new CspParameters((int)keyType, null, null, defaultFlags);
                        break;
                    //case CspAlgorithmType.Rsa:
                    default:
                        parameters = new CspParameters(DefaultRsaProviderType, null, null, defaultFlags);
                        break;
                }
                //end: sk
            }
            else
            {
                ValidateCspFlags(userParameters.Flags);
                parameters = new CspParameters(userParameters);
            }
            if (parameters.KeyNumber == -1)
            {
                // if gost goes here it ends with KeyNumber.Exchange
                parameters.KeyNumber = keyType == CapiHelper.CspAlgorithmType.Dss
                                           ? (int)KeyNumber.Signature
                                           : (int)KeyNumber.Exchange;
            }
            else if (parameters.KeyNumber == CALG_DSS_SIGN || 
                     parameters.KeyNumber == CALG_RSA_SIGN ||
                     parameters.KeyNumber == GostConstants.CALG_GR3410EL ||
                     parameters.KeyNumber == GostConstants.CALG_GR3410_12_256 ||
                     parameters.KeyNumber == GostConstants.CALG_GR3410_12_256)
            {
                parameters.KeyNumber = (int)KeyNumber.Signature;
            }
            else if (parameters.KeyNumber == CALG_RSA_KEYX ||
                     parameters.KeyNumber == GostConstants.CALG_DH_EL_SF ||
                     parameters.KeyNumber == GostConstants.CALG_DH_EL_SF ||
                     parameters.KeyNumber == GostConstants.CALG_DH_GR3410_12_512_SF)
            {
                parameters.KeyNumber = (int)KeyNumber.Exchange;
            }

            // If no key container was specified and UseDefaultKeyContainer is not used, then use CRYPT_VERIFYCONTEXT
            // to generate an ephemeral key
            randomKeyContainer = IsFlagBitSet((uint)parameters.Flags, (uint)CspProviderFlags.CreateEphemeralKey);

            if (parameters.KeyContainerName == null && !IsFlagBitSet((uint)parameters.Flags,
                (uint)CspProviderFlags.UseDefaultKeyContainer))
            {
                // add: sk
                switch (parameters.ProviderType)
                {
                    case (int)CspAlgorithmType.PROV_GOST_2001_DH:
                    case (int)CspAlgorithmType.PROV_GOST_2012_256:
                    case (int)CspAlgorithmType.PROV_GOST_2012_512:
                    {
                        parameters.KeyContainerName = GetRandomKeyContainer();
                        break;
                    }
                    default:
                    {
                        parameters.Flags |= CspProviderFlags.CreateEphemeralKey;
                        break;
                    }
                }
                // end: sk
                randomKeyContainer = true;
            }

            return parameters;
        }
		
		// add: sk

        /// <summary>
        /// Generates random keyContainer name
        /// </summary>
        private static string GetRandomKeyContainer()
        {
            return "CLR{" + Guid.NewGuid().ToString().ToUpper() + "}";
        }

        // end: sk

        /// <summary>
        /// Validates the CSP flags are expected
        /// </summary>
        /// <param name="flags">CSP provider flags</param>
        private static void ValidateCspFlags(CspProviderFlags flags)
        {
            // check that the flags are consistent.
            if (IsFlagBitSet((uint)flags, (uint)CspProviderFlags.UseExistingKey))
            {
                CspProviderFlags keyFlags = (CspProviderFlags.UseNonExportableKey |
                                            CspProviderFlags.UseArchivableKey |
                                            CspProviderFlags.UseUserProtectedKey);
                if ((flags & keyFlags) != CspProviderFlags.NoFlags)
                {
                    throw new ArgumentException(SR.Format(SR.Arg_EnumIllegalVal, Convert.ToString(flags)), nameof(flags));
                }
            }
        }

        /// <summary>
        /// Helper function to get the key pair
        /// </summary>
        internal static SafeKeyHandle GetKeyPairHelper(
            CspAlgorithmType keyType,
            CspParameters parameters,
            int keySize,
            SafeProvHandle safeProvHandle)
        {
            // If the key already exists, use it, else generate a new one
            SafeKeyHandle hKey;
            int hr = CapiHelper.GetUserKey(safeProvHandle, parameters.KeyNumber, out hKey);
            if (hr != S_OK)
            {
                hKey.Dispose();
                if (unchecked(IsFlagBitSet((uint)parameters.Flags, (uint)CspProviderFlags.UseExistingKey) ||
                                                                   (uint)hr != (uint)CryptKeyError.NTE_NO_KEY))
                {
                    throw new CryptographicException((int)hr);
                }

                // GenerateKey will check for failures and throw an exception
                CapiHelper.GenerateKey(safeProvHandle, parameters.KeyNumber, (int)parameters.Flags,
                                        (uint)keySize, out hKey);
            }

            return hKey;
        }

        /// <summary>
        /// Wrapper for get last error function
        /// </summary>
        /// <returns>returns the error code</returns>
        internal static int GetErrorCode()
        {
            return Marshal.GetLastWin32Error();
        }

        /// <summary>
        /// Returns PersistKeyInCsp value
        /// </summary>
        /// <param name="safeProvHandle">Safe Prov Handle. Expects a valid handle</param>
        /// <returns>true if key is persisted otherwise false</returns>
        internal static bool GetPersistKeyInCsp(SafeProvHandle safeProvHandle)
        {
            VerifyValidHandle(safeProvHandle);
            return safeProvHandle.PersistKeyInCsp;
        }

        /// <summary>
        /// Sets the PersistKeyInCsp
        /// </summary>
        /// <param name="safeProvHandle">Safe Prov Handle. Expects a valid handle</param>
        /// <param name="fPersistKeyInCsp">Sets the PersistKeyInCsp value</param>
        internal static void SetPersistKeyInCsp(SafeProvHandle safeProvHandle, bool fPersistKeyInCsp)
        {
            VerifyValidHandle(safeProvHandle);
            safeProvHandle.PersistKeyInCsp = fPersistKeyInCsp;
        }

  
        //add:SK
        /// <summary>
        /// Получение OID алгоритма для переданного объекта хеширования.
        /// </summary>
        /// 
        /// <param name="hashAlg">Объект хеширования: собственно
        /// объект, OID, строка имени...</param>
        /// 
        /// <returns>OID алгоритма хеширования.</returns>
        /// 
        /// <exception cref="ArgumentException">Переданный объект
        /// не объект алгоритма хеширования.</exception>
        /// 
        /// <intdoc><para>Функция полностью аналогична MS.</para></intdoc>
        internal static string ObjToOidValue(object hashAlg)
        {
            if (hashAlg == null)
                throw new ArgumentNullException("hashAlg");
            string s = null;
            string sHashAlg = hashAlg as string;
            if (sHashAlg != null)
            {
                s = CryptoConfig.MapNameToOID(sHashAlg);
                if (s == null)
                    s = sHashAlg;
            }
            else if ((hashAlg is HashAlgorithm))
            {
                s = CryptoConfig.MapNameToOID(hashAlg.GetType().ToString());
            }
            else if ((hashAlg is Type))
            {
                s = CryptoConfig.MapNameToOID(hashAlg.ToString());
            }
            if (s == null)
                throw new ArgumentException(SR.Argument_InvalidValue, nameof(hashAlg));
            return s;
        }

        /// <summary>
        /// Helper for Export CSP
        /// </summary>
        internal static byte[] ExportKeyBlob(bool includePrivateParameters, SafeKeyHandle safeKeyHandle)
        {
            VerifyValidHandle(safeKeyHandle);

            byte[] pbRawData = null;
            int cbRawData = 0;
            int dwBlobType = includePrivateParameters ? PRIVATEKEYBLOB : PUBLICKEYBLOB;

            if (!Interop.CryptExportKey(safeKeyHandle, SafeKeyHandle.InvalidHandle, dwBlobType, 0, null, ref cbRawData))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
            pbRawData = new byte[cbRawData];

            if (!Interop.CryptExportKey(safeKeyHandle, SafeKeyHandle.InvalidHandle, dwBlobType, 0, pbRawData, ref cbRawData))
            {
                throw new CryptographicException(Marshal.GetLastWin32Error());
            }
            return pbRawData;
        }
        //end: SK

        //    //add: sk
        //    //HelperMethod used by HashData
        //    public static void CryptHashData(SafeHashHandle hHash, byte[] pbData, int dwDataLen, int dwFlags)
        //    {
        //        unsafe
        //        {
        //            bool ret = Interop.CryptHashData(hHash, pbData,
        //                dwDataLen, 0);
        //            if (!ret)
        //                throw new CryptographicException(
        //                    Marshal.GetLastWin32Error());
        //        }
        //    }

        //    /// <summary>
        //    /// Завершение хешифрования и получение значения хеша.
        //    /// </summary>
        //    /// 
        //    /// <param name="hHash">HNALDE хеша.</param>
        //    /// 
        //    /// <returns>Значение хеша.</returns>
        //    /// 
        //    /// <exception cref="CryptographicException">При ошибках на native
        //    /// уровне.</exception>
        //    /// 
        //    /// <intdoc><para>Есть аналог у MS с тем же прототипом и похожей
        //    /// (CRYPT_HASH_CTX другой) реализацией.</para></intdoc>
        //    /// 
        //    /// <unmanagedperm action="LinkDemand" />
        //    //internal static byte[] EndHash(SafeHashHandle hHash)
        //    //{
        //    //    int dwDataLen = 0;
        //    //    int dwHashSize = 0;
        //    //    bool ret = Interop.CryptGetHashParam(hHash,
        //    //        CryptHashProperty.HP_HASHVAL, out dwHashSize, ref dwDataLen, 0);
        //    //    if (!ret)
        //    //        throw new CryptographicException(Marshal.GetLastWin32Error());
        //    //    byte[] data = new byte[dwDataLen];
        //    //    ret = Interop.CryptGetHashParam(hHash,
        //    //        CryptHashProperty.HP_HASHVAL, out data, ref dwDataLen, 0);
        //    //    if (!ret)
        //    //        throw new CryptographicException(Marshal.GetLastWin32Error());
        //    //    return data;
        //    //}
        //    //end:sk


        /// <summary>
        /// Destroy a crypto provider.
        /// </summary>
        public static bool CryptReleaseContext(IntPtr safeProvHandle, int dwFlags)
        {
            return Interop.CryptReleaseContext(safeProvHandle, dwFlags);
        }

        /// <summary>
        /// Destroy a crypto key.
        /// </summary>
        public static bool CryptDestroyKey(IntPtr hKey)
        {
            return Interop.CryptDestroyKey(hKey);
        }

        /// <summary>
        /// Destroy a crypto hash.
        /// </summary>
        public static bool CryptDestroyHash(IntPtr hHash)
        {
            return Interop.CryptDestroyHash(hHash);
        }

        /// <summary>
        /// Create a CAPI-1 hash handle that contains the specified bits as its hash value.
        /// </summary>
        private static SafeHashHandle CreateHashHandle(this SafeProvHandle hProv, byte[] hash, int calgHash)
        {
            SafeHashHandle hHash;
            if (!Interop.CryptCreateHash(hProv, calgHash, SafeKeyHandle.InvalidHandle, CryptCreateHashFlags.None, out hHash))
            {
                int hr = Marshal.GetHRForLastWin32Error();

                hHash.Dispose();

                throw new CryptographicException(hr);
            }

            try
            {
                int dwHashSize = 0;
                int cbHashSize = sizeof(int);
                if (!Interop.CryptGetHashParam(hHash, CryptHashProperty.HP_HASHSIZE, out dwHashSize, ref cbHashSize, 0))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }
                if (dwHashSize != hash.Length)
                    throw new CryptographicException(unchecked((int)CryptKeyError.NTE_BAD_HASH));

                if (!Interop.CryptSetHashParam(hHash, CryptHashProperty.HP_HASHVAL, hash, 0))
                {
                    int hr = Marshal.GetHRForLastWin32Error();
                    throw new CryptographicException(hr);
                }

                SafeHashHandle hHashPermanent = hHash;
                hHash = null;
                return hHashPermanent;
            }
            finally
            {
                if (hHash != null)
                {
                    hHash.Dispose();
                }
            }
        }

        /// <summary>
        /// Helper for GostCryptoServiceProvider.VerifyData/VerifyHash apis.
        /// </summary>
        public static bool VerifySign(SafeProvHandle hProv, SafeKeyHandle hKey, int calgKey, int calgHash, byte[] hash, byte[] signature)
        {
            switch (calgKey)
            {
                case CALG_RSA_SIGN:
                    signature = signature.CloneByteArray();
                    Array.Reverse(signature);
                    break;
                default:
                    throw new InvalidOperationException();
            }

            using (SafeHashHandle hHash = hProv.CreateHashHandle(hash, calgHash))
            {
                bool verified = Interop.CryptVerifySignature(hHash, signature, signature.Length, hKey, null, CryptSignAndVerifyHashFlags.None);
                return verified;
            }
        }
        /// <summary>
        /// Helper for Import CSP
        /// </summary>
        internal static void ImportKeyBlob(SafeProvHandle saveProvHandle, CspProviderFlags flags, bool addNoSaltFlag, byte[] keyBlob, out SafeKeyHandle safeKeyHandle)
        {
            // Compat note: This isn't the same check as the one done by the CLR _ImportCspBlob QCall,
            // but this does match the desktop CLR behavior and the only scenarios it
            // affects are cases where a corrupt blob is passed in.
            bool isPublic = keyBlob.Length > 0 && keyBlob[0] == CapiHelper.PUBLICKEYBLOB;

            int dwCapiFlags = MapCspKeyFlags((int)flags);
            if (isPublic)
            {
                dwCapiFlags &= ~(int)(CryptGenKeyFlags.CRYPT_EXPORTABLE);
            }

            if (addNoSaltFlag)
            {
                // For RC2 running in rsabase.dll compatibility mode, make sure 11 bytes of
                // zero salt are generated when using a 40 bit RC2 key.
                dwCapiFlags |= (int)CryptGenKeyFlags.CRYPT_NO_SALT;
            }

            SafeKeyHandle hKey;
            if (!Interop.CryptImportKey(saveProvHandle, keyBlob, keyBlob.Length, SafeKeyHandle.InvalidHandle, dwCapiFlags, out hKey))
            {
                int hr = Marshal.GetHRForLastWin32Error();

                hKey.Dispose();

                throw new CryptographicException(hr);
            }

            hKey.PublicOnly = isPublic;
            safeKeyHandle = hKey;

            return;
        }
    }//End of class CapiHelper : Wrappers

    /// <summary>
    /// All the PInvoke are captured in following part of CapiHelper class
    /// </summary>
    internal static partial class CapiHelper
    {
        private static class Interop
        {
            [DllImport(Libraries.CapiLite, SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CryptGetDefaultProviderW")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptGetDefaultProvider(int dwProvType, IntPtr pdwReserved, int dwFlags,
                                                              StringBuilder pszProvName, ref int IntPtrProvName);

            [DllImport(Libraries.CapiLite, SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CryptAcquireContextW")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptAcquireContext(out SafeProvHandle psafeProvHandle, string pszContainer,
                                                            string pszProvider, int dwProvType, uint dwFlags);

            public static unsafe bool CryptGetProvParam(
                SafeProvHandle safeProvHandle,
                CryptProvParam dwParam,
                byte[] pbData,
                ref int dwDataLen,
                int dwFlags)
            {
                if (dwDataLen > pbData?.Length)
                {
                    throw new IndexOutOfRangeException();
                }

                fixed (byte* bytePtr = pbData)
                {
                    return global::Interop.CapiLite.CryptGetProvParam(
                        safeProvHandle,
                        dwParam,
                        (IntPtr)bytePtr,
                        ref dwDataLen,
                        dwFlags);
                }
            }

            [DllImport(Libraries.CapiLite, SetLastError = true, EntryPoint = "CryptSetProvParam")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptSetProvParamIndirectPtr(SafeProvHandle safeProvHandle, CryptProvParam dwParam, ref IntPtr pbData, int dwFlags);

            public static bool CryptSetProvParam(
                SafeProvHandle safeProvHandle,
                CryptProvParam dwParam,
                IntPtr pbData,
                int dwFlags)
            {
                return global::Interop.CapiLite.CryptSetProvParam(safeProvHandle, dwParam, pbData, dwFlags);
            }

            [DllImport(Libraries.CapiLite, SetLastError = true, EntryPoint = "CryptGetUserKey")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool _CryptGetUserKey(SafeProvHandle safeProvHandle, int dwKeySpec, out SafeKeyHandle safeKeyHandle);

            [DllImport(Libraries.CapiLite, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptGetKeyParam(SafeKeyHandle safeKeyHandle, int dwParam, byte[] pbData,
                                                        ref int pdwDataLen, int dwFlags);

            [DllImport(Libraries.CapiLite, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptSetKeyParam(SafeKeyHandle safeKeyHandle, int dwParam, byte[] pbData, int dwFlags);

            [DllImport(Libraries.CapiLite, SetLastError = true, EntryPoint = "CryptSetKeyParam")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptSetKeyParamInt(SafeKeyHandle safeKeyHandle, int dwParam, ref int pdw, int dwFlags);

            [DllImport(Libraries.CapiLite, SetLastError = true, EntryPoint = "CryptGenKey")]
            private static extern bool _CryptGenKey(SafeProvHandle safeProvHandle, int Algid, int dwFlags, out SafeKeyHandle safeKeyHandle);

            [DllImport(Libraries.CapiLite, SetLastError = true)]
            public static extern bool CryptReleaseContext(IntPtr safeProvHandle, int dwFlags);

            [DllImport(Libraries.CapiLite, SetLastError = true)]
            public static extern bool CryptDecrypt(SafeKeyHandle safeKeyHandle, SafeHashHandle safeHashHandle, bool Final,
                                                    int dwFlags, byte[] pbData, ref int pdwDataLen);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptEncrypt(SafeKeyHandle safeKeyHandle, SafeHashHandle safeHashHandle,
                                                    bool Final, int dwFlags, byte[] pbData, ref int pdwDataLen,
                                                    int dwBufLen);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptDeriveKey")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool _CryptDeriveKey(SafeProvHandle safeProvHandle, int algId, SafeHashHandle phHash, int dwFlags, out SafeKeyHandle phKey);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptExportKey(SafeKeyHandle hKey, SafeKeyHandle hExpKey, int dwBlobType,
                                                    int dwFlags, [In, Out] byte[] pbData, ref int dwDataLen);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptImportKey")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool _CryptImportKey(SafeProvHandle hProv, byte[] pbData, int dwDataLen, SafeKeyHandle hPubKey, int dwFlags, out SafeKeyHandle phKey);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptCreateHash")]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool _CryptCreateHash(SafeProvHandle hProv, int algId, SafeKeyHandle hKey, CryptCreateHashFlags dwFlags, out SafeHashHandle phHash);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptHashData(SafeHashHandle hHash, byte[] pbData, int dwDataLen, int dwFlags);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptGetHashParam(SafeHashHandle hHash, CryptHashProperty dwParam, out int pbData, [In, Out] ref int pdwDataLen, int dwFlags);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptSetHashParam(SafeHashHandle hHash, CryptHashProperty dwParam, byte[] buffer, int dwFlags);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptSignHashW")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptSignHash(SafeHashHandle hHash, KeySpec dwKeySpec, String sDescription, CryptSignAndVerifyHashFlags dwFlags, [Out] byte[] pbSignature, [In, Out] ref int pdwSigLen);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CryptVerifySignatureW")]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptVerifySignature(SafeHashHandle hHash, byte[] pbSignature, int dwSigLen, SafeKeyHandle hPubKey, String sDescription, CryptSignAndVerifyHashFlags dwFlags);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptDestroyKey(IntPtr hKey);

            [DllImport(Libraries.CapiLite, CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CryptDestroyHash(IntPtr hHash);

            public static bool CryptGetUserKey(
                SafeProvHandle safeProvHandle,
                int dwKeySpec,
                out SafeKeyHandle safeKeyHandle)
            {
                bool response = _CryptGetUserKey(safeProvHandle, dwKeySpec, out safeKeyHandle);

                safeKeyHandle.SetParent(safeProvHandle);

                return response;
            }

            public static bool CryptGenKey(
                SafeProvHandle safeProvHandle,
                int algId,
                int dwFlags,
                out SafeKeyHandle safeKeyHandle)
            {
                bool response = _CryptGenKey(safeProvHandle, algId, dwFlags, out safeKeyHandle);

                safeKeyHandle.SetParent(safeProvHandle);

                return response;
            }

            public static bool CryptImportKey(
                SafeProvHandle hProv,
                byte[] pbData,
                int dwDataLen,
                SafeKeyHandle hPubKey,
                int dwFlags,
                out SafeKeyHandle phKey)
            {
                bool response = _CryptImportKey(hProv, pbData, dwDataLen, hPubKey, dwFlags, out phKey);

                phKey.SetParent(hProv);

                return response;
            }

            public static bool CryptCreateHash(
                SafeProvHandle hProv,
                int algId,
                SafeKeyHandle hKey,
                CryptCreateHashFlags dwFlags,
                out SafeHashHandle phHash)
            {
                bool response = _CryptCreateHash(hProv, algId, hKey, dwFlags, out phHash);

                phHash.SetParent(hProv);

                return response;
            }

            public static bool CryptDeriveKey(
                SafeProvHandle hProv,
                int algId,
                SafeHashHandle phHash,
                int dwFlags,
                out SafeKeyHandle phKey)
            {
                bool response = _CryptDeriveKey(hProv, algId, phHash, dwFlags, out phKey);

                phKey.SetParent(hProv);

                return response;
            }
        }
    } //End CapiHelper : Pinvokes
}
