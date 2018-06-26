// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;

namespace Internal.NativeCrypto
{
    internal static partial class CapiHelper
    {

        /// <summary>
        /// Helper for all GostCryptoServiceProvider.ImportParameters()
        /// </summary>
        /// Кодирование Public ключа ГОСТ 34.10 в BLOB для импорта.
        /// </summary>
        /// 
        /// <param name="cspObject">Открытый ключ с параметрами.</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <returns>BLOB для импорта.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. У нас функция используется еще 
        /// и при разборе открытого клуча в обходе
        /// <see cref="CryptoPro.Sharpei.NetDetours.CPPublicKey"/>.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static byte[] EncodePublicBlob(Gost3410CspObject cspObject, CspAlgorithmType alg)
        {
            int keySize;
            int algId;

            switch (alg)
            {
                case CspAlgorithmType.PROV_GOST_2001_DH:
                    keySize = GostConstants.EL_SIZE;
                    algId = GostConstants.CALG_GR3410EL;
                    break;
                case CspAlgorithmType.PROV_GOST_2012_256:
                    keySize = GostConstants.GOST3410_2012_256KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_256;
                    break;
                case CspAlgorithmType.PROV_GOST_2012_512:
                    keySize = GostConstants.GOST3410_2012_512KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_512;
                    break;
                default:
                    throw new CryptographicException(SR.Cryptography_CSP_WrongKeySpec);
            }

            if (cspObject == null)
                throw new ArgumentNullException("cspObject");

            byte[] encodedParameters = cspObject.EncodeParameters();

            byte[] data = new byte[16 + encodedParameters.Length
                + cspObject._publicKey.Length];
            data[0] = GostConstants.PUBLICKEYBLOB;
            data[1] = GostConstants.CSP_CUR_BLOB_VERSION;

            byte[] algid = BitConverter.GetBytes(algId);
            Array.Copy(algid, 0, data, 4, 4);

            byte[] magic = BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC);
            Array.Copy(magic, 0, data, 8, 4);

            byte[] bitlen = BitConverter.GetBytes(keySize);
            Array.Copy(bitlen, 0, data, 12, 4);

            Array.Copy(encodedParameters, 0, data, 16,
                encodedParameters.Length);
            Array.Copy(cspObject._publicKey, 0, data,
                16 + encodedParameters.Length,
                cspObject._publicKey.Length);
            return data;
        }

        /// <summary>
        /// Helper for all GostCryptoServiceProvider.ImportParameters()
        /// </summary>
        /// Кодирование Public ключа ГОСТ 34.10 в BLOB для импорта.
        /// </summary>
        /// 
        /// <param name="keyBlob">Откытый ключ без параметров.</param>
        /// <param name="paramBlob">Параметры откытого ключа</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <returns>BLOB для импорта.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. У нас функция используется еще 
        /// и при разборе открытого клуча в обходе
        /// <see cref="CryptoPro.Sharpei.NetDetours.CPPublicKey"/>.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static byte[] EncodePublicBlob(byte[] keyBlob, byte[] paramBlob, CspAlgorithmType alg)
        {
            int keySize;
            int algId;

            switch (alg)
            {
                case CspAlgorithmType.PROV_GOST_2001_DH:
                    keySize = GostConstants.EL_SIZE;
                    algId = GostConstants.CALG_GR3410EL;
                    break;
                case CspAlgorithmType.PROV_GOST_2012_256:
                    keySize = GostConstants.GOST3410_2012_256KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_256;
                    break;
                case CspAlgorithmType.PROV_GOST_2012_512:
                    keySize = GostConstants.GOST3410_2012_512KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_512;
                    break;
                default:
                    throw new CryptographicException(SR.Cryptography_CSP_WrongKeySpec);
            }

            byte[] data = new byte[16 + paramBlob.Length
                + keyBlob.Length];
            data[0] = GostConstants.PUBLICKEYBLOB;
            data[1] = GostConstants.CSP_CUR_BLOB_VERSION;

            byte[] algid = BitConverter.GetBytes(algId);
            Array.Copy(algid, 0, data, 4, 4);

            byte[] magic = BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC);
            Array.Copy(magic, 0, data, 8, 4);

            byte[] bitlen = BitConverter.GetBytes(keySize);
            Array.Copy(bitlen, 0, data, 12, 4);

            Array.Copy(paramBlob, 0, data, 16,
                paramBlob.Length);
            Array.Copy(keyBlob, 0, data,
                16 + paramBlob.Length,
                keyBlob.Length);
            return data;
        }

        /// <summary>
        /// Разбор BLOB открытого ключа ГОСТ 34.10.
        /// </summary>
        /// 
        /// <param name="obj">Gost3410CspObject</param>
        /// <param name="data">BLOB</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <argnull name="obj" />
        /// <exception cref="CryptographicException">Если 
        /// <paramref name="obj"/> не объект типа 
        /// <see cref="Gost3410CspObject"/></exception>
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. </para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void DecodePublicBlob(Object obj, byte[] data, CspAlgorithmType alg)
        {
            int keySize;

            switch (alg)
            {
                case CspAlgorithmType.PROV_GOST_2001_DH:
                    keySize = GostConstants.EL_SIZE;
                    break;
                case CspAlgorithmType.PROV_GOST_2012_256:
                    keySize = GostConstants.GOST3410_2012_256KEY_SIZE;
                    break;
                case CspAlgorithmType.PROV_GOST_2012_512:
                    keySize = GostConstants.GOST3410_2012_512KEY_SIZE;
                    break;
                default:
                    throw new CryptographicException(SR.Cryptography_CSP_WrongKeySpec);
            }

            if (obj == null)
                throw new ArgumentNullException("obj");
            Gost3410CspObject cspObject = obj as Gost3410CspObject;
            if (cspObject == null)
                throw new CryptographicException(GostConstants.NTE_BAD_ALGID);
            if (data.Length < 16 + keySize / 8)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            
            // CRYPT_PUBKEYPARAM -> 8 { Magic, BitLen )
            uint magic = BitConverter.ToUInt32(data, 8);
            uint bitlen = BitConverter.ToUInt32(data, 12);
            if (magic != GostConstants.GR3410_1_MAGIC)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            if (bitlen != keySize)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);

            byte[] tmp = new byte[data.Length - 16 - keySize / 8];
            Array.Copy(data, 16, tmp, 0, data.Length - 16 - keySize / 8);


            var publicKeyParameters = new GostKeyExchangeParameters();
            var encodeKeyParameters = new byte[(data.Length - 16) - keySize / 8];
            Array.Copy(data, 16, encodeKeyParameters, 0, (data.Length - 16) - keySize / 8);
            publicKeyParameters.DecodeParameters(encodeKeyParameters);

            var publicKey = new byte[keySize / 8];
            Array.Copy(data, data.Length - keySize / 8, publicKey, 0, keySize / 8);
            publicKeyParameters.PublicKey = publicKey;

            cspObject._publicKey = publicKeyParameters.PublicKey;
            cspObject._publicKeyParamSet = publicKeyParameters.PublicKeyParamSet;
            cspObject._digestParamSet = publicKeyParameters.DigestParamSet;
        }

        /// <summary>
        /// Кодирование сессионного ключа в SIMPLE BLOB.
        /// </summary>
        /// 
        /// <param name="cspObject">Зашифрованный сессионный ключ.</param>
        /// <param name="algid">Алгоритм зашифрованного ключа.</param>
        /// 
        /// <returns>BLOB</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. </para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        //internal static byte[] EncodeSimpleBlob(GostWrappedKeyObject cspObject, int algid)
        //{
        //    if (cspObject == null)
        //        throw new ArgumentNullException("cspObject");

        //    byte[] par = cpAsnUtils.EncodeGost28147_89_BlobParameters(
        //        cspObject.encryptionParamSet_);

        //    byte[] ret = new byte[16
        //        + GostConstants.SEANCE_VECTOR_LEN
        //        + GostConstants.G28147_KEYLEN
        //        + GostConstants.EXPORT_IMIT_SIZE
        //        + par.Length];
        //    int pos = 0;

        //    // CRYPT_SIMPLEBLOB_->CRYPT_SIMPLEBLOB_HEADER
        //    ret[pos] = GostConstants.SIMPLEBLOB;
        //    pos++;
        //    ret[pos] = GostConstants.CSP_CUR_BLOB_VERSION;
        //    pos++;

        //    pos += 2; // Reserved

        //    byte[] balgid = BitConverter.GetBytes(algid);
        //    Array.Copy(balgid, 0, ret, pos, 4);
        //    pos += 4;

        //    byte[] magic = BitConverter.GetBytes(GostConstants.SIMPLEBLOB_MAGIC);
        //    Array.Copy(magic, 0, ret, pos, 4);
        //    pos += 4;

        //    byte[] ealgid = BitConverter.GetBytes(GostConstants.CALG_G28147);
        //    Array.Copy(ealgid, 0, ret, pos, 4);
        //    pos += 4;

        //    // CRYPT_SIMPLEBLOB_->bSV
        //    Array.Copy(cspObject.ukm_, 0, ret, pos, GostConstants.SEANCE_VECTOR_LEN);
        //    pos += GostConstants.SEANCE_VECTOR_LEN;

        //    // CRYPT_SIMPLEBLOB_->bEncryptedKey
        //    Array.Copy(cspObject.encryptedKey_, 0, ret, pos, GostConstants.G28147_KEYLEN);
        //    pos += GostConstants.G28147_KEYLEN;

        //    // CRYPT_SIMPLEBLOB_->bMacKey
        //    Array.Copy(cspObject.mac_, 0, ret, pos, GostConstants.EXPORT_IMIT_SIZE);
        //    pos += GostConstants.EXPORT_IMIT_SIZE;

        //    // CRYPT_SIMPLEBLOB_->bEncryptionParamSet
        //    Array.Copy(par, 0, ret, pos, par.Length);
        //    return ret;
        //}

        /// <summary>
        /// Декодирование зашифрованного сессионного ключа из BLOB
        /// в структуру.
        /// </summary>
        /// 
        /// <param name="cspObject"><see cref="GostWrappedKeyObject"/></param>
        /// <param name="data">BLOB</param>
        /// 
        /// <argnull name="data" />
        /// <argnull name="cspObject" />
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования структуры.</exception>
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. </para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        //internal static void DecodeSimpleBlob(GostWrappedKeyObject cspObject, byte[] data)
        //{
        //    if (data == null)
        //        throw new ArgumentNullException("data");
        //    if (cspObject == null)
        //        throw new ArgumentNullException("cspObject");
        //    if (data.Length < 16 + 0)
        //        throw new CryptographicException(GostConstants.NTE_BAD_DATA);
        //    // CRYPT_SIMPLEBLOB_HEADER_->BLOB_HEADER.aiKeyAlg ->4
        //    uint aiKeyAlg = BitConverter.ToUInt32(data, 4);
        //    if (aiKeyAlg != GostConstants.CALG_G28147)
        //        throw new CryptographicException(GostConstants.NTE_BAD_DATA);
        //    // CRYPT_SIMPLEBLOB_HEADER_-> 8 (Magic, EncryptKeyAlgId)
        //    uint magic = BitConverter.ToUInt32(data, 8);
        //    if (magic != GostConstants.SIMPLEBLOB_MAGIC)
        //        throw new CryptographicException(GostConstants.NTE_BAD_DATA);
        //    uint EncryptKeyAlgId = BitConverter.ToUInt32(data, 12);
        //    if (EncryptKeyAlgId != GostConstants.CALG_G28147)
        //        throw new CryptographicException(GostConstants.NTE_BAD_DATA);
        //    // CRYPT_SIMPLEBLOB_->bSV
        //    int pos = 16;
        //    cspObject.ukm_ = new byte[GostConstants.SEANCE_VECTOR_LEN];
        //    Array.Copy(data, pos, cspObject.ukm_, 0, GostConstants.SEANCE_VECTOR_LEN);
        //    pos += GostConstants.SEANCE_VECTOR_LEN;
        //    // CRYPT_SIMPLEBLOB_->bEncryptedKey
        //    cspObject.encryptedKey_ = new byte[GostConstants.G28147_KEYLEN];
        //    Array.Copy(data, pos, cspObject.encryptedKey_, 0, GostConstants.G28147_KEYLEN);
        //    pos += GostConstants.G28147_KEYLEN;
        //    // CRYPT_SIMPLEBLOB_->bMacKey
        //    cspObject.mac_ = new byte[GostConstants.EXPORT_IMIT_SIZE];
        //    Array.Copy(data, pos, cspObject.mac_, 0, GostConstants.EXPORT_IMIT_SIZE);
        //    pos += GostConstants.EXPORT_IMIT_SIZE;
        //    // CRYPT_SIMPLEBLOB_->bEncryptionParamSet
        //    byte[] tmp = new byte[data.Length - pos];
        //    Array.Copy(data, pos, tmp, 0, data.Length - pos);
        //    cspObject.encryptionParamSet_ = cpAsnUtils.DecodeGost28147_89_BlobParameters(tmp);
       //}
    }
}
