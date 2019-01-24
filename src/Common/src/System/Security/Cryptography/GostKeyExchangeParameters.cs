// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    /// <summary>
    /// Параметры алгоритма цифровой подписи ГОСТ Р 34.10 и алгоритма формирования общего секретного ключа, включая открытый ключ.
    /// </summary>
    public sealed class GostKeyExchangeParameters
    {
        public GostKeyExchangeParameters()
        {
        }

        public GostKeyExchangeParameters(GostKeyExchangeParameters parameters)
        {
            DigestParamSet = parameters.DigestParamSet;
            PublicKeyParamSet = parameters.PublicKeyParamSet;
            EncryptionParamSet = parameters.EncryptionParamSet;
            PublicKey = parameters.PublicKey;
            PrivateKey = parameters.PrivateKey;
        }


        /// <summary>
        /// Идентификатор OID параметров хэширования.
        /// </summary>
        public string DigestParamSet;

        /// <summary>
        /// Идентификатор OID параметров открытого ключа.
        /// </summary>
        public string PublicKeyParamSet;

        /// <summary>
        /// Идентификатор OID параметров шифрования.
        /// </summary>
        public string EncryptionParamSet;

        /// <summary>
        /// Открытый ключ.
        /// </summary>
        public byte[] PublicKey;

        /// <summary>
        /// Закрытый ключ.
        /// </summary>
        public byte[] PrivateKey;


        public void DecodeParameters(byte[] data)
        {
            if (data == null)
            {
                throw new Exception("ArgumentNull - data");
            }

            var asnDecoder = new Asn1BerDecodeBuffer(data);
            var publicKeyParameters = new GostR34102001PublicKeyParameters();
            publicKeyParameters.Decode(asnDecoder);

            DigestParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.DigestParamSet);
            PublicKeyParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.PublicKeyParamSet);
            EncryptionParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.EncryptionParamSet);
        }


        public byte[] EncodeParameters()
        {
            byte[] data;

            var publicKeyParameters = new GostR34102001PublicKeyParameters();

            publicKeyParameters.DigestParamSet = Asn1ObjectIdentifier.FromOidString(DigestParamSet);
            publicKeyParameters.PublicKeyParamSet = Asn1ObjectIdentifier.FromOidString(PublicKeyParamSet);
            publicKeyParameters.EncryptionParamSet = CreateEncryptionParamSet(EncryptionParamSet);

            var asnEncoder = new Asn1BerEncodeBuffer();
            publicKeyParameters.Encode(asnEncoder);
            data = asnEncoder.MsgCopy;

            return data;
        }


        public void DecodePublicKey(byte[] data)
        {
            if (data == null)
            {
                throw new Exception("ArgumentNull - data");
            }

            var asnDecoder = new Asn1BerDecodeBuffer(data);
            var publicKey = new GostR34102001PublicKey();
            publicKey.Decode(asnDecoder);

            PublicKey = publicKey.Value;

        }

        internal static Gost2814789ParamSet CreateEncryptionParamSet(string value)
        {
            return (value != null) ? new Gost2814789ParamSet(Asn1ObjectIdentifier.FromOidString(value).Value) : null;
        }

        public static byte[] EncodePublicBlob(GostKeyExchangeParameters publicKeyParameters)
        {
            if (publicKeyParameters == null)
            {
                throw new Exception("ArgumentNull - publicKeyParameters");
            }

            var encodeKeyParameters = publicKeyParameters.EncodeParameters();
            var importedKeyBytes = new byte[(encodeKeyParameters.Length + 16) + publicKeyParameters.PublicKey.Length];
            importedKeyBytes[0] = 6;
            importedKeyBytes[1] = 32;
            Array.Copy(BitConverter.GetBytes(GostConstants.CALG_GR3410EL), 0, importedKeyBytes, 4, 4);
            Array.Copy(BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC), 0, importedKeyBytes, 8, 4);
            Array.Copy(BitConverter.GetBytes(GostConstants.GOST_3410EL_SIZE), 0, importedKeyBytes, 12, 4);
            Array.Copy(encodeKeyParameters, 0, importedKeyBytes, 16, encodeKeyParameters.Length);
            Array.Copy(publicKeyParameters.PublicKey, 0, importedKeyBytes, encodeKeyParameters.Length + 16, publicKeyParameters.PublicKey.Length);

            return importedKeyBytes;
        }
    }
}
