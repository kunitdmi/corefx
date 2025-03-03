﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    /// <summary>
    /// Переходник от структуры <see cref="Gost3410Parameters"/> к объекту.
    /// </summary>
    /// 
    internal class Gost3410CspObject
    {
        /// <summary>
        /// Конструктор объекта класса <see cref="Gost3410CspObject"/>
        /// </summary>
        public Gost3410CspObject()
        {
        }

        /// <summary>
        /// Конструктор объекта класса по параметрам ключа.
        /// </summary>
        public Gost3410CspObject(Gost3410Parameters parameters)
        {
            _publicKeyParamSet = parameters.PublicKeyParamSet;
            _digestParamSet = parameters.DigestParamSet;
            _encryptionParamSet = parameters.EncryptionParamSet;
            _publicKey = parameters.PublicKey;
            _privateKey = parameters.PrivateKey;
        }

        /// <summary>
        /// Получение/установка параметров ключа.
        /// </summary>
        public Gost3410Parameters Parameters
        {
            get
            {
                Gost3410Parameters ret;
                ret.PublicKeyParamSet = _publicKeyParamSet;
                ret.DigestParamSet = _digestParamSet;
                ret.EncryptionParamSet = _encryptionParamSet;
                ret.PublicKey = _publicKey;
                ret.PrivateKey = _privateKey;
                return ret;
            }
            set
            {
                _publicKeyParamSet = value.PublicKeyParamSet;
                _digestParamSet = value.DigestParamSet;
                _encryptionParamSet = value.EncryptionParamSet;
                _publicKey = value.PublicKey;
                _privateKey = value.PrivateKey;
            }
        }

        public void DecodeParameters(byte[] data)
        {
            if (data == null)
            {
                throw new Exception("ArgumentNull - data");
            }


            var asnDecoder = new Asn1BerDecodeBuffer(data);
            var publicKeyParameters = new GostR34102001PublicKeyParameters();
            publicKeyParameters.Decode(asnDecoder);

            _digestParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.DigestParamSet);
            _publicKeyParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.PublicKeyParamSet);
            _encryptionParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.EncryptionParamSet);
        }


        public byte[] EncodeParameters()
        {
            byte[] data;

            var publicKeyParameters = new GostR34102001PublicKeyParameters();

            publicKeyParameters.DigestParamSet = Asn1ObjectIdentifier.FromOidString(_digestParamSet);
            publicKeyParameters.PublicKeyParamSet = Asn1ObjectIdentifier.FromOidString(_publicKeyParamSet);
            publicKeyParameters.EncryptionParamSet = GostKeyExchangeParameters.CreateEncryptionParamSet(_encryptionParamSet);

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

            _publicKey = publicKey.Value;
        }

        /// <summary>
        /// OID параметров хеширования.
        /// </summary>
        internal string _digestParamSet;
        /// <summary>
        /// Необязательный OID параметров шифрования.
        /// </summary>
        internal string _encryptionParamSet;
        /// <summary>
        /// OID параметров подписи и DH.
        /// </summary>
        internal string _publicKeyParamSet;
        /// <summary>
        /// Открытый ключ.
        /// </summary>
        internal byte[] _publicKey;
        /// <summary>
        /// Секретный ключ.
        /// </summary>
        internal byte[] _privateKey;
    }
}
