﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Numerics;
using System.Security.Cryptography.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed class Gost3410SignatureGenerator : X509SignatureGenerator
    {
        private readonly Gost3410 _key;

        internal Gost3410SignatureGenerator(Gost3410 key)
        {
            Debug.Assert(key != null);

            _key = key;
        }

        public override byte[] GetSignatureAlgorithmIdentifier(HashAlgorithmName hashAlgorithm)
        {
            if (hashAlgorithm != HashAlgorithmName.Gost3411)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(hashAlgorithm),
                    hashAlgorithm,
                    SR.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name));
            }

            using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.PushSequence();
                writer.WriteObjectIdentifier(Oids.Gost3410EL);
                writer.PopSequence();
                return writer.Encode();
            }
        }

        public override byte[] SignData(byte[] data, HashAlgorithmName hashAlgorithm)
        {
            return _key.SignData(data, hashAlgorithm);
        }

        protected override PublicKey BuildPublicKey()
        {
            Oid publicKeyOid = new Oid(Oids.Gost3410EL);

            var rawParams = ((Gost3410CryptoServiceProvider)_key).ExportCspBlob(false);

            byte[] param = new byte[rawParams.Length - 16 - GostConstants.GOST_3410EL_SIZE / 8];
            Array.Copy(rawParams, 16, param, 0, rawParams.Length - 16 - GostConstants.GOST_3410EL_SIZE / 8);
            var publicKey = new byte[GostConstants.GOST_3410EL_SIZE / 8];
            Array.Copy(
                rawParams,
                rawParams.Length - GostConstants.GOST_3410EL_SIZE / 8,
                publicKey,
                0,
                GostConstants.GOST_3410EL_SIZE / 8);

            using (AsnWriter writer = new AsnWriter(AsnEncodingRules.DER))
            {
                writer.WriteOctetString(publicKey);
                publicKey = writer.Encode();
            }

            return new PublicKey(
                publicKeyOid,
                new AsnEncodedData(publicKeyOid, param),
                new AsnEncodedData(publicKeyOid, publicKey));
        }
    }
}
