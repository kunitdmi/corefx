// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Text;

namespace System.Security.Cryptography
{
    [Serializable]
    class Asn1Utf8String : Asn1CharString
    {
        public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, Utf8StringTypeCode);

        public Asn1Utf8String()
            : base(Utf8StringTypeCode)
        {
        }

        public Asn1Utf8String(string data)
            : base(data, Utf8StringTypeCode)
        {
        }

        private byte[] AllocByteArray(int nbytes)
        {
            return new byte[nbytes];
        }

        public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
        {
            var num = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
            var str = new Asn1OctetString();
            str.Decode(buffer, false, num);

            Value = Encoding.UTF8.GetString(str.Value, 0, str.Value.Length);

            if (explicitTagging && (num == Asn1Status.IndefiniteLength))
            {
                MatchTag(buffer, Asn1Tag.Eoc);
            }
        }

        public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
        {
            var len = 0;
            var bytes = Encoding.UTF8.GetBytes(Value);
            len = bytes.Length;
            buffer.Copy(bytes);

            if (explicitTagging)
            {
                len += buffer.EncodeTagAndLength(Tag, len);
            }

            return len;
        }

        public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
        {
            var bytes = Encoding.UTF8.GetBytes(Value);

            if (explicitTagging)
            {
                outs.EncodeTag(Tag);
            }

            outs.EncodeLength(bytes.Length);
            outs.Write(bytes);
        }

        private byte[] ReAllocByteArray(byte[] ba1, int nbytes)
        {
            var destinationArray = new byte[nbytes];

            if (ba1 != null)
            {
                Array.Copy(ba1, 0, destinationArray, 0, ba1.Length);
            }

            return destinationArray;
        }
    }
}
