// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
	[Serializable]
	class Asn1ObjectDescriptor : Asn1VarWidthCharString
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, ObjectDescriptorTypeCode);

		public Asn1ObjectDescriptor()
			: base(ObjectDescriptorTypeCode)
		{
		}

		public Asn1ObjectDescriptor(string data)
			: base(data, ObjectDescriptorTypeCode)
		{
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			Decode(buffer, explicitTagging, implicitLength, Tag);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			return Encode(buffer, explicitTagging, Tag);
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			outs.EncodeCharString(Value, explicitTagging, Tag);
		}
	}
}
