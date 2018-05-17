// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IO;

namespace System.Security.Cryptography
{
	interface IAsn1Type
	{
		void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength);
		int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging);
		void Encode(Asn1BerOutputStream outs, bool explicitTagging);
		void Print(TextWriter outs, string varName, int level);
	}
}
