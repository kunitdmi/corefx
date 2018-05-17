// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
	class Asn1DerEncodeBuffer : Asn1BerEncodeBuffer
	{
		public Asn1DerEncodeBuffer()
		{
			ByteIndex = SizeIncrement - 1;
		}

		public Asn1DerEncodeBuffer(int sizeIncrement)
			: base(sizeIncrement)
		{
			ByteIndex = SizeIncrement - 1;
		}
	}
}
