// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IO;

namespace System.Security.Cryptography
{
	class Asn1DerDecodeBuffer : Asn1BerDecodeBuffer
	{
		public Asn1DerDecodeBuffer(byte[] msgdata)
			: base(msgdata)
		{
		}

		public Asn1DerDecodeBuffer(Stream inputStream)
			: base(inputStream)
		{
		}
	}
}
