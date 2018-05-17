// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
	[Serializable]
	abstract class Asn18BitCharString : Asn1CharString
	{
		public const int BitsPerCharA = 8;
		public const int BitsPerCharU = 7;

		protected internal Asn18BitCharString(short typeCode)
			: base(typeCode)
		{
		}

		protected internal Asn18BitCharString(string data, short typeCode)
			: base(data, typeCode)
		{
		}
	}
}
