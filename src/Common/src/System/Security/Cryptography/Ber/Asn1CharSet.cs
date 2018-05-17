// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
	abstract class Asn1CharSet
	{
		private readonly int _aBitsPerChar;
		private readonly int _uBitsPerChar;

		protected internal Asn1CharSet(int nchars)
		{
			_uBitsPerChar = Asn1Integer.GetBitCount(nchars - 1);
			_aBitsPerChar = 1;

			while (_uBitsPerChar > _aBitsPerChar)
			{
				_aBitsPerChar = _aBitsPerChar << 1;
			}
		}

		public abstract int MaxValue { get; }

		public abstract int GetCharAtIndex(int index);

		public abstract int GetCharIndex(int charValue);

		public virtual int GetNumBitsPerChar(bool aligned)
		{
			if (!aligned)
			{
				return _uBitsPerChar;
			}

			return _aBitsPerChar;
		}
	}
}
