namespace System.Security.Cryptography
{
	class Asn1DiscreteCharSet : Asn1CharSet
	{
		private readonly int[] _charSet;

		public Asn1DiscreteCharSet(string charSet)
			: base(charSet.Length)
		{
			_charSet = new int[charSet.Length];

			for (var i = 0; i < _charSet.Length; i++)
			{
				_charSet[i] = charSet[i];
			}
		}

		public Asn1DiscreteCharSet(int[] charSet)
			: base(charSet.Length)
		{
			_charSet = charSet;
		}

		public override int MaxValue
		{
			get { return _charSet[_charSet.Length - 1]; }
		}

		public override int GetCharAtIndex(int index)
		{
			if (index >= _charSet.Length)
			{
				throw new Exception("Asn1ConsVioException");
			}

			return _charSet[index];
		}

		public override int GetCharIndex(int charValue)
		{
			var index = 0;

			while ((index < _charSet.Length) && (_charSet[index] != charValue))
			{
				index++;
			}

			if (index >= _charSet.Length)
			{
				throw new Exception("Asn1ConsVioException");
			}

			return index;
		}
	}
}
