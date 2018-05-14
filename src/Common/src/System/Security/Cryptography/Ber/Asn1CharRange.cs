namespace System.Security.Cryptography
{
	class Asn1CharRange : Asn1CharSet
	{
		private readonly int _lower;
		private readonly int _upper;

		public Asn1CharRange(int lower, int upper)
			: base((upper - lower) + 1)
		{
			_lower = lower;
			_upper = upper;
		}

		public override int MaxValue
		{
			get { return _upper; }
		}

		public override int GetCharAtIndex(int index)
		{
			index += _lower;

			if (index > _upper)
			{
				throw new Exception("Asn1 Cons Vio Exception");
			}

			return index;
		}

		public override int GetCharIndex(int charValue)
		{
			var num = charValue - _lower;

			if (num < 0)
			{
				throw new Exception("Asn1 Cons Vio Exception");
			}

			return num;
		}
	}
}
