using System.IO;

namespace System.Security.Cryptography
{
	class Asn1CerInputStream : Asn1BerInputStream
	{
		public Asn1CerInputStream(Stream inputStream)
			: base(inputStream)
		{
		}
	}
}
