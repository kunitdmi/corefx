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
