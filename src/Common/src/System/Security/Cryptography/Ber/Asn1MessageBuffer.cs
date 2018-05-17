// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IO;

namespace System.Security.Cryptography
{
	abstract class Asn1MessageBuffer
	{
		public abstract Stream GetInputStream();

		public static void HexDump(Stream ins)
		{
			//var outs = new StreamWriter(Console.OpenStandardOutput(), Console.Out.Encoding)
			//		   {
			//			   AutoFlush = true
			//		   };

			//HexDump(ins, outs);
		}

		public static void HexDump(Stream ins, StreamWriter outs)
		{
		}
	}
}
