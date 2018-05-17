// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IO;

namespace System.Security.Cryptography
{
	class Asn1TraceHandler : IAsn1NamedEventHandler
	{
		internal StreamWriter mPrintStream;

		public Asn1TraceHandler()
		{
			//mPrintStream = new StreamWriter(Console.OpenStandardOutput(), Console.Out.Encoding);
			mPrintStream.AutoFlush = true;
		}

		public Asn1TraceHandler(StreamWriter ps)
		{
			mPrintStream = ps;
		}

		public virtual void Characters(string svalue, short typeCode)
		{
			mPrintStream.WriteLine("data: " + svalue);
		}

		public virtual void EndElement(string name, int index)
		{
			mPrintStream.Write(name);
			if (index >= 0)
			{
				mPrintStream.Write("[" + index + "]");
			}
			mPrintStream.WriteLine(": end");
		}

		public virtual void StartElement(string name, int index)
		{
			mPrintStream.Write(name);
			if (index >= 0)
			{
				mPrintStream.Write("[" + index + "]");
			}
			mPrintStream.WriteLine(": start");
		}
	}
}
