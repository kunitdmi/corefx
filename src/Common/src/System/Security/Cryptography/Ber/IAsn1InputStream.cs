// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
	interface IAsn1InputStream
	{
		int Available();
		void Close();
		void Mark();
		bool MarkSupported();
		void Reset();
		long Skip(long nbytes);
	}
}
