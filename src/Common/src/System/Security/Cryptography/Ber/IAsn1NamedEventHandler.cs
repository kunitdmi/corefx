// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
	interface IAsn1NamedEventHandler
	{
		void Characters(string svalue, short typeCode);
		void EndElement(string name, int index);
		void StartElement(string name, int index);
	}
}
