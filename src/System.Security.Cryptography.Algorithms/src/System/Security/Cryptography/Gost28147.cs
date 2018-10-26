// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;
using System.ComponentModel;

namespace System.Security.Cryptography
{
    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class Gost28147 : SymmetricAlgorithm
    {
        protected Gost28147()
        {
            KeySizeValue = DefaultKeySize;
            BlockSizeValue = DefaultBlockSize;
            FeedbackSizeValue = DefaultFeedbackSize;
            LegalBlockSizesValue = DefaultLegalBlockSizes;
            LegalKeySizesValue = DefaultLegalKeySizes;
        }

        /// <summary>
        /// Размер ключа 256 бит.
        /// </summary>
        internal const int DefaultBlockSize = 64;
        /// <summary>
        /// Размер блока 64 бита.
        /// </summary>
        internal const int DefaultKeySize = 256;
        /// <summary>
        /// Размер зацепления 64 бита.
        /// </summary>
        internal const int DefaultFeedbackSize = 64;
        /// <summary>
        /// Размер синхропосылки 64 бита.
        /// </summary>
        internal const int DefaultIvSize = 64;

        public static readonly KeySizes[] DefaultLegalKeySizes = { new KeySizes(DefaultKeySize, DefaultKeySize, 0) };
        public static readonly KeySizes[] DefaultLegalBlockSizes = { new KeySizes(DefaultBlockSize, DefaultBlockSize, 0) };


        /// <summary>
        /// Создание объекта, реализуещего алгоритм шифрования ГОСТ-28147.
        /// </summary>
        /// 
        /// <returns>Криптографический объект, реализующий алгоритм ГОСТ 
        /// 28147.</returns>
        /// 
        /// <remarks><para>Создание объекта алгоритма шифрования ГОСТ 28147. 
        /// Объект может использоваться
        /// для симметричного зашифрования и расшифрования.</para></remarks>
        /// 
        /// <doc-sample path="Simple\Encrypt" name="EncryptDecryptRandomFile"
        /// region="EncryptDecryptRandomFile">Пример зашифрования и
        /// расшифрования файла при помощи 
        ///  порожденного класса <see cref="Gost28147CryptoServiceProvider"/>.
        ///  </doc-sample>
        public static new Gost28147 Create()
        {
            // Создание объекта идет по конфигурации для алгоритма заданного 
            // полным именем класса Gost28147.
            return Gost28147.Create(typeof(Gost28147).FullName);
        }

        /// <summary>
        /// Создание объекта, реализующего алгоритм шифрования ГОСТ-28147 
        /// с заданным именем реализации.
        /// </summary>
        /// 
        /// <param name="algName">Имя реализации алгоритма.</param>
        /// 
        /// <returns>Криптографический объект, реализующий алгоритм 
        /// ГОСТ 28147.</returns>
        /// 
        /// <doc-sample path="Simple\Encrypt" name="EncryptDecryptRandomFile"
        /// region="EncryptDecryptRandomFile">Пример зашифрования и
        /// расшифрования файла при помощи 
        ///  порожденного класса <see cref="Gost28147CryptoServiceProvider"/>.
        ///  </doc-sample>
        public static new Gost28147 Create(string algName)
        {
            // Создание объекта идет по конфигурации для алгоритма заданного 
            // параметром.
            return (Gost28147)CryptoConfig.CreateFromName(algName);
        }

        /// <summary>
        /// Хэширует секретный ключ.
        /// </summary>
        /// 
        /// <param name="hash">Класс, реализующий функцию хэширования.</param>
        /// 
        /// <returns>Хэш-значение секретного ключа</returns>
        public abstract byte[] ComputeHash(HashAlgorithm hash);

        /// <summary>
        /// Экспортирует (шифрует) секретный ключ.
        /// </summary>
        /// <param name="keyExchangeAlgorithm">Общий секретный ключ.</param>
        /// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
        public abstract byte[] EncodePrivateKey(Gost28147 keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod);

        /// <summary>
        /// Импортирует (дешифрует) секретный ключ.
        /// </summary>
        /// <param name="encodedKeyExchangeData">Зашифрованный общий секретный ключ.</param>
        /// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
        public abstract SymmetricAlgorithm DecodePrivateKey(byte[] encodedKeyExchangeData, GostKeyExchangeExportMethod keyExchangeExportMethod);
    }
}
