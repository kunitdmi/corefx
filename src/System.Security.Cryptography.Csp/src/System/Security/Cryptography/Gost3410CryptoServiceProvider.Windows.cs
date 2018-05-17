// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using Internal.NativeCrypto;
using static Internal.NativeCrypto.CapiHelper;
namespace System.Security.Cryptography
{
    /// <summary>
    /// Реализация алгоритма подписи по ГОСТ Р 34.10 через 
    /// Cryptographic Service Provider (CSP). 
    /// Этот класс не наследуется.
    /// </summary>
    /// 
    /// <remarks><para> Класс <c>Gost3410CryptoServiceProvider</c> 
    /// используется для создания цифровой подписи, формирования общего 
    /// секрета  (Shared Secret). Алгоритм использует секретный ключ длиной 
    /// 256, и открытый ключ длиной 512 бит.</para>
    /// </remarks>
    /// 
    /// <basedon cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
    /// <basedon cref="System.Security.Cryptography.DSACryptoServiceProvider"/>
    /// 
    /// <doc-sample path="Simple\Sign" name="Gost3410CSPSample">Пример работы с 
    /// Gost3410CryptoServiceProvider.
    ///  </doc-sample>
    ///  
    /// <intdoc><para>При реализации убрана длина ключа, она всегда const</para>
    /// </intdoc>
    /// 
    /// <cspversions />
    public sealed class Gost3410CryptoServiceProvider :
        Gost3410, ICspAsymmetricAlgorithm
    {
        private static volatile CspProviderFlags s_useMachineKeyStore = 0;
        private CspParameters _parameters;
        private bool _randomKeyContainer;
        private SafeKeyHandle _safeKeyHandle;
        private SafeProvHandle _safeProvHandle;

        /// <summary>
        /// Конструктор, создающий объект класса 
        /// <see cref="Gost3410CryptoServiceProvider"/>.
        /// </summary>
        /// 
        /// <remarks><para>Создается контейнер с типом 75 на провайдере
        /// по умолчанию, со случайным именем контейнера. Ключи 
        /// будут храниться в store пользователя или машины в 
        /// зависимости от установленного свойства 
        /// <see cref="Gost3410CryptoServiceProvider.UseMachineKeyStore"/>
        /// в момент создания объекта.</para>
        /// <para>Создание ключей будет отложено до момента, когда
        /// этот ключ реально потребуется.</para>
        /// </remarks>
        /// 
        /// <doc-sample path="Simple\Sign" name="Gost3410CSPSample">Пример создания 
        /// и работы с Gost3410CryptoServiceProvider.
        ///  </doc-sample>
        [SecuritySafeCritical]
        public Gost3410CryptoServiceProvider()
            : this(new CspParameters(
            GostConstants.PROV_GOST_2001_DH, null, null,
            Gost3410CryptoServiceProvider.s_useMachineKeyStore))
        {
        }

        /// <summary>
        /// Конструктор алгоритма подписи по ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="parameters">Параметры алгоритма.</param>
        /// 
        /// <remarks><para>При создании контейнера без заданного имени
        /// контейнера и без указания флага использования контейнера по 
        /// умолчанию будет создано случайное имя, а создание ключей
        /// будет отложено, до его первого обращения.
        /// </para>
        /// 
        /// <para>При инициализации объекта через данный конструктор 
        /// будут использованы именно эти параметры, в независимости от
        /// флага <see cref="UseMachineKeyStore"/>. По умолчанию значение
        /// флага из 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// устанавливется в использование ключей из хранилищи пользователя.
        /// Для использования ключей из хранилища компьютера 
        /// необходимо установить флаг <see cref="CspParameters.Flags"/>:
        /// <see cref="CspProviderFlags.UseMachineKeyStore"/>.
        /// </para>
        /// </remarks>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        [SecuritySafeCritical]
        public Gost3410CryptoServiceProvider(CspParameters parameters)
        {
            _parameters = CapiHelper.SaveCspParameters(CapiHelper.CspAlgorithmType.PROV_GOST_2001_DH,
                parameters,
                s_useMachineKeyStore,
                out _randomKeyContainer);
            SafeKeyHandle.PublicOnly = false;
            SafeKeyHandle.KeySpec = _parameters.KeyNumber;
            SafeProvHandle.PersistKeyInCsp = false;
            LegalKeySizesValue = new KeySizes[] { new KeySizes(
                GostConstants.EL_SIZE, GostConstants.EL_SIZE,  0) };
            if (!_randomKeyContainer)
                GetKeyPair();
        }


        /// <summary>
        /// Вычисляет значение хэш для байтового массива и подписывает его.
        /// </summary>
        /// 
        /// <param name="buffer">Данные, для которых вычисляется 
        /// подпись.</param>
        /// <param name="hashAlg">Объект, реализующий алгоритм 
        /// хэширования.</param>
        /// 
        /// <returns>Подпись данных, выполненная по алгоритму 
        /// ГОСТ Р 34.10.</returns>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignData1">Пример подписи и 
        ///  проверки подписи данных.</doc-sample>
        /// <doc-sample path="Simple\Sign" name="SignFile1">Пример подписи и 
        ///  проверки подписи для файла.</doc-sample>
        ///  
        ///  <exception cref="CryptographicException"><c>hashAlg</c> не является
        ///  алгоритмом хеширования по ГОСТ Р 34.11.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Sign">Для подписи на не случайном контейнере.
        /// </containerperm>
        [SecuritySafeCritical]
        public byte[] SignData(byte[] buffer, object hashAlg)
        {
            // SignHash допускает только хеш по ГОСТ Р 34.11, в отличии
            // от RSA. Поэтому проверяем корректность типа хеша
            // и на подпись передаем правильный.
            string oid = CapiHelper.ObjToOidValue(hashAlg);
            if (!oid.Equals(GostConstants.OID_CP_GOST_R3411))
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, oid.ToString());


            int calgHash = CapiHelper.ObjToHashAlgId(hashAlg);
            HashAlgorithm hash = CapiHelper.ObjToHashAlgorithm(hashAlg);
            byte[] hashVal = hash.ComputeHash(buffer);
            return SignHash(hashVal);
        }

        /// <summary>
        /// Вычисление значения хэш для указанного интервала из байтового 
        /// массива и его подпись.
        /// </summary>
        /// 
        /// <param name="buffer">Данные, для которых вычисляется 
        /// подпись.</param>
        /// <param name="offset">Смещение от начала массива. </param>
        /// <param name="count">Число байтов для подсчета хэша.</param>
        /// <param name="hashAlg">Объект, реализующий алгоритм 
        /// хэширования.</param>
        /// 
        /// <returns>Подпись данных, выполненная по алгоритму 
        /// ГОСТ Р 34.10</returns>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignData3">Пример подписи и 
        ///  проверки подписи данных.</doc-sample>
        ///  
        ///  <exception cref="CryptographicException"><c>halg</c> не является
        ///  алгоритмом хеширования по ГОСТ Р 34.11.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Sign">Для подписи на не случайном контейнере.
        /// </containerperm>
        [SecuritySafeCritical]
        public byte[] SignData(byte[] buffer, int offset, int count,
            object hashAlg)
        {
            // SignHash допускает только хеш по ГОСТ Р 34.11, в отличии
            // от RSA. Поэтому проверяем корректность типа хеша
            // и на подпись передаем правильный.
            // SignHash допускает только хеш по ГОСТ Р 34.11, в отличии
            // от RSA. Поэтому проверяем корректность типа хеша
            // и на подпись передаем правильный.
            string oid = CapiHelper.ObjToOidValue(hashAlg);
            if (!oid.Equals(GostConstants.OID_CP_GOST_R3411))
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, oid.ToString());

            HashAlgorithm algorithm = CapiHelper.ObjToHashAlgorithm(hashAlg);
            byte[] bufferTemp = algorithm.ComputeHash(buffer, offset, count);
            return SignHash(bufferTemp);
        }

        /// <summary>
        /// Вычисляет значение хэш для данных из потока и подписывает его.
        /// </summary>
        /// <param name="inputStream">Данные, для которых вычисляется подпись.</param>
        /// <param name="hashAlg">Объект, реализующий алгоритм хэширования.</param>
        /// <returns>Подпись данных, выполненная по алгоритму ГОСТ-34.10.</returns>
        /// <doc-sample path="Simple\Sign" name="SignData2">Пример подписи и 
        ///  проверки подписи данных.</doc-sample>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Sign">Для подписи на не случайном контейнере.
        /// </containerperm>
        [SecuritySafeCritical]
        public byte[] SignData(Stream inputStream, object hashAlg)
        {
            // SignHash допускает только хеш по ГОСТ Р 34.11, в отличии
            // от RSA. Поэтому проверяем корректность типа хеша
            // и на подпись передаем правильный.
            // SignHash допускает только хеш по ГОСТ Р 34.11, в отличии
            // от RSA. Поэтому проверяем корректность типа хеша
            // и на подпись передаем правильный.
            string oid = CapiHelper.ObjToOidValue(hashAlg);
            if (!oid.Equals(GostConstants.OID_CP_GOST_R3411))
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, oid.ToString());

            HashAlgorithm algorithm = CapiHelper.ObjToHashAlgorithm(hashAlg);
            byte[] bufferTemp = algorithm.ComputeHash(inputStream);
            return SignHash(bufferTemp);
        }

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            // we're sealed and the base should have checked this already
            Debug.Assert(data != null);
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));

            using (HashAlgorithm hash = Gost3411.Create())//GetHashAlgorithm(hashAlgorithm))
            {
                return hash.ComputeHash(data);
            }
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            // we're sealed and the base should have checked this already
            Debug.Assert(data != null);
            Debug.Assert(count >= 0 && count <= data.Length);
            Debug.Assert(offset >= 0 && offset <= data.Length - count);
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));

            using (HashAlgorithm hash = Gost3411.Create())//GetHashAlgorithm(hashAlgorithm))
            {
                return hash.ComputeHash(data, offset, count);
            }
        }

        /// <summary>
        /// Вычисляет подпись для заданного значения хэш.
        /// </summary>
        /// 
        /// <param name="hash">Подписываемое значение хэш.</param>
        /// 
        /// <returns>Подпись хэша, выполненная по алгоритму 
        /// ГОСТ Р 34.10.</returns>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignHash">Пример подписи и 
        ///  проверки подписи хэш.</doc-sample>
        ///  
        /// <intdoc><para>Стандарт допускает только алгоритм хеширования 
        /// ГОСТ Р 34.11. 
        /// </para></intdoc>
        /// 
        /// <remarks><para>Функция тождественна 
        /// <see cref="CreateSignature"/>.</para></remarks>
        /// 
        /// <argnull name="hash" />
        /// <exception cref="CryptographicException">Объект не содержит 
        /// секретного ключа или хеш имееет неправильный размер.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Sign">Для подписи на не случайном контейнере.
        /// </containerperm>
        public override byte[] SignHash(
    byte[] hash,
    HashAlgorithmName hashAlgorithm
    )
        {
            if (hash == null)
                throw new ArgumentNullException(nameof(hash));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw new CryptographicException(SR.Cryptography_HashAlgorithmNameNullOrEmpty);
            if (hashAlgorithm != HashAlgorithmName.Gost3411)
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm);

            return SignHash(hash);
        }

        /// <summary>
        /// Вычисляет подпись для заданного значения хэш.
        /// </summary>
        /// 
        /// <param name="hash">Подписываемое значение хэш.</param>
        /// 
        /// <returns>Подпись хэша, выполненная по алгоритму 
        /// ГОСТ Р 34.10.</returns>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignHash">Пример подписи и 
        ///  проверки подписи хэш.</doc-sample>
        ///  
        /// <intdoc><para>Стандарт допускает только алгоритм хеширования 
        /// ГОСТ Р 34.11. Не таскаем лишний параметр алгоритм хеширования.
        /// </para></intdoc>
        /// 
        /// <remarks><para>Функция тождественна 
        /// <see cref="CreateSignature"/>.</para></remarks>
        /// 
        /// <argnull name="hash" />
        /// <exception cref="CryptographicException">Объект не содержит 
        /// секретного ключа или хеш имееет неправильный размер.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Sign">Для подписи на не случайном контейнере.
        /// </containerperm>
        [SecuritySafeCritical]
        private byte[] SignHash(byte[] hash)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (PublicOnly)
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);

            if (hash.Length != (GostConstants.GOST3411_SIZE / 8))
            {
                throw new CryptographicException(SR.Cryptography_InvalidHashSize,
                    string.Format("{0} - {1}", "GOST3411", GostConstants.GOST3411_SIZE / 8));
            }
            GetKeyPair();
            return CapiHelper.SignValue(
                    SafeProvHandle,
                    SafeKeyHandle,
                    _parameters.KeyNumber, //0?
                    CapiHelper.CALG_RSA_SIGN, //переворачиваем подпись
                    GostConstants.CALG_GR3411,
                    hash);

        }

        /// <summary>
        /// Проверка подписи для указанных данных.
        /// </summary>
        /// 
        /// <param name="buffer">Данные, для которых проверяется 
        /// подпись.</param>
        /// <param name="hashAlg">Объект, реализующий алгоритм вычисления 
        /// хэш по ГОСТ Р 34.11.</param>
        /// <param name="signature">Подпись, которую необходимо 
        /// проверить.</param>
        /// 
        /// <returns><see langword="true"/>, если подпись подлинна, 
        /// <see langword="false"/> - иначе.</returns>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignData1">Пример подписи и 
        ///  проверки подписи данных.</doc-sample>
        ///  
        /// <exception cref="CryptographicException"><c>halg</c> не является
        ///  алгоритмом хеширования по ГОСТ Р 34.11.</exception>
        ///  
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        [SecuritySafeCritical]
        public bool VerifyData(byte[] buffer, object hashAlg, byte[] signature)
        {
            // VerifyHash допускает только хеш по ГОСТ Р 34.11, в отличии
            // от RSA. Поэтому проверяем корректность типа хеша
            // и на подпись передаем правильный.
            string oid = CapiHelper.ObjToOidValue(hashAlg);
            if (!oid.Equals(GostConstants.OID_CP_GOST_R3411))
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, oid.ToString());

            HashAlgorithm hashAlgorithm = CapiHelper.ObjToHashAlgorithm(hashAlg);
            byte[] bufferTemp = hashAlgorithm.ComputeHash(buffer);
            return VerifyHash(bufferTemp, signature);
        }

        /// <summary>
        /// Проверка подписи для указанных данных.
        /// </summary>
        /// 
        /// <param name="inputStream">Данные, для которых проверяется 
        /// подпись.</param>
        /// <param name="hashAlg">Объект, реализующий алгоритм вычисления 
        /// хэш по ГОСТ Р 34.11.</param>
        /// <param name="signature">Подпись, подлинность которой необходимо
        /// проверить.</param>
        /// 
        /// <returns><see langword="true"/>, если продпись подлинна, 
        /// <see langword="false"/> - иначе.</returns>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignData2">Пример подписи и 
        ///  проверки подписи данных.</doc-sample>
        ///  
        /// <exception cref="CryptographicException"><c>halg</c> не является
        /// алгоритмом хеширования по ГОСТ Р 34.11.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        [SecuritySafeCritical]
        public bool VerifyData(Stream inputStream, object hashAlg,
            byte[] signature)
        {
            // VerifyHash допускает только хеш по ГОСТ Р 34.11, в отличии
            // от RSA. Поэтому проверяем корректность типа хеша
            // и на подпись передаем правильный.
            string oid = CapiHelper.ObjToOidValue(hashAlg);
            if (!oid.Equals(GostConstants.OID_CP_GOST_R3411))
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, oid.ToString());

            HashAlgorithm hashAlgorithm = CapiHelper.ObjToHashAlgorithm(hashAlg);
            byte[] buffer1 = hashAlgorithm.ComputeHash(inputStream);
            return VerifyHash(buffer1, signature);
        }

        /// <summary>
        /// Проверяет подлинность подписи для указанного значения хэш.
        /// </summary>
        /// 
        /// <param name="hash">Хэш, для которого проверяется 
        /// подпись.</param>
        /// <param name="signature">Подпись, подлинность которой 
        /// необходимо проверить.</param>
        /// 
        /// <returns><see langword="true"/>, если продпись подлинна, 
        /// <see langword="false"/> - иначе.</returns>
        /// 
        /// <remarks>Алгоритм вычисления хэш для ГОСТ Р 34.10 
        /// всегда ГОСТ Р 34.11.</remarks>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignHash">Пример подписи и 
        ///  проверки подписи хэш.</doc-sample>
        ///  
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        [SecuritySafeCritical]
        public bool VerifyHash(byte[] hash, byte[] signature)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (signature == null)
                throw new ArgumentNullException("signature");
            if (hash.Length != (GostConstants.GOST3411_SIZE / 8))
            {
                throw new CryptographicException(SR.Cryptography_InvalidHashSize,
                    string.Format("{0} - {1}", "GOST3411", GostConstants.GOST3411_SIZE / 8));
            }

            GetKeyPair();
            bool ret = CapiHelper.VerifySign(SafeProvHandle, SafeKeyHandle,
                CapiHelper.CALG_RSA_SIGN, GostConstants.CALG_GR3411, hash, signature); //????
            return ret;
        }

        // <summary>
        /// Для переопределения абстрактных методов класса Gost3410.
        /// Потом переписать !!!!
        /// </summary>
        /// 
        /// <param name="hash">Хэш, для которого проверяется 
        /// подпись.</param>
        /// <param name="signature">Подпись, подлинность которой 
        /// необходимо проверить.</param>
        /// 
        /// <returns><see langword="true"/>, если продпись подлинна, 
        /// <see langword="false"/> - иначе.</returns>
        /// 
        /// <remarks>Алгоритм вычисления хэш для ГОСТ Р 34.10 
        /// всегда ГОСТ Р 34.11.</remarks>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignHash">Пример подписи и 
        ///  проверки подписи хэш.</doc-sample>
        ///  
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        [SecuritySafeCritical]
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgName)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (signature == null)
                throw new ArgumentNullException("signature");
            if (hash.Length != (GostConstants.GOST3411_SIZE / 8))
            {
                throw new CryptographicException(SR.Cryptography_InvalidHashSize,
                    string.Format("{0} - {1}", "GOST3411", GostConstants.GOST3411_SIZE / 8));
            }


            bool ret = VerifyHash(hash, signature);
            return ret;
        }
        /// <summary>
        /// Экспортирует параметры алгоритма в BLOB.
        /// </summary>
        /// 
        /// <param name="includePrivateParameters">Для экспорта секретного
        /// ключа.</param>
        /// 
        /// <returns>BLOB со структурой описанной для CSP.</returns>
        /// 
        /// <remarks><para>Экспорт секретного ключа не поддерживается.
        /// </para></remarks>
        /// 
        /// <exception cref="CryptographicException">При экспорте секретного
        /// ключа.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        /// 
        /// <intdoc>Экспорт секретного ключа запрещен, поэтому
        /// не требуются права на экспорт. При экспорте открытого
        /// ключа может потребоваться открытие (создание) контейнера,
        /// поэтому требование прав на открытие.</intdoc>
        [SecuritySafeCritical]
        public byte[] ExportCspBlob(bool includePrivateParameters)
        {
            // Права на экспорт / импорт проверять бесполезно
            // CSP все равно не поддерживает. Бесполезно да же эмулировать:
            // сделать с этим BLOB потом ничего нельзя.
            if (includePrivateParameters)
                throw new CryptographicException(SR.Argument_InvalidValue, "includePrivateParameters equal true ");
            return CapiHelper.ExportKeyBlob(includePrivateParameters, SafeKeyHandle);
        }

        /// <summary>
        /// This method helps Acquire the default CSP and avoids the need for static SafeProvHandle
        /// in CapiHelper class
        /// </summary>
        private SafeProvHandle AcquireSafeProviderHandle()
        {
            SafeProvHandle safeProvHandleTemp;
            CapiHelper.AcquireCsp(new CspParameters(GostConstants.PROV_GOST_2001_DH), out safeProvHandleTemp);
            return safeProvHandleTemp;
        }

        /// <summary>
        /// Импорт параметров алгоритма ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="rawData">Байтовый массив, содержащий ключ и параметры
        /// алгоритма ГОСТ Р 34.10.</param>.
        /// 
        /// <remarks><para>Импорт секретного ключа не поддерживается.
        /// </para></remarks>
        /// 
        /// <exception cref="CryptographicException">При экспорте секретного
        /// ключа.</exception>
        [SecuritySafeCritical]
        public void ImportCspBlob(byte[] rawData)
        {
            SafeKeyHandle safeKeyHandle;

            // Права на экспорт / импорт проверять бесполезно
            // CSP все равно не поддерживает. Бесполезно да же эмулировать:
            // сделать с этим BLOB потом ничего нельзя.

            // Это открытый ключ, поэтому можно его export
            // в verify context.
            // Нет обращения к секретному ключу, поэтому
            // не создаем контейнер без надобности.
            if (IsPublic(rawData))
            {
                SafeProvHandle safeProvHandleTemp = AcquireSafeProviderHandle();

                CapiHelper.ImportKeyBlob(safeProvHandleTemp, CspProviderFlags.NoFlags,
                   false, //?
                   rawData,
                   out safeKeyHandle);

                // The property set will take care of releasing any already-existing resources.
                SafeProvHandle = safeProvHandleTemp;
            }
            else
            {
                throw new CryptographicException(SR.CspParameter_invalid, "Cryptography_UserExportBulkBlob");
            }

            // The property set will take care of releasing any already-existing resources.
            SafeKeyHandle = safeKeyHandle;

            if (_parameters != null)
            {
                _parameters.KeyNumber = SafeKeyHandle.KeySpec;
            }

            // Эмулируем MS HANDLE
            SafeKeyHandle.PublicOnly = true;
        }

        /// <summary>
        /// Импорт параметров алгоритма ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="keyBlob">Байтовый массив, содержащий ключ
        /// алгоритма ГОСТ Р 34.10 без параметров. </param>.
        /// 
        /// <param name="paramBlob">Байтовый массив, параметры ключа
        /// алгоритма ГОСТ Р 34.10 без параметров. </param>.
        /// 
        /// <remarks><para>Импорт секретного ключа не поддерживается.
        /// </para></remarks>
        /// 
        /// <exception cref="CryptographicException">При экспорте секретного
        /// ключа.</exception>
        [SecuritySafeCritical]
        public void ImportCspBlob(byte[] keyBlob, byte[] paramBlob)
        {
            SafeKeyHandle safeKeyHandle;
            var rawData = CapiHelper.EncodePublicBlob(keyBlob, paramBlob, CspAlgorithmType.PROV_GOST_2001_DH);

            // Права на экспорт / импорт проверять бесполезно
            // CSP все равно не поддерживает. Бесполезно да же эмулировать:
            // сделать с этим BLOB потом ничего нельзя.

            // Это открытый ключ, поэтому можно его export
            // в verify context.
            // Нет обращения к секретному ключу, поэтому
            // не создаем контейнер без надобности.
            if (IsPublic(rawData))
            {
                SafeProvHandle safeProvHandleTemp = AcquireSafeProviderHandle();

                CapiHelper.ImportKeyBlob(safeProvHandleTemp, CspProviderFlags.NoFlags,
                   false, //?
                   rawData,
                   out safeKeyHandle);

                // The property set will take care of releasing any already-existing resources.
                SafeProvHandle = safeProvHandleTemp;
            }
            else
            {
                throw new CryptographicException(SR.CspParameter_invalid, "Cryptography_UserExportBulkBlob");
            }

            // The property set will take care of releasing any already-existing resources.
            SafeKeyHandle = safeKeyHandle;

            if (_parameters != null)
            {
                _parameters.KeyNumber = SafeKeyHandle.KeySpec;
            }

            // Эмулируем MS HANDLE
            SafeKeyHandle.PublicOnly = true;
        }

        /// <summary>
        /// Экспорт параметров <see cref="Gost3410Parameters"/> 
        /// алгоритма ГОСТ Р 34.10 в CSP.
        /// </summary>
        /// 
        /// <param name="includePrivateParameters"><see langword="true"/>, 
        /// чтобы включить секретный ключ, <see langword="false"/> - для 
        /// экспорта только открытого ключа и его параметров.</param>
        /// 
        /// <returns>Параметры в виде структуры 
        /// <see cref="Gost3410Parameters"/></returns>
        /// 
        /// <remarks>
        /// <if notdefined="userexp"><para>По соображениям безопасности 
        /// в данной сборке при экспорте 
        /// секретного ключа всегда возбуждает исключение 
        /// <see cref="CryptographicException"/>.</para></if>
        /// </remarks>
        /// 
        /// <doc-sample path="Simple\DocBlock" name="ExportParameters" 
        /// region="ExportParameters" />
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        /// <containerperm flag="Export">Для экспорта секретного ключа.
        /// </containerperm>
        [SecuritySafeCritical]
        public override Gost3410Parameters ExportParameters(bool includePrivateParameters)
        {
            GetKeyPair();
            Gost3410CspObject obj1 = new Gost3410CspObject();
            if (includePrivateParameters)
            {
                throw new CryptographicException(SR.Argument_InvalidValue, "includePrivateParameters equal true ");
            }

            byte[] data = ExportCspBlob(false);
            DecodePublicBlob(obj1, data, CspAlgorithmType.PROV_GOST_2001_DH);

            return obj1.Parameters;

            //byte[] cspBlob = ExportCspBlob(includePrivateParameters);
            //return cspBlob.ToGost3410Parameters(includePrivateParameters);
        }

        /// <summary>
        /// Импорт параметров <see cref="Gost3410Parameters"/> 
        /// алгоритма ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="parameters">Параметры алгоритма 
        /// ГОСТ Р 10.34.</param>
        /// 
        /// <doc-sample path="Simple\DocBlock" name="ImportParameters" 
        /// region="ImportParameters" />
        /// 
        /// <exception cref="CryptographicException">При импорте секретного
        /// ключа.</exception>
        /// 
        /// <remarks>
        /// <if notdefined="userimp"><para>В данной сборке при импорте 
        /// секретного ключа всегда возбуждает исключение 
        /// <see cref="CryptographicException"/>.</para></if>
        /// </remarks>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Import">Для импорта секретного ключа.
        /// </containerperm>
        [SecuritySafeCritical]
        public override void ImportParameters(Gost3410Parameters parameters)
        {
            Gost3410CspObject pubKey = new Gost3410CspObject(parameters);
            if ((SafeKeyHandle != null) && !SafeKeyHandle.IsClosed)
            {
                SafeKeyHandle.Dispose();
            }

            SafeKeyHandle = SafeKeyHandle.InvalidHandle;
            if (Gost3410CryptoServiceProvider.IsPublic(parameters))
            {
                SafeKeyHandle safeKeyHandle;
                // Это открытый ключ, поэтому можно его export
                // в verify context.
                // Нет обращения к секретному ключу, поэтому
                // не создаем контейнер без надобности.
                var safeProvHandleTemp = AcquireSafeProviderHandle();
                if (pubKey == null)
                    throw new ArgumentNullException("pubKey");

                byte[] keyBlob = EncodePublicBlob(pubKey, CspAlgorithmType.PROV_GOST_2001_DH);
                CapiHelper.ImportKeyBlob(safeProvHandleTemp, CspProviderFlags.NoFlags, false, keyBlob, out safeKeyHandle);

                SafeKeyHandle = safeKeyHandle;
                SafeKeyHandle.PublicOnly = true;
                return;
            }

            throw new CryptographicException(SR.CspParameter_invalid, "Cryptography_UserExportBulkBlob");
        }

        /// <summary>
        /// Освобождает неуправляемые объектом класса 
        /// <see cref="Gost3410CryptoServiceProvider"/> ресурсы и, по выбору, 
        /// управляемые. 
        /// </summary>
        /// <param name="disposing"><see langword="true"/>, чтобы освободить 
        /// и управляемые, и неупавляемые ресурсы; <see langword="false"/>, 
        /// чтобы освободить только неуправляемые.</param>
        [SecuritySafeCritical]
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (_safeKeyHandle != null && !_safeKeyHandle.IsClosed)
            {
                _safeKeyHandle.Dispose();
            }
            if (_safeProvHandle != null && !_safeProvHandle.IsClosed)
            {
                _safeProvHandle.Dispose();
            }
        }

        /// <summary>
        /// Получает информацию о CSP <see cref="CspKeyContainerInfo"/>, 
        /// в котором хранится ключевая пара.
        /// </summary>
        /// 
        /// <doc-sample path="Simple\KeyManage" name="PersistKeyInCspSample">Пример вызова свойства
        /// CspKeyContainerInfo.</doc-sample>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public CspKeyContainerInfo CspKeyContainerInfo
        {
            [SecuritySafeCritical]
            get
            {
                if (_parameters == null)
                {
                    return null;
                }
                GetKeyPair();
                return new CspKeyContainerInfo(_parameters,
                    _randomKeyContainer);
            }
        }

        /// <summary>
        /// Возвращает длину ключа, используемого в алгоритме, в битах.
        /// </summary>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public override int KeySize
        {
            [SecuritySafeCritical]
            get
            {
                // Проверяем наличие ключа.
                GetKeyPair();
                // В подлиннике обращение к CSP, нам не требуется
                return GostConstants.EL_SIZE;
            }
        }

        /// <summary>
        /// Возвращает или устанавливает флаг, указывающий, должен ли ключ 
        /// храниться в CSP.
        /// </summary>
        /// 
        /// <value>
        /// <see langword="true"/>, если ключ должен храниться в CSP, 
        /// <see langword="false"/> - иначе.
        /// </value>
        /// 
        /// <remarks><para>
        /// Используйте это свойство, если хотите хранить ключ в контейнере
        /// или хотите удалить существующий ключ.</para>
        /// <para>При заданном имени контейнера в <see cref="CspParameters"/>
        /// cвойство <c>PersistKeyInCsp</c> устанавливается в <see langword="true"/>
        /// автоматически и имя испольузуется при инициализации 
        /// <see cref="Gost3410CryptoServiceProvider"/>.
        /// Задать имя CSP можно используя свойство 
        /// <see cref="System.Security.Cryptography.CspKeyContainerInfo.KeyContainerName"/></para>
        /// <para>Если свойство <c>PersistKeyInCsp</c> установлено в 
        /// <see langword="true"/> без инициализации 
        /// <see cref="Gost3410CryptoServiceProvider"/> экземпляром класса
        /// <see cref="CspParameters"/> будет создано случайный
        /// контейнера, с приставкой "CLR" в имени.</para>
        /// </remarks>
        /// 
        /// <doc-sample path="Simple\KeyManage" name="PersistKeyInCspSample">Пример работы
        /// с контейнером закрытого ключа.</doc-sample>
        /// 
        /// <containerperm flag="Open">Для открытия существующего контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера.</containerperm>
        /// <containerperm flag="Delete">Для удаления контейнера.</containerperm>
        /// 
        /// <cspversions><exclude version="30"/><exclude version="20"/><since version="36" build="5276" /></cspversions>
        public bool PersistKeyInCsp
        {
            get
            {
                return CapiHelper.GetPersistKeyInCsp(SafeProvHandle);
            }
            set
            {
                bool oldPersistKeyInCsp = PersistKeyInCsp;
                if (value == oldPersistKeyInCsp)
                {
                    return; // Do nothing
                }
                CapiHelper.SetPersistKeyInCsp(SafeProvHandle, value);
            }
        }

        private SafeProvHandle SafeProvHandle
        {
            get
            {
                if (_safeProvHandle == null)
                {
                    lock (_parameters)
                    {
                        if (_safeProvHandle == null)
                        {
                            SafeProvHandle hProv = CapiHelper.CreateProvHandle(_parameters, _randomKeyContainer);

                            Debug.Assert(hProv != null);
                            Debug.Assert(!hProv.IsInvalid);
                            Debug.Assert(!hProv.IsClosed);

                            _safeProvHandle = hProv;
                        }
                    }

                    return _safeProvHandle;
                }

                return _safeProvHandle;
            }
            set
            {
                lock (_parameters)
                {
                    SafeProvHandle current = _safeProvHandle;

                    if (ReferenceEquals(value, current))
                    {
                        return;
                    }

                    if (current != null)
                    {
                        SafeKeyHandle keyHandle = _safeKeyHandle;
                        _safeKeyHandle = null;
                        keyHandle?.Dispose();
                        current.Dispose();
                    }

                    _safeProvHandle = value;
                }
            }
        }

        private SafeKeyHandle SafeKeyHandle
        {
            get
            {
                if (_safeKeyHandle == null)
                {
                    lock (_parameters)
                    {
                        if (_safeKeyHandle == null)
                        {
                            SafeKeyHandle hKey = CapiHelper.GetKeyPairHelper(
                                CapiHelper.CspAlgorithmType.PROV_GOST_2001_DH,
                                _parameters,
                                GostConstants.EL_SIZE,
                                SafeProvHandle);

                            Debug.Assert(hKey != null);
                            Debug.Assert(!hKey.IsInvalid);
                            Debug.Assert(!hKey.IsClosed);

                            _safeKeyHandle = hKey;
                        }
                    }
                }

                return _safeKeyHandle;
            }

            set
            {
                lock (_parameters)
                {
                    SafeKeyHandle current = _safeKeyHandle;

                    if (ReferenceEquals(value, current))
                    {
                        return;
                    }

                    _safeKeyHandle = value;
                    current?.Dispose();
                }
            }
        }

        /// <summary>
        /// Получает значение, указывающее, не содержит ли объект 
        /// <see cref="Gost3410CryptoServiceProvider"/>
        /// только открытый ключ.
        /// </summary>
        /// 
        /// <value>
        /// <see langword="true"/>, если 
        /// <see cref="Gost3410CryptoServiceProvider"/> содержит только 
        /// открытый ключ, <see langword="false"/> - иначе.
        /// </value>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public bool PublicOnly
        {
            [SecuritySafeCritical]
            get
            {
                // Я так и не смог разобраться как MS хранят (или 
                // все-таки получают) этот флаг, но все равно у нас
                // нет официального способа его получения. Поэтому 
                // просто его храним.
                GetKeyPair();
                return SafeKeyHandle.PublicOnly;
            }
        }

        /// <summary> 
        /// Возвращает или устанавливает флаг того, что ключ должен храниться 
        /// в STORE ключей компьютера, а не в профиле пользователя.
        /// </summary>
        /// 
        /// <value>
        /// <see langword="true"/>, если ключ должен храниться в банке ключей 
        /// компьютера, <see langword="false"/> - иначе.
        /// </value>
        /// 
        /// <remarks><para>Данный флаг устанавливает использование ключей из
        /// STORE пользователя или компьютера при открытии ключей без 
        /// указания данного флага. Установка данного флага эквивалентна
        /// передаче установке флага 
        /// <see cref="CspProviderFlags.UseMachineKeyStore"/>
        /// в <see cref="CspParameters"/>. Свойство <c>UseMachineKeyStore</c>
        /// устанавливается для всего кода в текущем домене, в то время как 
        /// <see cref="CspParameters"/> применимо только к объекту на который
        /// он ссылается. Установка/сброс данного флага полезна при 
        /// имперсонализации или работе без загруженного профиля пользователя.
        /// </para>
        /// 
        /// <para>При инициализации объекта через конструктор 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// будут использованы именно эти параметры, в независимости от
        /// флага <see cref="UseMachineKeyStore"/>. По умолчанию значение
        /// флага из 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// устанавливется в использование ключей из хранилищи пользователя.
        /// Для использования ключей из хранилища компьютера при использовании
        /// конструктора 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// необходимо установить флаг <see cref="CspParameters.Flags"/>:
        /// <see cref="CspProviderFlags.UseMachineKeyStore"/>.
        /// </para>
        /// </remarks>
        public static bool UseMachineKeyStore
        {
            get
            {
                return (s_useMachineKeyStore == CspProviderFlags.UseMachineKeyStore);
            }
            set
            {
                s_useMachineKeyStore = (value ? CspProviderFlags.UseMachineKeyStore : 0);
            }
        }

        /// <summary>
        /// Создание ключа согласования (agree ключа).
        /// </summary>
        /// 
        /// <param name="alg">Открытый ключ получателя.</param>
        /// 
        /// <returns>Ключ согласования <see cref="GostSharedSecretAlgorithm"/> 
        /// для шифрования ключевой информации.</returns>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        //[SecuritySafeCritical]
        //public override GostSharedSecretAlgorithm CreateAgree(
        //    Gost3410Parameters alg)
        //{
        //    // TODO: Еще одно дополнительное право доступа!

        //    // Получаем собственный ключ.
        //    GetKeyPair();

        //    // Превращаем его в объект для экспорта.
        //    Gost3410CspObject obj1 = new Gost3410CspObject(alg);

        //    return new GostSharedSecretCryptoServiceProvider(_safeKeyHandle,
        //        _safeProvHandle, obj1, CspAlgorithmType.Gost2001);
        //}

        /// <summary>
        /// Получение/установка сертификата в конейнер.
        /// </summary>
        /// 
        /// <argnullset />
        /// 
        /// <unmanagedperm action="Demand" />
        /// <value>Возвращается хранимый сертификат или <see langword="null"/>,
        /// если сертификат в контейнере отсутствует.</value>
        //public X509Certificate2 ContainerCertificate
        //{
        //    [SecuritySafeCritical]
        //    [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        //    get
        //    {
        //        byte[] rawData = COMCryptography.GetContainerCertificate(
        //            SafeKeyHandle);
        //        if (rawData == null)
        //            return null;
        //        X509Certificate2 ret = new X509Certificate2(rawData);
        //        // Ошибка до сборки 1.0.4015.0 включительно.
        //        // возвращался сертификат, без обратной привязки на собственный секретный ключ
        //        // Есть способ просто установить ссылку, через документированный интерфейс:
        //        // ret.PrivateKey = this;
        //        // но, во-первых, он излишне долгий, т.к. происходит генерация открытого ключа
        //        // и проверка соответствия, что делать не требуется так как сертификат
        //        // уже есть в контейнере.
        //        // во-вторых, требует обработки исключений при несоответсвии
        //        object m_safeCertContext = CPX509Certificate2.SafeCertContextFieldInfo.GetValue(ret);
        //        try
        //        {
        //            CPX509Certificate2.SetPrivateKeyProperty(m_safeCertContext, this);
        //        }
        //        catch (CryptographicException e)
        //        {
        //            DetourTraceHelper.Trace(DetourInfoCode.CallIgnore, e);
        //        }
        //        return ret;
        //    }
        //    [SecuritySafeCritical]
        //    [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        //    set
        //    {
        //        if (value == null)
        //            throw new ArgumentNullException("value");
        //        byte[] rawData = value.RawData;

        //        COMCryptography.SetKeyParamRgb(SafeKeyHandle,
        //            GostConstants.KP_CERTIFICATE, rawData);
        //    }
        //}

        /// <summary>
        /// Установка пароля доступа к контейнеру.
        /// </summary>
        /// 
        /// <param name="password">Пароль доступа к контейнеру.</param>
        /// 
        /// <remarks><para>Если ключ уже загружен в память, то поведение 
        /// данной функции зависит от провайдера, обычно проверяется 
        /// соответствие передаваемого пароля и пароля
        /// доступа на контейнер.</para> 
        /// <para>Если ключ не был загружен в память, данная функция
        /// не проверяет корректность вводимого пароля, а только 
        /// запоминает его. Проверка правильности введенного пароля
        /// будет происходить при доступе к ключу, например при
        /// операции подписи. </para></remarks>
        //[SecuritySafeCritical]
        //public void SetContainerPassword(SecureString password)
        //{
        //    // Дополнительных прав не требуем.
        //    // ничего плохого в окне выбора контейнера нет.
        //    SecurityPermission perm = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
        //    perm.Assert();
        //    // Специально не документируем поведение при password == null
        //    // комментарий см. CPUtils.SetPin
        //    if (PublicOnly)
        //        throw new CryptographicException(
        //            Resources.Cryptography_CSP_NoPrivateKey);
        //    GetKeyPair();
        //    CPUtils.SetPin(_safeProvHandle, password, this._keySpec);
        //}

        /// <summary>
        /// Предварительная загрузка контейнера в память.
        /// </summary>
        /// 
        /// <cspversions><exclude version="20"/></cspversions>
        //[SecuritySafeCritical]
        //public void PreloadContainer()
        //{
        //    // Дополнительных прав не требуем.
        //    // ничего плохого в окне выбора контейнера нет.
        //    SecurityPermission perm = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
        //    perm.Assert();
        //    if (PublicOnly)
        //        throw new CryptographicException(
        //            Resources.Cryptography_CSP_NoPrivateKey);
        //    GetKeyPair();
        //    CPUtils.GetHCryptProv(_safeProvHandle);
        //}

        /// <summary>
        /// Вывод диалогового окна выбора контейнера и получение 
        /// имени выбранного контейнера
        /// </summary>
        /// 
        /// <param name="fullyQualifiedContainerName">Вернуть полностью
        /// кваллифицированное имя контейнера.</param>
        /// <param name="machine">Использовать локальное хранилище
        /// компьютера (<see langword="true"/>) или пользователя
        /// (<see langword="true"/>).</param>
        /// <param name="parent">HWND родительского окна или IntPtr.Zero,
        /// для выдачи окна без родителя.</param>
        /// 
        /// <returns>Строку имени контейнера.</returns>
        //[SecuritySafeCritical]
        //public static string SelectContainer(bool fullyQualifiedContainerName,
        //    bool machine, IntPtr parent)
        //{
        //    // Дополнительных прав не требуем.
        //    // ничего плохого в окне выбора контейнера нет.
        //    //SecurityPermission perm = new SecurityPermission(SecurityPermissionFlag.UnmanagedCode);
        //    //perm.Assert();
        //    return COMCryptography.SelectContainer(fullyQualifiedContainerName,
        //        machine, parent, GostConstants.PROV_GOST_2001_DH);
        //}

        /// <summary>
        /// Генерация ключевой пары.
        /// </summary>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        [SecurityCritical]
        private void GetKeyPair()
        {

            // Force-read the SafeKeyHandle property, which will summon it into existence.
            SafeKeyHandle localHandle = SafeKeyHandle;
            SafeProvHandle.PersistKeyInCsp = true;
            Debug.Assert(localHandle != null);
        }

        /// <summary>
        /// Проверка, что переданные параметры, являются параметрами
        /// только открытого ключа.
        /// </summary>
        /// 
        /// <param name="gostParams">Проверяемые параметры.</param>
        /// 
        /// <returns><see langword="true"/>, если параметры не содержат, секретного 
        /// ключа</returns>
        private static bool IsPublic(Gost3410Parameters gostParams)
        {
            return (gostParams.PrivateKey == null);
        }

        /// <summary>
        /// Проверка, что байтовый массив представляет собой
        /// BLOB открытого ключа алгоритма ГОСТ Р 34.10
        /// </summary>
        /// <param name="keyBlob">Проверяемый BLOB.</param>
        /// <returns><see langword="true"/>, если похоже на BLOB ГОСТ Р 34.10 
        /// открытого ключа, <see langword="false"/> во всех остальных 
        /// случаях.</returns>
        /// <argnull name="keyBlob" />
        private static bool IsPublic(byte[] keyBlob)
        {
            // BYTE bType       0
            // BYTE bVersion    1
            // WORD reserved    2
            // ALG_ID aiKeyAlg  4
            // DWORD magic      8
            if (keyBlob == null)
                throw new ArgumentNullException("keyBlob");
            if (keyBlob[0] != GostConstants.PUBLICKEYBLOB || keyBlob.Length < 12)
                return false;
            byte[] magic = BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC);
            if (magic[0] != keyBlob[8] || magic[1] != keyBlob[9] ||
                magic[2] != keyBlob[10] || magic[3] != keyBlob[11])
                return false;
            return true;
        }

        ///// <summary>
        ///// Шаг хеширования.
        ///// </summary>
        ///// 
        ///// <param name="hashAlgorithm">HashAlgorithmName</param>
        ///// <param name="data">Массив с хешируемыми данними.</param>
        ///// <param name="offset">Начало хешируемого блока в массиве.</param>
        ///// <param name="count">Размер хешируемого блока.</param>
        ///// 
        ///// <exception cref="CryptographicException">При ошибках на native
        ///// уровне.</exception>
        //[SecurityCritical]
        //protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        //{
        //    CapiHelper.CryptHashData(this.SafeHashHandle, data, count, 0);
        //    return CapiHelper.EndHash(this.SafeHashHandle);
        //}
    }
}
