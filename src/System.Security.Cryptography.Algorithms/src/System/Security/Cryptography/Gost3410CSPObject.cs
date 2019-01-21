namespace System.Security.Cryptography
{
    /// <summary>
    /// Переходник от структуры <see cref="Gost3410Parameters"/> к объекту.
    /// </summary>
    /// 
    ///// <basedon cref="System.Security.Cryptography.RSACspObject"/> 
    ///// <basedon cref="System.Security.Cryptography.DSACspObject"/>
    internal class Gost3410CspObject
    {
        /// <summary>
        /// Конструктор объекта класса <see cref="Gost3410CspObject"/>
        /// </summary>
        public Gost3410CspObject()
        {
        }

        /// <summary>
        /// Конструктор объекта класса по параметрам ключа.
        /// </summary>
        public Gost3410CspObject(Gost3410Parameters parameters)
        {
            _publicKeyParamSet = parameters.PublicKeyParamSet;
            _digestParamSet = parameters.DigestParamSet;
            _encryptionParamSet = parameters.EncryptionParamSet;
            _publicKey = parameters.PublicKey;
            _privateKey = parameters.PrivateKey;
        }

        /// <summary>
        /// Получение/установка параметров ключа.
        /// </summary>
        public Gost3410Parameters Parameters
        {
            get
            {
                Gost3410Parameters ret;
                ret.PublicKeyParamSet = _publicKeyParamSet;
                ret.DigestParamSet = _digestParamSet;
                ret.EncryptionParamSet = _encryptionParamSet;
                ret.PublicKey = _publicKey;
                ret.PrivateKey = _privateKey;
                return ret;
            }
            set
            {
                _publicKeyParamSet = value.PublicKeyParamSet;
                _digestParamSet = value.DigestParamSet;
                _encryptionParamSet = value.EncryptionParamSet;
                _publicKey = value.PublicKey;
                _privateKey = value.PrivateKey;
            }
        }

        /// <summary>
        /// OID параметров хеширования.
        /// </summary>
        internal string _digestParamSet;
        /// <summary>
        /// Необязательный OID параметров шифрования.
        /// </summary>
        internal string _encryptionParamSet;
        /// <summary>
        /// OID параметров подписи и DH.
        /// </summary>
        internal string _publicKeyParamSet;
        /// <summary>
        /// Открытый ключ.
        /// </summary>
        internal byte[] _publicKey;
        /// <summary>
        /// Секретный ключ.
        /// </summary>
        internal byte[] _privateKey;
    }
}
