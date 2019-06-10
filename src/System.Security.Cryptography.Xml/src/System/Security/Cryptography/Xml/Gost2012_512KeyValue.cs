//// Copyright (C) 2006-2012 Крипто-Про. Все права защищены.
////
//// Этот файл содержит информацию, являющуюся
//// собственностью компании Крипто-Про.
//// 
//// Любая часть этого файла не может быть скопирована,
//// исправлена, переведена на другие языки,
//// локализована или модифицирована любым способом,
//// откомпилирована, передана по сети с или на
//// любую компьютерную систему без предварительного
//// заключения соглашения с компанией Крипто-Про.
//// 

//// Класс сделан по образу и подобию RSAKeyValue
//// Namespace: System.Security.Cryptography.Xml
//// Assembly: System.Security (in system.security.dll)

//using System;
//using System.Collections.Generic;
//using System.Security.Cryptography.Xml;
//using System.Text;
//using System.Xml;
//using CryptoPro.Sharpei;

//namespace CryptoPro.Sharpei.Xml
//{
//    /// <summary>
//    /// Представляет закрытый ключ ГОСТ 34.10-2012 512 элемента &lt;KeyInfo&gt;.
//    /// </summary>
//    /// 
//    /// <remarks><para>
//    /// Класс <see cref="System.Security.Cryptography.Xml.KeyInfo"/> 
//    /// представляет элемент &lt;KeyInfo&gt;, содержащий открытый ключ ГОСТ 34.10-2012 512. 
//    /// </para>
//    /// <para>Используйте <c>GostKeyValue</c> для идентификации открытого ключа, 
//    /// соответствующего закрытому ключу ГОСТ 34.10-2012 512, который был использован 
//    /// для создания цифровой подписи.</para>
//    /// <para>Если ключ не предоставляется конструктору явно, новая пара ключей 
//    /// ГОСТ 34.10-2012 512 генерируется случайным образом.</para>
//    /// <para>Класс <c>GostKeyValue</c> используется с подписями XML. С 
//    /// дополнительными сведениями о спецификации консорциума W3C можно ознакомиться 
//    /// на веб-узле http://www.w3.org/TR/xmldsig-core/. Дополненения к спецификации 
//    /// для российских стандартов
//    /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
//    /// </para>
//    /// </remarks>
//    public class Gost2012_512KeyValue : KeyInfoClause
//    {
//        /// <summary>
//        /// Инициализирует новый экземпляр класса <c>GostKeyValue</c> с новым, 
//        /// сгенерированным случайным образом открытым ключом ГОСТ 34.10-2012 512.
//        /// </summary>
//        /// <remarks>При создании нового ключа ГОСТ 34.10-2012 512 этот конструктор 
//        /// использует реализацию <see cref="CryptoPro.Sharpei.Gost3410_2012_512"/> по 
//        /// умолчанию, как определено классом 
//        /// <see cref="System.Security.Cryptography.CryptoConfig"/>.</remarks>
//        public Gost2012_512KeyValue()
//        {
//            m_key = Gost3410_2012_512.Create();
//        }

//        /// <summary>
//        /// Инициализирует новый экземпляр класса <c>GostKeyValue</c> с заданным 
//        /// открытым ключом ГОСТ 34.10-2012 512.
//        /// </summary>
//        /// 
//        /// <param name="key">Экземпляр реализации класса 
//        /// <see cref="CryptoPro.Sharpei.Gost3410_2012_512"/>, в котором содержится открытый 
//        /// ключ.</param>
//        public Gost2012_512KeyValue(Gost3410_2012_512 key)
//        {
//            m_key = key;
//        }

//        /// <summary>
//        /// Возвращает XML представление подэлемента GostKeyValue 
//        /// </summary>
//        /// 
//        /// <returns>XML представление подэлемента GostKeyValue 
//        /// <see cref="KeyInfo"/>.</returns>
//        /// 
//        /// <remarks><para>Данный метод служит для преобразования выходных 
//        /// данных объекта <c>GostKeyValue</c> в формат XML.</para></remarks>
//        public override XmlElement GetXml()
//        {
//            XmlDocument document1 = new XmlDocument();
//            document1.PreserveWhitespace = true;
//            return this.GetXml(document1);
//        }

//        /// <summary>
//        /// Возвращает XML представление подэлемента GostKeyValue.
//        /// </summary>
//        /// 
//        /// <param name="xmlDocument">XML документ.</param>
//        /// 
//        /// <returns>XML элемент представления.</returns>
//        private XmlElement GetXml(XmlDocument xmlDocument)
//        {
//            // Несмотря на то что функция очень похожа на ParamsToXmlString
//            // не удается их объединить.
//            // С одной стороны, нет возможности втащить полноценный XML parser
//            // в cpBase (зависимость только от system), с другой нам необходим
//            // namespace в именах.
//            Gost3410Parameters parameters = m_key.ExportParameters(false);
//            XmlElement keyValue = xmlDocument.CreateElement(
//                "KeyValue", Constants.XmlDsigNamespace);
//            XmlElement gostKeyValue = xmlDocument.CreateElement(
//                Constants.TagKeyValue2001, Constants.XmlDsigNamespace);

//            XmlElement publicKeyParameters = xmlDocument.CreateElement(
//                Constants.TagPublicKeyParameters, Constants.XmlDsigNamespace);

//            XmlElement publicKeyParamSet = xmlDocument.CreateElement(
//                Constants.TagPublicKeyParamSet, Constants.XmlDsigNamespace);
//            publicKeyParamSet.AppendChild(xmlDocument.CreateTextNode("urn:oid:"+parameters.PublicKeyParamSet));

//            XmlElement digestParamSet = xmlDocument.CreateElement(
//                Constants.TagDigestParamSet, Constants.XmlDsigNamespace);
//            digestParamSet.AppendChild(xmlDocument.CreateTextNode("urn:oid:" + parameters.DigestParamSet));

//            XmlElement encryptionParamSet = null;
//            if (parameters.EncryptionParamSet != null)
//            {
//                xmlDocument.CreateElement(Constants.TagEncryptionParamSet,
//                    Constants.XmlDsigNamespace);
//                encryptionParamSet.AppendChild(xmlDocument.CreateTextNode("urn:oid:" + parameters.EncryptionParamSet));
//            }

//            XmlElement publicKey = xmlDocument.CreateElement(
//                Constants.TagPublicKey, Constants.XmlDsigNamespace);
//            publicKey.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(parameters.PublicKey)));

//            publicKeyParameters.AppendChild(publicKeyParamSet);
//            publicKeyParameters.AppendChild(digestParamSet);
//            if (encryptionParamSet != null)
//                publicKeyParameters.AppendChild(encryptionParamSet);

//            gostKeyValue.AppendChild(publicKeyParameters);
//            gostKeyValue.AppendChild(publicKey);
//            keyValue.AppendChild(gostKeyValue);
//            return keyValue;
//        }

//        /// <summary>
//        /// Загружает состояние GostKeyValue из элемента XML.
//        /// </summary>
//        /// 
//        /// <param name="value">Элемент XML, из которого загружается 
//        /// состояние GostKeyValue.</param>
//        /// 
//        /// <argnull name="value" />
//        public override void LoadXml(XmlElement value)
//        {
//            if (value == null)
//                throw new ArgumentNullException("value");
//            this.m_key.FromXmlString(value.OuterXml);
//        }

//        /// <summary>
//        /// Возвращает или устаналивает объект <see cref="Gost3410_2012_512"/>, 
//        /// которому принадлежит открытый ключ.
//        /// </summary>
//        public Gost3410_2012_512 Key 
//        {
//            get
//            {
//                return this.m_key;
//            }
//            set
//            {
//                this.m_key = value;
//            }
//        }

//        /// <summary>
//        /// Объект <see cref="Gost3410_2012_512"/>, которому принадлежит открытый ключ.
//        /// </summary>
//        private Gost3410_2012_512 m_key;
//    }
//}
