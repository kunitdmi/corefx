using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using Xunit;

namespace System.Security.Cryptography.Xml.Tests
{
    public class GostSignedXmlTest
    {
        [Fact]
        public void Verify2012_256()
        {
            var rawXml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><MyXML Signed=\"true\"><ElementToSign Signed=\"true\">Here is some data to sign.</ElementToSign><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /></Transforms><DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\" /><DigestValue>AJurr2ph8YjCraU6VFAeTKXKM3zZtz4gHgN0+gzE5y8=</DigestValue></Reference></SignedInfo><SignatureValue>fbjm76Pe8oe++5udjiqVolYUBmwue11qdxdudGSjw+7TNevOQ4NsGkSYaK/zbsXntZyGGk8vNzJiIpqQH7NLdw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIBhDCCATGgAwIBAgIQdRGdjFEFWqJFdK3uXftqvDAKBggqhQMHAQEDAjAdMRswGQYDVQQDDBJHb3N0XzIwMTJfMjU2X1Rlc3QwHhcNMTcxMTI4MDc1NjM1WhcNNDAwMzIwMDczMTAwWjAdMRswGQYDVQQDDBJHb3N0XzIwMTJfMjU2X1Rlc3QwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAA1ZjRyfGkhalAO5hgXvYUvs8S3Xkap98Fp9RfqA7L+BV0391rHPL6d0uGx4WsBmM9G802YJgDZCuiMyKAgi5R6NGMEQwDgYDVR0PAQH/BAQDAgXgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR1pExePljgg5daru/pCaFbqIYHvTAKBggqhQMHAQEDAgNBAIekQ/6QdH47xOGFMN3lEMmFi503SmGZ8o7sIjBAjBeWrHNUsoGXeVl46KZbCYtrw7mGxyVn6iUmFGLXYD22He8=</X509Certificate></X509Data></KeyInfo></Signature></MyXML>";
            var doc = new XmlDocument();
            // Сохраняем все пробельные символы, они важны при проверке 
            // подписи.
            doc.PreserveWhitespace = true;
            doc.LoadXml(rawXml);
            var result = ValidateXmlFIle(doc);
            Assert.True(result);
        }

        static XmlDocument SignXmlFile(XmlDocument doc, AsymmetricAlgorithm Key, X509Certificate Certificate)
        {
            // Создаем объект SignedXml по XML документу.
            SignedXml signedXml = new SignedXml(doc);

            // Добавляем ключ в SignedXml документ. 
            signedXml.SigningKey = Key;

            // Создаем ссылку на node для подписи.
            // При подписи всего документа проставляем "".
            Reference reference = new Reference();
            reference.Uri = "";

            // Явно проставляем алгоритм хэширования,
            // по умолчанию SHA1.
            reference.DigestMethod =
                SignedXml.XmlDsigGost3411_2012_256Url;

            // Добавляем transform на подписываемые данные
            // для удаления вложенной подписи.
            XmlDsigEnvelopedSignatureTransform env =
                new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Добавляем СМЭВ трансформ.
            // начиная с .NET 4.5.1 для проверки подписи, необходимо добавить этот трансформ в довернные:
            // signedXml.SafeCanonicalizationMethods.Add("urn://smev-gov-ru/xmldsig/transform");
            XmlDsigSmevTransform smev =
                new XmlDsigSmevTransform();
            reference.AddTransform(smev);

            // Добавляем transform для канонизации.
            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
            reference.AddTransform(c14);

            // Добавляем ссылку на подписываемые данные
            signedXml.AddReference(reference);

            // Создаем объект KeyInfo.
            KeyInfo keyInfo = new KeyInfo();

            // Добавляем сертификат в KeyInfo
            keyInfo.AddClause(new KeyInfoX509Data(Certificate));

            // Добавляем KeyInfo в SignedXml.
            signedXml.KeyInfo = keyInfo;

            // Можно явно проставить алгоритм подписи: ГОСТ Р 34.10.
            // Если сертификат ключа подписи ГОСТ Р 34.10
            // и алгоритм ключа подписи не задан, то будет использован
            // XmlDsigGost3410Url
            // signedXml.SignedInfo.SignatureMethod =
            //     CPSignedXml.XmlDsigGost3410_2012_256Url;

            // Вычисляем подпись.
            signedXml.ComputeSignature();

            // Получаем XML представление подписи и сохраняем его 
            // в отдельном node.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Добавляем node подписи в XML документ.
            doc.DocumentElement.AppendChild(doc.ImportNode(
                xmlDigitalSignature, true));

            // При наличии стартовой XML декларации ее удаляем
            // (во избежание повторного сохранения)
            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            return doc;
        }

        static bool ValidateXmlFIle(XmlDocument xmlDocument)
        {
            // Ищем все node "Signature" и сохраняем их в объекте XmlNodeList
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName(
                "Signature", SignedXml.XmlDsigNamespaceUrl);

            // Проверяем все подписи.
            bool result = true;
            for (int curSignature = 0; curSignature < nodeList.Count; curSignature++)
            {
                // Создаем объект SignedXml для проверки подписи документа.
                SignedXml signedXml = new SignedXml(xmlDocument);

                // начиная с .NET 4.5.1 для проверки подписи, необходимо добавить СМЭВ transform в довернные:

                signedXml.SafeCanonicalizationMethods.Add("urn://smev-gov-ru/xmldsig/transform");

                // Загружаем узел с подписью.
                signedXml.LoadXml((XmlElement)nodeList[curSignature]);

                // Проверяем подпись и выводим результат.
                result &= signedXml.CheckSignature();
            }
            return result;
        }

        //private static Gost3410_2012_256CryptoServiceProvider GetGostProvider()
        //{
        //    CspParameters cpsParams = new CspParameters(
        //        75,
        //        "",
        //        "\\\\.\\HDIMAGE\\G2012256");
        //    return new Gost3410_2012_256CryptoServiceProvider(cpsParams);
        //}
    }
}
