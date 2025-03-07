using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using dk.nita.saml20.Schema.Protocol;
using dk.nita.saml20.Utils;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using SfwEncryptedData = dk.nita.saml20.Schema.XEnc.EncryptedData;

namespace dk.nita.saml20
{
    /// <summary>
    /// Handles the <code>EncryptedAssertion</code> element. 
    /// </summary>
    public class Saml20EncryptedAssertion
    {
        /// <summary>
        /// The assertion that is stored within the encrypted assertion.
        /// </summary>
        private XmlDocument _assertion;

        /// <summary>
        /// The <code>Assertion</code> element that is embedded within the <code>EncryptedAssertion</code> element.
        /// </summary>
        public XmlDocument Assertion
        {
            get { return _assertion; }
            set { _assertion = value; }
        }

        /// <summary>
        /// The <code>EncryptedAssertion</code> element containing an <code>Assertion</code>.
        /// </summary>
        private XmlDocument _encryptedAssertion;

        /// <summary>
        /// Initializes a new instance of <code>EncryptedAssertion</code>.
        /// </summary>
        public Saml20EncryptedAssertion()
        { }

        /// <summary>
        /// Initializes a new instance of <code>EncryptedAssertion</code>.
        /// </summary>
        /// <param name="transportKey">The transport key is used for securing the symmetric key that has encrypted the assertion.</param>        
        public Saml20EncryptedAssertion(RSA transportKey) : this()
        {
            _transportKey = transportKey;
        }

        /// <summary>
        /// Initializes a new instance of <code>EncryptedAssertion</code>.
        /// </summary>
        /// <param name="transportKey">The transport key is used for securing the symmetric key that has encrypted the assertion.</param>
        /// <param name="encryptedAssertion">An <code>XmlDocument</code> containing an <code>EncryptedAssertion</code> element.</param>
        public Saml20EncryptedAssertion(RSA transportKey, XmlDocument encryptedAssertion) : this(transportKey)
        {
            LoadXml(encryptedAssertion.DocumentElement);
        }

        /// <summary>
        /// Initializes the instance with a new <code>EncryptedAssertion</code> element.
        /// </summary>
        public void LoadXml(XmlElement element)
        {
            CheckEncryptedAssertionElement(element);

            _encryptedAssertion = new XmlDocument();
            _encryptedAssertion.XmlResolver = null;
            _encryptedAssertion.AppendChild(_encryptedAssertion.ImportNode(element, true));
        }

        /// <summary>
        /// Verifies that the given <code>XmlElement</code> is actually a SAML 2.0 <code>EncryptedAssertion</code> element.
        /// </summary>
        private static void CheckEncryptedAssertionElement(XmlElement element)
        {
            if (element.LocalName != EncryptedAssertion.ELEMENT_NAME)
                throw new ArgumentException("The element must be of type \"EncryptedAssertion\".");

            if (element.NamespaceURI != Saml20Constants.ASSERTION)
                throw new ArgumentException("The element must be of type \"" + Saml20Constants.ASSERTION + "#EncryptedAssertion\".");
        }


        /// <summary>
        /// Returns the XML representation of the encrypted assertion.
        /// </summary>        
        public XmlDocument GetXml()
        {
            return _encryptedAssertion;
        }

        private string _sessionKeyAlgorithm = EncryptedXml.XmlEncAES256Url;

        /// <summary>
        /// Specifiy the algorithm to use for the session key. The algorithm is specified using the identifiers given in the 
        /// Xml Encryption Specification. see also http://www.w3.org/TR/xmlenc-core/#sec-Algorithms
        /// The class <code>EncryptedXml</code> contains public fields with the identifiers. If nothing is 
        /// specified, a 256 bit AES key is used.
        /// </summary>
        public string SessionKeyAlgorithm
        {
            get { return _sessionKeyAlgorithm; }
            set
            {
                // Validate that the URI used to identify the algorithm of the session key is probably correct. Not a complete validation, but should catch most obvious mistakes.
                if (!value.StartsWith(Saml20Constants.XENC))
                    throw new ArgumentException("The session key algorithm must be specified using the identifying URIs listed in the specification.");

                _sessionKeyAlgorithm = value;
            }
        }

        private RSA _transportKey;
        /// <summary>
        /// The transport key is used for securing the symmetric key that has encrypted the assertion.
        /// </summary>
        public RSA TransportKey
        {
            set { _transportKey = value; }
            get { return _transportKey; }
        }

        /// <summary>
        /// Decrypts the assertion using the key given as the method parameter. The resulting assertion
        /// is available through the <code>Assertion</code> property.
        /// </summary>
        /// <exception cref="Saml20FormatException">Thrown if it not possible to decrypt the assertion.</exception>
        public void Decrypt()
        {
            if (TransportKey == null)
                throw new InvalidOperationException("The \"TransportKey\" property must contain the asymmetric key to decrypt the assertion.");

            if (_encryptedAssertion == null)
                throw new InvalidOperationException("Unable to find the <EncryptedAssertion> element. Use a constructor or the LoadXml - method to set it.");

            // Get the <EncryptedData> element
            XmlElement encryptedDataElement = GetElement(SfwEncryptedData.ELEMENT_NAME, Saml20Constants.XENC, _encryptedAssertion.DocumentElement);
            EncryptedData encryptedData = new EncryptedData();
            encryptedData.LoadXml(encryptedDataElement);

            // Extract and decrypt the session key using BouncyCastle
            SymmetricAlgorithm sessionKey;
            if (encryptedData.EncryptionMethod != null)
            {
                _sessionKeyAlgorithm = encryptedData.EncryptionMethod.KeyAlgorithm;
                sessionKey = ExtractSessionKey(_encryptedAssertion, encryptedData.EncryptionMethod.KeyAlgorithm);
            }
            else
            {
                sessionKey = ExtractSessionKey(_encryptedAssertion);
            }

            // Decrypt the assertion using AES-GCM
            byte[] plaintext = DecryptionHelper.Decrypt(encryptedData, sessionKey.Key);

            _assertion = new XmlDocument();
            _assertion.XmlResolver = null;
            _assertion.PreserveWhitespace = true;

            try
            {
                _assertion.Load(new StringReader(Encoding.UTF8.GetString(plaintext)));
            }
            catch (XmlException e)
            {
                _assertion = null;
                throw new Saml20FormatException("Unable to parse the decrypted assertion.", e);
            }
        }

        private SymmetricAlgorithm ExtractSessionKey(XmlDocument encryptedAssertionDoc, string keyAlgorithm = "")
        {
            if (keyAlgorithm == DecryptionHelper.AesGcmAlgorithmName)
                return ExtractSessionKeyWithAesGcm(encryptedAssertionDoc);

            return ExtractSessionKeyWithOtherAlgorithm(encryptedAssertionDoc, keyAlgorithm);
        }

        private SymmetricAlgorithm ExtractSessionKeyWithAesGcm(XmlDocument encryptedAssertionDoc)
        {
            // Find <EncryptedKey> in the SAML response
            XmlElement encryptedKeyElement = GetElement("EncryptedKey", Saml20Constants.XENC, encryptedAssertionDoc.DocumentElement);
            if (encryptedKeyElement == null)
                throw new Saml20FormatException("Unable to locate assertion decryption key.");

            var encryptedKey = new EncryptedKey();
            encryptedKey.LoadXml(encryptedKeyElement);

            // Extract cipher value (encrypted AES key)
            byte[] encryptedAesKey = encryptedKey.CipherData.CipherValue;

            // Decrypt the AES key using BouncyCastle (RSA-OAEP-SHA256 + MGF1-SHA256)
            byte[] aesKey = DecryptionHelper.DecryptKeyWithOaepSha256(encryptedAesKey, TransportKey);

            // Create an AES instance and set the key
            SymmetricAlgorithm aes = Aes.Create();
            aes.KeySize = 256;
            aes.Key = aesKey;

            return aes;
        }

        /// <summary>
        /// Locates and deserializes the key used for encrypting the assertion. Searches the list of keys below the &lt;EncryptedAssertion&gt; element and 
        /// the &lt;KeyInfo&gt; element of the &lt;EncryptedData&gt; element.
        /// </summary>
        /// <param name="encryptedAssertionDoc"></param>
        /// <param name="keyAlgorithm">The XML Encryption standard identifier for the algorithm of the session key.</param>
        /// <returns>A <code>SymmetricAlgorithm</code> containing the key if it was successfully found. Null if the method was unable to locate the key.</returns>
        private SymmetricAlgorithm ExtractSessionKeyWithOtherAlgorithm(XmlDocument encryptedAssertionDoc, string keyAlgorithm)
        {
            // Check if there are any <EncryptedKey> elements immediately below the EncryptedAssertion element.
            foreach (XmlNode node in encryptedAssertionDoc.DocumentElement.ChildNodes)
                if (node.LocalName == Schema.XEnc.EncryptedKey.ELEMENT_NAME && node.NamespaceURI == Saml20Constants.XENC)
                {
                    return ToSymmetricKey((XmlElement)node, keyAlgorithm);
                }

            // Check if the key is embedded in the <EncryptedData> element.
            XmlElement encryptedData =
                GetElement(SfwEncryptedData.ELEMENT_NAME, Saml20Constants.XENC, encryptedAssertionDoc.DocumentElement);
            if (encryptedData != null)
            {
                XmlElement encryptedKeyElement =
                    GetElement(Schema.XEnc.EncryptedKey.ELEMENT_NAME, Saml20Constants.XENC, encryptedAssertionDoc.DocumentElement);
                if (encryptedKeyElement != null)
                {
                    return ToSymmetricKey(encryptedKeyElement, keyAlgorithm);
                }
            }

            throw new Saml20FormatException("Unable to locate assertion decryption key.");
        }

        /// <summary>
        /// Extracts the key from a &lt;EncryptedKey&gt; element.
        /// </summary>
        /// <param name="encryptedKeyElement"></param>
        /// <param name="keyAlgorithm"></param>
        /// <returns></returns>
        private SymmetricAlgorithm ToSymmetricKey(XmlElement encryptedKeyElement, string keyAlgorithm)
        {
            var encryptedKey = new EncryptedKey();
            encryptedKey.LoadXml(encryptedKeyElement);

            if (encryptedKey.CipherData.CipherValue != null)
            {
                var key = GetKeyInstance(keyAlgorithm);
                if (encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl)
                {
                    key.Key = EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, TransportKey, true);
                }
                else if (encryptedKey.EncryptionMethod.KeyAlgorithm.ToLower().Contains("oaep"))
                {
                    key.Key = DecryptionHelper.DecryptKeyWithOaepSha256(encryptedKey.CipherData.CipherValue, TransportKey);
                }
                else
                {
                    key.Key = EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, TransportKey, false); // PKCS#1
                }

                return key;
            }

            throw new NotImplementedException("Unable to decode CipherData of type \"CipherReference\".");
        }

        /// <summary>
        /// Creates an instance of a symmetric key, based on the algorithm identifier found in the Xml Encryption standard.        
        /// see also http://www.w3.org/TR/xmlenc-core/#sec-Algorithms
        /// </summary>
        /// <param name="algorithm">A string containing one of the algorithm identifiers found in the XML Encryption standard. The class
        /// <code>EncryptedXml</code> contains the identifiers as fields.</param>        
        private static SymmetricAlgorithm GetKeyInstance(string algorithm)
        {
            SymmetricAlgorithm result;
            switch (algorithm)
            {
                case EncryptedXml.XmlEncTripleDESUrl:
                    result = TripleDES.Create();
                    break;
                case EncryptedXml.XmlEncAES128Url:
                    result = new RijndaelManaged();
                    result.KeySize = 128;
                    break;
                case EncryptedXml.XmlEncAES192Url:
                    result = new RijndaelManaged();
                    result.KeySize = 192;
                    break;
                case EncryptedXml.XmlEncAES256Url:
                    result = new RijndaelManaged();
                    result.KeySize = 256;
                    break;
                default:
                    result = new RijndaelManaged();
                    result.KeySize = 256;
                    break;
            }
            return result;
        }


        /// <summary>
        /// Utility method for retrieving a single element from a document.
        /// </summary>
        private static XmlElement GetElement(string element, string elementNS, XmlElement doc)
        {
            XmlNodeList list = doc.GetElementsByTagName(element, elementNS);
            if (list.Count == 0)
                return null;

            return (XmlElement)list[0];
        }


        private SymmetricAlgorithm _sessionKey;

        /// <summary>
        /// The key used for encrypting the <code>Assertion</code>. This key is embedded within a <code>KeyInfo</code> element
        /// in the <code>EncryptedAssertion</code> element. The session key is encrypted with the <code>TransportKey</code> before
        /// being embedded.
        /// </summary>
        private SymmetricAlgorithm SessionKey
        {
            get
            {
                if (_sessionKey == null)
                {
                    _sessionKey = GetKeyInstance(_sessionKeyAlgorithm);
                    _sessionKey.GenerateKey();
                }
                return _sessionKey;
            }
        }

        /// <summary>
        /// Writes the assertion to the XmlWriter.
        /// </summary>
        /// <param name="writer">The writer.</param>
        public void WriteAssertion(XmlWriter writer)
        {
            _encryptedAssertion.WriteTo(writer);
        }
    }
}
