using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using Trace = dk.nita.saml20.Utils.Trace;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal abstract class SignatureProvider : ISignatureProvider
    {
        public abstract string SignatureUri { get; }

        public abstract string DigestUri { get; }

        public byte[] SignData(AsymmetricAlgorithm key, byte[] data)
        {
            var rsa = (RSA)key;
            return SignDataIntern(rsa, data);
        }

        protected abstract byte[] SignDataIntern(RSA key, byte[] data);

        public bool VerifySignature(AsymmetricAlgorithm key, byte[] data, byte[] signature)
        {
            var rsa = (RSA)key;
            return VerifySignatureIntern(rsa, data, signature);
        }

        protected abstract bool VerifySignatureIntern(RSA key, byte[] data, byte[] signature);

        public void SignAssertion(XmlDocument doc, string id, X509Certificate2 cert)
        {
            var signedXml = Sign(doc, id, cert);
            // Append the computed signature. The signature must be placed as the sibling of the Issuer element.
            XmlNodeList nodes = doc.DocumentElement.GetElementsByTagName("Issuer", Saml20Constants.ASSERTION);
            nodes[0].ParentNode.InsertAfter(doc.ImportNode(signedXml.GetXml(), true), nodes[0]);
        }

        public void SignMetaData(XmlDocument doc, string id, X509Certificate2 cert)
        {
            var signedXml = Sign(doc, id, cert);
            doc.DocumentElement.InsertBefore(doc.ImportNode(signedXml.GetXml(), true), doc.DocumentElement.FirstChild);
        }
        private SignedXml Sign(XmlDocument doc, string id, X509Certificate2 cert)
        {
            SignedXml signedXml = new SignedXml(doc);
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = SignatureUri;
            signedXml.SigningKey = cert.GetRSAPrivateKey();

            // Retrieve the value of the "ID" attribute on the root assertion element.
            Reference reference = new Reference("#" + id);
            reference.DigestMethod = DigestUri;

            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());

            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion.
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(cert, X509IncludeOption.WholeChain));

            signedXml.ComputeSignature();
            return signedXml;
        }
    }
}