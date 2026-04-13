using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha256SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA256Url;
        public override string DigestUri => SignedXml.XmlDsigSHA256Url;
        protected override byte[] SignDataIntern(RSA key, byte[] data)
        {
            return key.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        protected override bool VerifySignatureIntern(RSA key, byte[] data, byte[] signature)
        {
            return key.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}