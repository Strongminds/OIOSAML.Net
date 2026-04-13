using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha1SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA1Url;
        public override string DigestUri => SignedXml.XmlDsigSHA1Url;
        protected override byte[] SignDataIntern(RSA key, byte[] data)
        {
            return key.SignData(data, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }

        protected override bool VerifySignatureIntern(RSA key, byte[] data, byte[] signature)
        {
            return key.VerifyData(data, signature, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);
        }

    }
}