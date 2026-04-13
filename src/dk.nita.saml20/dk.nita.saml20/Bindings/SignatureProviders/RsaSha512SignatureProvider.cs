using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Bindings.SignatureProviders
{
    internal class RsaSha512SignatureProvider : SignatureProvider
    {
        public override string SignatureUri => SignedXml.XmlDsigRSASHA512Url;
        public override string DigestUri => SignedXml.XmlDsigSHA512Url;
        protected override byte[] SignDataIntern(RSA key, byte[] data)
        {
            return key.SignData(data, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        protected override bool VerifySignatureIntern(RSA key, byte[] data, byte[] signature)
        {
            return key.VerifyData(data, signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }
    }
}