using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Modes;
using System;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Utils
{
    /// <summary>
    /// Helper class for decryption operations.
    /// </summary>
    public static class DecryptionHelper
    {
        /// <summary>
        /// Algorithm name for AES GCM
        /// </summary>
        public const string AesGcmAlgorithmName = "http://www.w3.org/2009/xmlenc11#aes256-gcm";

        /// <summary>
        /// Decrypts private certificate with support for OaepSha256 format
        /// </summary>
        /// <param name="cipherValue">Cipher to be decrypted</param>
        /// <param name="rsa">RSA key parameters</param>
        /// <returns></returns>
        public static byte[] DecryptKeyWithOaepSha256(byte[] cipherValue, RSA rsa)
        {
            // Export RSA parameters
            var rsaParams = rsa.ExportParameters(true);

            // Convert RSAParameters to private key key parameters
            var keyParams = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, rsaParams.Modulus),
                new BigInteger(1, rsaParams.Exponent),
                new BigInteger(1, rsaParams.D),
                new BigInteger(1, rsaParams.P),
                new BigInteger(1, rsaParams.Q),
                new BigInteger(1, rsaParams.DP),
                new BigInteger(1, rsaParams.DQ),
                new BigInteger(1, rsaParams.InverseQ)
            );

            // Create the RSA engine with OAEP using SHA-256
            var engine = new OaepEncoding(new RsaEngine(), new Sha256Digest(), new Sha256Digest(), null);
            engine.Init(false, keyParams); // false for decryption

            return engine.ProcessBlock(cipherValue, 0, cipherValue.Length);
        }

        /// <summary>
        /// Decrypts private certificate
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] Decrypt(EncryptedData encryptedData, byte[] key)
        {
            if (encryptedData.EncryptionMethod.KeyAlgorithm != AesGcmAlgorithmName)
            {
                throw new InvalidOperationException("The key algorithm is not supported");
            }

            // Base64 decode encrypted data
            var nonceCipherValue = encryptedData.CipherData.CipherValue;

            // separate nonce and ciphertextTag
            const int nonceSize = 12;
            const int macSize = 16;

            var nonce = new byte[nonceSize];
            Buffer.BlockCopy(nonceCipherValue, 0, nonce, 0, nonceSize);
            var ciphertextTag = new byte[nonceCipherValue.Length - nonceSize];
            Buffer.BlockCopy(nonceCipherValue, nonceSize, ciphertextTag, 0, ciphertextTag.Length);

            var gcmBlockCipher = new GcmBlockCipher(new AesEngine());
            gcmBlockCipher.Init(false, new AeadParameters(new KeyParameter(key), macSize * 8, nonce));
            var outputSizeDecryptedData = gcmBlockCipher.GetOutputSize(ciphertextTag.Length);
            var decryptedData = new byte[outputSizeDecryptedData];
            var processedBytes = gcmBlockCipher.ProcessBytes(ciphertextTag, 0, ciphertextTag.Length, decryptedData, 0);
            gcmBlockCipher.DoFinal(decryptedData, processedBytes);

            return decryptedData;
        }
    }
}
