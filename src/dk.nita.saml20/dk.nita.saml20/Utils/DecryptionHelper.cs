using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

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
        /// Decrypts an RSA-OAEP-SHA256 encrypted key using the supplied private RSA key.
        /// Uses the native .NET RSA implementation to avoid exporting private key material,
        /// which fails on CNG key stores unless the key is explicitly marked as exportable.
        /// The cipher (OAEP-SHA256 + MGF1-SHA256) is identical to the previous BouncyCastle path.
        /// </summary>
        public static byte[] DecryptKeyWithOaepSha256(byte[] cipherValue, RSA rsa)
        {
            return rsa.Decrypt(cipherValue, RSAEncryptionPadding.OaepSHA256);
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
