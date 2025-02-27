using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Math;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Modes;
using System.Linq;
using System;
using System.Security.Cryptography.Xml;

namespace dk.nita.saml20.Utils
{
    /// <summary>
    /// Helper class for BouncyCastle operations.
    /// </summary>
    public static class BouncyCastleHelper
    {
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

            // Convert RSAParameters to BouncyCastle key parameters
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
        /// Decrypts private certificate with support for OaepSha256 format
        /// </summary>
        /// <param name="encryptedData"></param>
        /// <param name="aesKey"></param>
        /// <returns></returns>
        public static byte[] DecryptAssertionWithAesGcm(EncryptedData encryptedData, byte[] aesKey)
        {
            byte[] encryptedBytes = encryptedData.CipherData.CipherValue;

            // Adjust these lengths if your SAML response uses different sizes.
            int ivLength = 12;   // Commonly 12 bytes for AES-GCM
            int tagLength = 16;  // Commonly 16 bytes

            if (encryptedBytes.Length < ivLength + tagLength)
                throw new Exception("The encrypted data is too short to contain both an IV and an authentication tag.");

            // Extract IV, ciphertext, and authentication tag.
            byte[] iv = encryptedBytes.Take(ivLength).ToArray();
            byte[] authTag = encryptedBytes.Skip(encryptedBytes.Length - tagLength).ToArray();
            byte[] cipherText = encryptedBytes.Skip(ivLength).Take(encryptedBytes.Length - ivLength - tagLength).ToArray();

            // Debug logging
            Console.WriteLine("IV Length: " + iv.Length);
            Console.WriteLine("Ciphertext Length: " + cipherText.Length);
            Console.WriteLine("Auth Tag Length: " + authTag.Length);

            // Initialize AES-GCM decryption
            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine());
            AeadParameters parameters = new AeadParameters(new KeyParameter(aesKey), tagLength * 8, iv, null);
            cipher.Init(false, parameters); // false for decryption

            byte[] output = new byte[cipher.GetOutputSize(cipherText.Length)];
            int len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, output, 0);
            cipher.DoFinal(output, len);

            return output;
        }
    }
}
