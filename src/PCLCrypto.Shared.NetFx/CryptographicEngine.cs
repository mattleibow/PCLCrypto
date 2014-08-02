//-----------------------------------------------------------------------
// <copyright file="CryptographicEngine.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Platform = System.Security.Cryptography;

    /// <summary>
    /// A .NET Framework implementation of CryptographicEngine.
    /// </summary>
    public static class CryptographicEngine
    {
        /// <summary>
        /// Encrypts data by using a symmetric or asymmetric algorithm.
        /// </summary>
        /// <param name="key">
        /// Cryptographic key to use for encryption. This can be an asymmetric or a symmetric
        /// key. For more information, see AsymmetricKeyAlgorithmProvider and SymmetricKeyAlgorithmProvider.
        /// </param>
        /// <param name="data">Data to encrypt.</param>
        /// <param name="iv">
        /// Buffer that contains the initialization vector. This can be null for a symmetric
        /// algorithm and should always be null for an asymmetric algorithm. If an initialization
        /// vector (IV) was used to encrypt the data, you must use the same IV to decrypt
        /// the data. You can use the GenerateRandom method to create an IV that contains
        /// random data. Other IVs, such as nonce-generated vectors, require custom implementation.
        /// For more information, see Symmetric Key Encryption.Cipher block chaining
        /// (CBC) block cipher mode algorithms require an initialization vector. For
        /// more information, see Remarks.
        /// </param>
        /// <returns>Encrypted data.</returns>
        public static byte[] Encrypt(ICryptographicKey key, byte[] data, byte[] iv = null)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
            return keyClass.Encrypt(data, iv);
        }

        /// <summary>
        /// Creates a cryptographic transform for use in a CryptoStream
        /// that encrypts data.
        /// </summary>
        /// <param name="key">The encryption key to use.</param>
        /// <param name="iv">The initialization vector, if applicable and nonzero.</param>
        /// <returns>The transform.</returns>
        public static ICryptoTransform CreateEncryptor(ICryptographicKey key, byte[] iv = null)
        {
            Requires.NotNull(key, "key");

            var keyClass = (CryptographicKey)key;
            return keyClass.CreateEncryptor(iv);
        }

        /// <summary>
        /// Decrypts content that was previously encrypted by using a symmetric or asymmetric
        /// algorithm.
        /// </summary>
        /// <param name="key">
        /// Cryptographic key to use for decryption. This can be an asymmetric or a symmetric
        /// key. For more information, see AsymmetricKeyAlgorithmProvider and SymmetricKeyAlgorithmProvider.
        /// </param>
        /// <param name="data">
        /// Buffer that contains the encrypted data.
        /// </param>
        /// <param name="iv">
        /// Buffer that contains the initialization vector. If an initialization vector
        /// (IV) was used to encrypt the data, you must use the same IV to decrypt the
        /// data. For more information, see Encrypt.
        /// </param>
        /// <returns>Decrypted data.</returns>
        public static byte[] Decrypt(ICryptographicKey key, byte[] data, byte[] iv = null)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            var keyClass = (CryptographicKey)key;
            return keyClass.Decrypt(data, iv);
        }

        /// <summary>
        /// Creates a cryptographic transform for use in a CryptoStream
        /// that decrypts data.
        /// </summary>
        /// <param name="key">The decryption key to use.</param>
        /// <param name="iv">The initialization vector, if applicable and nonzero.</param>
        /// <returns>The transform.</returns>
        public static ICryptoTransform CreateDecryptor(ICryptographicKey key, byte[] iv = null)
        {
            Requires.NotNull(key, "key");

            var keyClass = (CryptographicKey)key;
            return keyClass.CreateDecryptor(iv);
        }

        /// <summary>
        /// Signs digital content.
        /// </summary>
        /// <param name="key">Key used for signing.</param>
        /// <param name="data">Data to be signed.</param>
        /// <returns>The signature.</returns>
        public static byte[] Sign(ICryptographicKey key, byte[] data)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return ((CryptographicKey)key).Sign(data);
        }

        /// <summary>
        /// Signs the hashed input data using the specified key.
        /// </summary>
        /// <param name="key">The key to use to sign the hash.</param>
        /// <param name="data">
        /// The input data to sign. The data is a hashed value which can be obtained
        /// through incremental hash.
        /// </param>
        /// <returns>The signature.</returns>
        public static byte[] SignHashedData(ICryptographicKey key, byte[] data)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");

            return ((CryptographicKey)key).SignHash(data);
        }

        /// <summary>
        /// Verifies a message signature.
        /// </summary>
        /// <param name="key">
        /// Key used for verification. This must be the same key previously used to sign
        /// the message.
        /// </param>
        /// <param name="data">Message to be verified.</param>
        /// <param name="signature">Signature previously computed over the message to be verified.</param>
        /// <returns>true if the message is verified.</returns>
        public static bool VerifySignature(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "signature");

            return ((CryptographicKey)key).VerifySignature(data, signature);
        }

        /// <summary>
        /// Verifies the signature of the specified input data against a known signature.
        /// </summary>
        /// <param name="key">
        /// The key to use to retrieve the signature from the input data.
        /// </param>
        /// <param name="data">The data to be verified. The data is a hashed value of raw data.</param>
        /// <param name="signature">The known signature to use to verify the signature of the input data.</param>
        /// <returns>True if the signature is verified; otherwise false.</returns>
        public static bool VerifySignatureWithHashInput(ICryptographicKey key, byte[] data, byte[] signature)
        {
            Requires.NotNull(key, "key");
            Requires.NotNull(data, "data");
            Requires.NotNull(signature, "paramName");

            return ((CryptographicKey)key).VerifyHash(data, signature);
        }

        /// <summary>
        /// Derives a key from another key by using a key derivation function.
        /// </summary>
        /// <param name="key">The symmetric or secret key used for derivation.</param>
        /// <param name="parameters">Derivation parameters. The parameters vary depending on the type of KDF algorithm
        /// used.</param>
        /// <param name="desiredKeySize">Requested size, in bits, of the derived key.</param>
        /// <returns>
        /// Buffer that contains the derived key.
        /// </returns>
        public static byte[] DeriveKeyMaterial(ICryptographicKey key, IKeyDerivationParameters parameters, int desiredKeySize)
        {
            // Right now we're assuming that KdfGenericBinary is directly usable as a salt
            // in RFC2898. When our KeyDerivationParametersFactory class supports
            // more parameter types than just BuildForPbkdf2, we might need to adjust this code
            // to handle each type of parameter.
            var keyMaterial = ((KeyDerivationCryptographicKey)key).Key;
            byte[] salt = parameters.KdfGenericBinary;
            var deriveBytes = new Platform.Rfc2898DeriveBytes(keyMaterial, salt, parameters.IterationCount);
            return deriveBytes.GetBytes(desiredKeySize);
        }

        /// <summary>
        /// Gets the OID (or name) for a given hash algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>A non-empty string.</returns>
        internal static string GetHashAlgorithmOID(AsymmetricAlgorithm algorithm)
        {
            string algorithmName = HashAlgorithmProviderFactory.GetHashAlgorithmName(AsymmetricKeyAlgorithmProviderFactory.GetHashAlgorithmEnum(algorithm));

#if SILVERLIGHT
            // Windows Phone 8.0 and Silverlight both are missing the
            // CryptoConfig type. But that's ok since both platforms
            // accept the algorithm name directly as well as the OID
            // which we can't easily get to.
            return algorithmName;
#else
            // Mono requires the OID, so we get it when we can.
            return Platform.CryptoConfig.MapNameToOID(algorithmName);
#endif
        }

        /// <summary>
        /// Creates a hash algorithm instance that is appropriate for the given algorithm.T
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>The hash algorithm.</returns>
#if Android
        internal static Java.Security.MessageDigest GetHashAlgorithm(AsymmetricAlgorithm algorithm)
#else
        internal static Platform.HashAlgorithm GetHashAlgorithm(AsymmetricAlgorithm algorithm)
#endif
        {
            var hashAlgorithm = AsymmetricKeyAlgorithmProviderFactory.GetHashAlgorithmEnum(algorithm);
            return HashAlgorithmProvider.CreateHashAlgorithm(hashAlgorithm);
        }
    }
}
