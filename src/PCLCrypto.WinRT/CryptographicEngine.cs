//-----------------------------------------------------------------------
// <copyright file="CryptographicEngine.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using Validation;
    using Windows.Storage.Streams;
    using Platform = Windows.Security.Cryptography;

    /// <summary>
    /// A WinRT implementation of CryptographicEngine.
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
            if (keyClass.SymmetricAlgorithmProvider != null)
            {
                bool paddingInUse = keyClass.SymmetricAlgorithmProvider.Algorithm.GetPadding() != SymmetricAlgorithmPadding.None;
                Requires.Argument(paddingInUse || IsValidInputSize(keyClass, data.Length), "data", "Length does not a multiple of block size and no padding is selected.");
            }

            try
            {
                return Platform.Core.CryptographicEngine.Encrypt(
                    keyClass.Key,
                    data.ToBuffer(),
                    iv.ToBuffer()).ToArray();
            }
            catch (NotImplementedException ex)
            {
                throw new NotSupportedException(ex.Message, ex);
            }
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

            var ownKey = (CryptographicKey)key;
            return GetTransformForBlockMode(ownKey, iv, true);
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
            if (keyClass.SymmetricAlgorithmProvider != null)
            {
                Requires.Argument(IsValidInputSize(keyClass, data.Length), "data", "Length does not a multiple of block size and no padding is selected.");
            }

            return Platform.Core.CryptographicEngine.Decrypt(
                keyClass.Key,
                data.ToBuffer(),
                iv.ToBuffer()).ToArray();
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

            var ownKey = (CryptographicKey)key;
            return GetTransformForBlockMode(ownKey, iv, false);
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

            return Platform.Core.CryptographicEngine.Sign(
                ExtractPlatformKey(key),
                data.ToBuffer()).ToArray();
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

            var keyClass = (CryptographicKey)key;
            return Platform.Core.CryptographicEngine.SignHashedData(
                keyClass.Key,
                data.ToBuffer()).ToArray();
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

            return Platform.Core.CryptographicEngine.VerifySignature(
                ExtractPlatformKey(key),
                data.ToBuffer(),
                signature.ToBuffer());
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
            Requires.NotNull(signature, "signature");

            var keyClass = (CryptographicKey)key;
            return Platform.Core.CryptographicEngine.VerifySignatureWithHashInput(
                keyClass.Key,
                data.ToBuffer(),
                signature.ToBuffer());
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
            var platformKey = ((CryptographicKey)key).Key;
            var platformParameters = ((KeyDerivationParameters)parameters).Parameters;
            return Platform.Core.CryptographicEngine.DeriveKeyMaterial(platformKey, platformParameters, (uint)desiredKeySize).ToArray();
        }

        /// <summary>
        /// Extracts the platform-specific key from the PCL version.
        /// </summary>
        /// <param name="key">The PCL key.</param>
        /// <returns>The platform-specific key.</returns>
        private static Platform.Core.CryptographicKey ExtractPlatformKey(ICryptographicKey key)
        {
            Requires.NotNull(key, "key");
            var platformKey = ((CryptographicKey)key).Key;
            return platformKey;
        }

        /// <summary>
        /// Gets an <see cref="ICryptoTransform"/> instance to use for a given cryptographic key.
        /// </summary>
        /// <param name="key">The cryptographic key to use in the transform.</param>
        /// <param name="iv">The initialization vector to use, when applicable.</param>
        /// <param name="encrypting"><c>true</c> if encrypting; <c>false</c> if decrypting.</param>
        /// <returns>An instance of <see cref="ICryptoTransform"/>.</returns>
        private static ICryptoTransform GetTransformForBlockMode(CryptographicKey key, byte[] iv, bool encrypting)
        {
            Requires.NotNull(key, "key");

            if (key.SymmetricAlgorithmProvider != null && key.SymmetricAlgorithmProvider.Algorithm.IsBlockCipher())
            {
                switch (key.SymmetricAlgorithmProvider.Algorithm.GetMode())
                {
                    case SymmetricAlgorithmMode.Cbc:
                        var cbcOperation = encrypting
                            ? new Func<IBuffer, IBuffer, IBuffer>((input, iv2) => Platform.Core.CryptographicEngine.Encrypt(key.Key, input, iv2))
                            : new Func<IBuffer, IBuffer, IBuffer>((input, iv2) => Platform.Core.CryptographicEngine.Decrypt(key.Key, input, iv2));
                        return new CbcModeTransform(cbcOperation, iv, key.SymmetricAlgorithmProvider.BlockLength);
                    case SymmetricAlgorithmMode.Ecb:
                    case SymmetricAlgorithmMode.Ccm:
                    case SymmetricAlgorithmMode.Gcm:
                    default:
                        break;
                }
            }

            var bufferOperation = encrypting
               ? new Func<byte[], byte[]>(input => Platform.Core.CryptographicEngine.Encrypt(key.Key, input.ToBuffer(), iv.ToBuffer()).ToArray())
               : new Func<byte[], byte[]>(input => Platform.Core.CryptographicEngine.Decrypt(key.Key, input.ToBuffer(), iv.ToBuffer()).ToArray());
            return new BufferingCryptoTransform(bufferOperation);
        }

        /// <summary>
        /// Checks whether the given length is a valid one for an input buffer to the symmetric algorithm.
        /// </summary>
        /// <param name="key">The key.</param>
        /// <param name="lengthInBytes">The length of the input buffer in bytes.</param>
        /// <returns>
        ///   <c>true</c> if the size is allowed; <c>false</c> otherwise.
        /// </returns>
        private static bool IsValidInputSize(CryptographicKey key, int lengthInBytes)
        {
            Requires.NotNull(key, "key");
            return lengthInBytes > 0 && lengthInBytes % key.SymmetricAlgorithmProvider.BlockLength == 0;
        }

        /// <summary>
        /// A crypto transform that can do no work incrementally, but does it all at the end.
        /// </summary>
        /// <remarks>
        /// Sadly, this is necessary because WinRT offers no incremental encryption/decryption
        /// APIs.
        /// </remarks>
        private class BufferingCryptoTransform : ICryptoTransform
        {
            /// <summary>
            /// The buffering stream.
            /// </summary>
            private readonly MemoryStream bufferingStream = new MemoryStream();

            /// <summary>
            /// The transform to run when all bytes are collected.
            /// </summary>
            private readonly Func<byte[], byte[]> transform;

            /// <summary>
            /// Initializes a new instance of the <see cref="BufferingCryptoTransform"/> class.
            /// </summary>
            /// <param name="transform">The transform to run when all bytes are collected.</param>
            internal BufferingCryptoTransform(Func<byte[], byte[]> transform)
            {
                Requires.NotNull(transform, "transform");
                this.transform = transform;
            }

            /// <inheritdoc />
            public bool CanReuseTransform
            {
                get { return false; }
            }

            /// <inheritdoc />
            public bool CanTransformMultipleBlocks
            {
                get { return true; }
            }

            /// <inheritdoc />
            public int InputBlockSize
            {
                get { return 1; }
            }

            /// <inheritdoc />
            public int OutputBlockSize
            {
                get { return 1; }
            }

            /// <inheritdoc />
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                this.bufferingStream.Write(inputBuffer, inputOffset, inputCount);
                return 0;
            }

            /// <inheritdoc />
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                this.bufferingStream.Write(inputBuffer, inputOffset, inputCount);
                return this.transform(this.bufferingStream.ToArray());
            }

            /// <inheritdoc />
            public void Dispose()
            {
                this.bufferingStream.Dispose();
            }
        }

        /// <summary>
        /// Enables streaming crypto operations for CBC block modes.
        /// </summary>
        /// <remarks>
        /// WinRT lacks streaming encryption/decryption support.
        /// For certain block modes we can simulate the behavior. CBC is one of them.
        /// </remarks>
        private class CbcModeTransform : ICryptoTransform
        {
            /// <summary>
            /// The cipher function to invoke (encrypt or decrypt). First arg is input buffer, second arg is IV.
            /// </summary>
            private readonly Func<IBuffer, IBuffer, IBuffer> inputIVFunc;

            /// <summary>
            /// The block length in bytes.
            /// </summary>
            private readonly int blockLength;

            /// <summary>
            /// The initialization vector to pass to the next execution of the block.
            /// </summary>
            private IBuffer iv;

            /// <summary>
            /// Initializes a new instance of the <see cref="CbcModeTransform"/> class.
            /// </summary>
            /// <param name="inputIVFunc">The cipher function to invoke (encrypt or decrypt). First arg is input buffer, second arg is IV.</param>
            /// <param name="iv">The initialization vector.</param>
            /// <param name="blockLengthInBytes">The block length in bytes.</param>
            internal CbcModeTransform(Func<IBuffer, IBuffer, IBuffer> inputIVFunc, byte[] iv, int blockLengthInBytes)
            {
                Requires.NotNull(inputIVFunc, "inputIVFunc");

                this.inputIVFunc = inputIVFunc;
                this.iv = iv.ToBuffer();
                this.blockLength = blockLengthInBytes;
            }

            /// <inheritdoc />
            public bool CanReuseTransform
            {
                get { return false; }
            }

            /// <inheritdoc />
            public bool CanTransformMultipleBlocks
            {
                get { return false; }
            }

            /// <inheritdoc />
            public int InputBlockSize
            {
                get { return this.blockLength; }
            }

            /// <inheritdoc />
            public int OutputBlockSize
            {
                get { return this.blockLength; }
            }

            /// <inheritdoc />
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                var ciphertext = this.inputIVFunc(inputBuffer.ToBuffer(), this.iv);

                if (ciphertext.Length == this.blockLength * 2)
                {
                    // We ignore the ciphertext.Length and use inputCount instead because if padding is on,
                    // and if inputCount == blockLength, we might end up with a whole extra block of ciphertext
                    // that we want to drop since this isn't really the last block.
                    var ciphertextArray = ciphertext.ToArray();
                    Array.Resize(ref ciphertextArray, this.blockLength);
                    ciphertext = ciphertextArray.ToBuffer();
                }

                System.Buffer.BlockCopy(ciphertext.ToArray(), 0, outputBuffer, outputOffset, (int)ciphertext.Length);

                // Store off the ciphertext for use as the IV of the next block.
                this.iv = ciphertext;

                return (int)ciphertext.Length;
            }

            /// <inheritdoc />
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (inputCount < inputBuffer.Length || inputOffset > 0)
                {
                    var trimmedBuffer = new byte[inputCount];
                    System.Buffer.BlockCopy(inputBuffer, inputOffset, trimmedBuffer, 0, inputCount);
                    inputBuffer = trimmedBuffer;
                }

                var ciphertext = this.inputIVFunc(inputBuffer.ToBuffer(), this.iv);

                // Null this out to save memory and also to 'break' this so that 
                // future calls after this one will fail.
                this.iv = null;

                return ciphertext.ToArray();
            }

            /// <inheritdoc />
            public void Dispose()
            {
                this.iv = null;
            }
        }
    }
}
