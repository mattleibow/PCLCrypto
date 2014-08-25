//-----------------------------------------------------------------------
// <copyright file="SymmetricKeyAlgorithmProviderPlatform.cs" company="Andrew Arnott">
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
    using Java.Security;
    using Javax.Crypto;
    using Validation;

    /// <summary>
    /// A .NET Framework implementation of the SymmetricKeyAlgorithmProvider interface.
    /// </summary>
    internal class SymmetricKeyAlgorithmProviderPlatform : SymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// The algorithm used by this instance.
        /// </summary>
        private readonly SymmetricAlgorithm algorithm;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProviderPlatform"/> class.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>e
        internal SymmetricKeyAlgorithmProviderPlatform(SymmetricAlgorithm algorithm)
        {
            this.algorithm = algorithm;
        }

        /// <inheritdoc />
        public override int BlockLength
        {
            get
            {
                try
                {
                    using (var platform = Cipher.GetInstance(this.algorithm.GetName().GetString()))
                    {
                        return GetBlockSize(this.algorithm, platform);
                    }
                }
                catch (NoSuchAlgorithmException ex)
                {
                    throw new NotSupportedException("Algorithm not supported.", ex);
                }
            }
        }

        /// <summary>
        /// Gets the algorithm supported by this instance.
        /// </summary>
        internal SymmetricAlgorithm Algorithm
        {
            get { return this.algorithm; }
        }

        /// <summary>
        /// Creates a symmetric key.
        /// </summary>
        /// <param name="keyMaterial">
        /// Data used to generate the key. You can call the GenerateRandom method to
        /// create random key material.
        /// </param>
        /// <returns>Symmetric key.</returns>
        public override ICryptographicKey CreateSymmetricKey(byte[] keyMaterial)
        {
            Requires.NotNullOrEmpty(keyMaterial, "keyMaterial");

            return new SymmetricCryptographicKey(this.Algorithm, keyMaterial);
        }

        /// <summary>
        /// Gets the block size (in bytes) for the specified algorithm.
        /// </summary>
        /// <param name="pclAlgorithm">The PCL algorithm.</param>
        /// <param name="algorithm">The platform-specific algorithm.</param>
        /// <returns>The block size (in bytes).</returns>
        internal static int GetBlockSize(SymmetricAlgorithm pclAlgorithm, Cipher algorithm)
        {
            Requires.NotNull(algorithm, "algorithm");

            if (algorithm.BlockSize == 0 && pclAlgorithm.GetName() == SymmetricAlgorithmName.Rc4)
            {
                // This is a streaming cipher without a block size. Return 1 to emulate behavior of other platforms.
                return 1;
            }

            return algorithm.BlockSize;
        }
    }
}
