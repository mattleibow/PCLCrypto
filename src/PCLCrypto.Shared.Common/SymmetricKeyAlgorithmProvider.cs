//-----------------------------------------------------------------------
// <copyright file="SymmetricKeyAlgorithmProvider.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// Represents a provider of symmetric key algorithms.
    /// </summary>
    /// <content>
    /// Contains the static members of the class.
    /// </content>
    public abstract class SymmetricKeyAlgorithmProvider
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyAlgorithmProvider"/> class.
        /// </summary>
        /// <remarks>
        /// This constructor is internal because external derivation is not an intended design.
        /// </remarks>
        internal SymmetricKeyAlgorithmProvider()
        {
        }

        /// <summary>
        /// Gets the size, in bytes, of the cipher block for the open algorithm.
        /// </summary>
        /// <value>Block size.</value>
        public abstract int BlockLength
        {
            get;
        }

        /// <summary>
        /// Returns a crypto key management for a specified algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns>An instance of <see cref="SymmetricKeyAlgorithmProvider"/>.</returns>
        public static SymmetricKeyAlgorithmProvider OpenAlgorithm(SymmetricAlgorithm algorithm)
        {
#if PCL
            throw new NotImplementedException("Not implemented in reference assembly.");
#else
            return new SymmetricKeyAlgorithmProviderPlatform(algorithm);
#endif
        }

        /// <summary>
        /// Creates a symmetric key.
        /// </summary>
        /// <param name="keyMaterial">
        /// Data used to generate the key. You can call the GenerateRandom method to
        /// create random key material.
        /// </param>
        /// <returns>Symmetric key.</returns>
        public abstract ICryptographicKey CreateSymmetricKey(byte[] keyMaterial);
    }
}
