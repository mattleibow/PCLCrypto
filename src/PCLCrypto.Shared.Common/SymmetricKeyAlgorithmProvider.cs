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
    public partial class SymmetricKeyAlgorithmProvider
    {
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
            return new SymmetricKeyAlgorithmProvider(algorithm);
#endif
        }
    }
}
