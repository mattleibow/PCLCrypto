//-----------------------------------------------------------------------
// <copyright file="ReferenceAssemblyException.cs" company="Andrew Arnott">
//     Copyright (c) Andrew Arnott. All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

namespace PCLCrypto
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Text;

    /// <summary>
    /// An exception thrown at runtime by the PCL facade assembly when
    /// a platform assembly should be referenced.
    /// </summary>
    internal class ReferenceAssemblyException : NotImplementedException
    {
    }
}
