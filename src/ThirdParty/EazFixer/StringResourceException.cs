using System;

namespace EazFixer
{
    /// <summary>A string editor failure whose diagnostic is safe to display without target details.</summary>
    public sealed class StringResourceException : Exception
    {
        internal StringResourceException(string message) : base(message) { }
    }
}
