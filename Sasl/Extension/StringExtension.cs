using System.Text;

namespace Sasl;

internal static class StringExtension
{
    internal static byte[] GetBytes(this string self)
    {
        return Encoding.UTF8.GetBytes(self);
    }
}
