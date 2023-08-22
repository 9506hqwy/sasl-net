namespace Sasl;

internal static class UshortExtension
{
    internal static byte[] ToBigEndian(this ushort self)
    {
        return BitConverter.GetBytes(self).Reverse().ToArray();
    }
}
