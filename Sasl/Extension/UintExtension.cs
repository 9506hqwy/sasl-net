namespace Sasl;

internal static class UintExtension
{
    internal static byte[] ToBigEndian(this uint self)
    {
        return BitConverter.GetBytes(self).Reverse().ToArray();
    }
}
