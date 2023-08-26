namespace Sasl;

using System.Text;

internal static class ByteExtension
{
    internal static int Count1(this byte self)
    {
        var sum = 0;

        for (var i = 0; i < 8; i++)
        {
            sum += (self >> i) & 0x01;
        }

        return sum;
    }

    internal static string GetString(this byte[] self)
    {
        return Encoding.UTF8.GetString(self);
    }

    internal static string ToHex(this byte[] self)
    {
        return BitConverter.ToString(self)
            .Replace("-", string.Empty)
            .ToLowerInvariant();
    }

    internal static uint ToUint(this IEnumerable<byte> self)
    {
        var bytes = self.Reverse().ToArray();
        return BitConverter.ToUInt32(bytes, 0);
    }

    internal static ulong ToUlong(this IEnumerable<byte> self)
    {
        var bytes = self.Reverse().ToArray();
        return BitConverter.ToUInt64(bytes, 0);
    }

    internal static ushort ToUshort(this IEnumerable<byte> self)
    {
        var bytes = self.Reverse().ToArray();
        return BitConverter.ToUInt16(bytes, 0);
    }

    internal static IEnumerable<byte> Xor(this IEnumerable<byte> self, IEnumerable<byte> value)
    {
        return self.Zip(value, (a, b) => (byte)(a ^ b));
    }
}
