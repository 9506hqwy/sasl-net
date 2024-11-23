namespace Sasl;

using System.Security.Cryptography;
using System.Text;

internal static class MemoryStreamExtension
{
    internal static byte[] ComputeMd5(this MemoryStream self)
    {
        _ = self.Seek(0, SeekOrigin.Begin);

        using var md5 = MD5.Create();
        return md5.ComputeHash(self.ToArray());
    }

    internal static void Write(this MemoryStream self, byte[] value)
    {
        self.Write(value, 0, value.Length);
    }

    internal static void Write(this MemoryStream self, string? value)
    {
        if (value is not null)
        {
            // TODO: add `charset` support.
            self.Write(Encoding.UTF8.GetBytes(value));
        }
    }
}
