namespace Sasl.DigestMd5;

using System.Security.Cryptography;

public class Signer(byte[] key)
{
    private readonly HMAC hmac = new HMACMD5(key);

    public byte[] Hash(byte[] msg, uint seqNum)
    {
        using var mem = new MemoryStream();

        mem.Write(seqNum.ToBigEndian());
        mem.Write(msg);

        _ = mem.Seek(0, SeekOrigin.Begin);
        return this.hmac.ComputeHash(mem);
    }
}
