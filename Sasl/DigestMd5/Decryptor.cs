namespace Sasl.DigestMd5;

using System.Security.Cryptography;

public class Decryptor(SymmetricAlgorithm algorithm, Signer signer) : IDisposable
{
    private readonly SymmetricAlgorithm algorithm = algorithm;

    private readonly Signer signer = signer;

    private bool disposed = false;

    private uint seqNum = 0;

    public byte[] Decrypt(byte[] msg)
    {
        var version = msg.Skip(msg.Length - 6).Take(2).ToUshort();
        if (version != Constants.Version)
        {
            throw new InvalidOperationException($"Invalid version: {version}");
        }

        var seqNum = msg.Skip(msg.Length - 4).Take(4).ToUint();
        return seqNum != this.seqNum
            ? throw new InvalidOperationException($"Invalid sequence number: {seqNum}({this.seqNum})")
            : this.Plain(msg.Take(msg.Length - 6).ToArray());
    }

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (this.disposed)
        {
            return;
        }

        if (disposing)
        {
            this.algorithm.Dispose();
        }

        this.disposed = true;
    }

    private byte[] Plain(byte[] msg)
    {
        const int MacSize = Constants.SealingHMacSize;

        using var mem = new MemoryStream();
        mem.Write(msg);

        _ = mem.Seek(0, SeekOrigin.Begin);
        using var cipher = this.algorithm.CreateDecryptor();
        using var cryptor = new CryptoStream(mem, cipher, CryptoStreamMode.Read);

        var plain = new byte[msg.Length];
        var plainSize = cryptor.Read(plain, 0, plain.Length);
        plain = plain.Take(plainSize).ToArray();

        var paddingSize = (int)plain[plain.Length - (MacSize + 1)];

        var msgBytes = plain.Take(plainSize - paddingSize - MacSize).ToArray();
        var hashBytes = plain.Skip(plainSize - MacSize).ToArray();

        var hash = this.signer.Hash(msgBytes, this.seqNum).Take(MacSize).ToArray();
        if (hashBytes.Zip(hash, (a, b) => a != b).Any(b => b))
        {
            throw new InvalidOperationException($"Not match HMAC");
        }

        this.seqNum += 1;

        return msgBytes;
    }
}
