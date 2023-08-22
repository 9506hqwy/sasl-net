namespace Sasl.DigestMd5;

using System.Security.Cryptography;

public class Encryptor : IDisposable
{
    private readonly SymmetricAlgorithm algorithm;

    private readonly Signer signer;

    private bool disposed;

    private uint seqNum;

    public Encryptor(SymmetricAlgorithm algorithm, Signer signer)
    {
        this.algorithm = algorithm;
        this.signer = signer;
        this.disposed = false;
        this.seqNum = 0;
    }

    public void Dispose()
    {
        this.Dispose(true);
        GC.SuppressFinalize(this);
    }

    public byte[] Encrypt(byte[] msg)
    {
        using var mem = new MemoryStream();

        mem.Write(this.Cipher(msg));
        mem.Write(Constants.Version.ToBigEndian());
        mem.Write(this.seqNum.ToBigEndian());

        this.seqNum += 1;

        mem.Seek(0, SeekOrigin.Begin);
        return mem.ToArray();
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

    private byte[] Cipher(byte[] msg)
    {
        const int MacSize = Constants.SealingHMacSize;

        var paddingBytes = this.Padding(msg, MacSize);

        using var mem = new MemoryStream();
        using var cipher = this.algorithm.CreateEncryptor();
        using var cryptor = new CryptoStream(mem, cipher, CryptoStreamMode.Write);

        cryptor.Write(msg, 0, msg.Length);
        cryptor.Write(paddingBytes, 0, paddingBytes.Length);
        cryptor.Write(this.signer.Hash(msg, this.seqNum), 0, MacSize);
        cryptor.Flush();

        mem.Seek(0, SeekOrigin.Begin);
        return mem.ToArray();
    }

    private byte[] Padding(byte[] msg, int macSize)
    {
        var blockSize = this.algorithm.FeedbackSize;

        var paddingSize = blockSize - ((msg.Length + macSize) % blockSize);
        var paddingByte = BitConverter.GetBytes(paddingSize).First();
        return Enumerable.Repeat(paddingByte, paddingSize).ToArray();
    }
}
