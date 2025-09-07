using System.Security.Cryptography;
using static Sasl.DigestMd5.Constants;

namespace Sasl.DigestMd5;

public class DigestResponse
{
    public string? AuthzId { get; set; }

    public string? Charset { get; set; }

    public string? Cipher { get; set; }

    public string? Cnonce { get; set; }

    public string? DigestUri { get; set; }

    public uint? MaxBuf { get; set; }

    public string? Nc { get; set; }

    public string? Nonce { get; set; }

    public string? Qop { get; set; }

    public string? Realm { get; set; }

    public string? Response { get; set; }

    public Dictionary<string, string>? Tokens { get; set; }

    public string? Username { get; set; }

    internal int SealingHashSize => this.Cipher switch
    {
        CipherRc440 => 5,
        CipherRc456 => 7,
        CipherRc4 => 16,
        CipherDes => 16,
        Cipher3Des => 16,
        _ => throw new NotSupportedException($"Not supported cipher: {this.Cipher}"),
    };

    public static DigestResponse CreateFrom(DigestChallenge challenge, string digestUri)
    {
        var response = new DigestResponse
        {
            Charset = challenge.Charset,
            Cnonce = Guid.NewGuid().ToString(),
            DigestUri = digestUri,
            MaxBuf = challenge.MaxBuf,
            Nc = NonceCountInit,
            Nonce = challenge.Nonce,
            Realm = challenge.Realm,
        };

        if (challenge.Cipher is not null && challenge.Cipher.Any(c => c != string.Empty))
        {
            if (!SetCipher(response, challenge, CipherRc4)
                && !SetCipher(response, challenge, Cipher3Des)
                && !SetCipher(response, challenge, CipherDes)
                && !SetCipher(response, challenge, CipherRc456)
                && !SetCipher(response, challenge, CipherRc440))
            {
                var ciphers = string.Join(",", challenge.Cipher);
                throw new NotSupportedException($"Not supported ciphers: {ciphers}");
            }
        }

        if (challenge.Qop is not null && challenge.Qop.Any(q => q != string.Empty))
        {
            if (!SetQop(response, challenge, QopAuthConf)
                && !SetQop(response, challenge, QopAuthInt)
                && !SetQop(response, challenge, QopAuth))
            {
                var qops = string.Join(",", challenge.Qop);
                throw new NotSupportedException($"Not supported qop: {qops}");
            }
        }

        return response;
    }

    public byte[] GetClientSealingKey(string password)
    {
        return this.ComputeKey(password, this.SealingHashSize, ClientSealingKey);
    }

    public byte[] GetClientSigningKey(string password)
    {
        return this.ComputeKey(password, 16, ClientSigningKey);
    }

    public byte[] GetServerSealingKey(string password)
    {
        return this.ComputeKey(password, this.SealingHashSize, ServerSealingKey);
    }

    public byte[] GetServerSigningKey(string password)
    {
        return this.ComputeKey(password, 16, ServerSigningKey);
    }

    public Decryptor CreateDecryptor(Mode mode, string password)
    {
        if (this.Cipher != Cipher3Des)
        {
            throw new NotSupportedException($"Not supported cipher: {this.Cipher}");
        }

        var sealingKey = mode switch
        {
            Mode.Client => this.GetServerSealingKey(password),
            Mode.Server => this.GetClientSealingKey(password),
            _ => throw new InvalidProgramException(),
        };

        var signingKey = mode switch
        {
            Mode.Client => this.GetServerSigningKey(password),
            Mode.Server => this.GetClientSigningKey(password),
            _ => throw new InvalidProgramException(),
        };

        var algorithm = this.CreateAlgorithm(sealingKey);
        var signer = new Signer(signingKey);

        return new Decryptor(algorithm, signer);
    }

    public Encryptor CreateEncryptor(Mode mode, string password)
    {
        if (this.Cipher != Cipher3Des)
        {
            throw new NotSupportedException($"Not supported cipher: {this.Cipher}");
        }

        var sealingKey = mode switch
        {
            Mode.Client => this.GetClientSealingKey(password),
            Mode.Server => this.GetServerSealingKey(password),
            _ => throw new InvalidProgramException(),
        };

        var signingKey = mode switch
        {
            Mode.Client => this.GetClientSigningKey(password),
            Mode.Server => this.GetServerSigningKey(password),
            _ => throw new InvalidProgramException(),
        };

        var algorithm = this.CreateAlgorithm(sealingKey);
        var signer = new Signer(signingKey);

        return new Encryptor(algorithm, signer);
    }

    public void SetResponse(string username, string password)
    {
        this.Username = username;
        this.Response = this.ComputeResponse(password, Method).ToHex();
    }

    public string ToQueryString()
    {
        var builder = new List<string>();

        if (this.Username is not null)
        {
            builder.Add($"username=\"{this.Username}\"");
        }

        if (this.Realm is not null)
        {
            builder.Add($"realm=\"{this.Realm}\"");
        }

        if (this.Nonce is not null)
        {
            builder.Add($"nonce=\"{this.Nonce}\"");
        }

        if (this.Cnonce is not null)
        {
            builder.Add($"cnonce=\"{this.Cnonce}\"");
        }

        if (this.Nc is not null)
        {
            builder.Add($"nc={this.Nc}");
        }

        if (this.Qop is not null)
        {
            builder.Add($"qop={this.Qop}");
        }

        if (this.DigestUri is not null)
        {
            builder.Add($"digest-uri=\"{this.DigestUri}\"");
        }

        if (this.Response is not null)
        {
            builder.Add($"response={this.Response}");
        }

        if (this.MaxBuf is not null)
        {
            builder.Add($"maxbuf={this.MaxBuf}");
        }

        if (this.Charset is not null)
        {
            builder.Add($"charset={this.Charset}");
        }

        if (this.Cipher is not null)
        {
            builder.Add($"cipher={this.Cipher}");
        }

        if (this.AuthzId is not null)
        {
            builder.Add($"authzid=\"{this.AuthzId}\"");
        }

        if (this.Tokens is not null)
        {
            // TODO: add `auth-param` support.
        }

        return string.Join(",", builder);
    }

    public bool Verify(ResponseAuth response, string password)
    {
        var auth = this.ComputeResponse(password).ToHex();
        return response.RspAuth == auth;
    }

    private static byte AddOddParity(byte value)
    {
        var parity = (value.Count1() % 2) == 0 ? 0x01 : 0x00;
        return (byte)(value | parity);
    }

    private static byte[] CreateSubKey(byte[] key)
    {
        // 7bit に odd parity を追加して 8bit に変換する。
        // 7bit x 8 のビット列を入力して 8bit x 8 のビット列で返却する。
        // ビット列)
        // input :         01234560123456012345601234560123456012345601234560123456
        // output: 0123456x0123456x0123456x0123456x0123456x0123456x0123456x0123456x
        // x は odd parity
        var tmpBytes = new byte[8];
        Array.Copy(key, tmpBytes, key.Length);
        var input = tmpBytes.ToUlong() >> 8;

        var output = new byte[8];

        for (var i = 7; i >= 0; i--)
        {
            var value = (byte)((input & 0xFF) << 1);
            output[i] = AddOddParity(value);

            // Next 7bit.
            input >>= 7;
        }

        return output;
    }

    private static bool SetCipher(DigestResponse response, DigestChallenge challenge, string cipher)
    {
        var algorithm = challenge.Cipher.FirstOrDefault(c => c == cipher);
        if (algorithm is not null)
        {
            response.Cipher = cipher;
        }

        return response.Cipher is not null;
    }

    private static bool SetQop(DigestResponse response, DigestChallenge challenge, string qop)
    {
        var algorithm = challenge.Qop.FirstOrDefault(q => q == qop);
        if (algorithm is not null)
        {
            response.Qop = qop;
        }

        return response.Qop is not null;
    }

    private byte[] ComputeKey(string password, int size, string magic)
    {
        using var mem = new MemoryStream();

        mem.Write([.. this.ComputeHA1(password).Take(size)]);
        mem.Write(magic);

        return mem.ComputeMd5();
    }

    private byte[] ComputeHA1(string password)
    {
        using var mem = new MemoryStream();

        mem.Write(this.ComputeSecret(password));
        mem.Write(":");
        mem.Write(this.Nonce);
        mem.Write(":");
        mem.Write(this.Cnonce);
        if (this.AuthzId is not null)
        {
            mem.Write(":");
            mem.Write(this.AuthzId);
        }

        return mem.ComputeMd5();
    }

    private byte[] ComputeHA2(string? method = null)
    {
        using var mem = new MemoryStream();

        if (method is not null)
        {
            mem.Write(method);
        }

        mem.Write(":");
        mem.Write(this.DigestUri);
        if (this.Qop is QopAuthInt or QopAuthConf)
        {
            mem.Write(":");
            mem.Write(EmptyHash);
        }

        return mem.ComputeMd5();
    }

    private byte[] ComputeResponse(string password, string? method = null)
    {
        using var mem = new MemoryStream();

        mem.Write(this.ComputeHA1(password).ToHex());
        mem.Write(":");
        mem.Write(this.Nonce);
        mem.Write(":");
        mem.Write(this.Nc);
        mem.Write(":");
        mem.Write(this.Cnonce);
        mem.Write(":");
        mem.Write(this.Qop);
        mem.Write(":");
        mem.Write(this.ComputeHA2(method).ToHex());

        return mem.ComputeMd5();
    }

    private byte[] ComputeSecret(string password)
    {
        if (this.Username is null)
        {
            throw new InvalidOperationException($"Need to execute `{nameof(this.SetResponse)}` method");
        }

        using var mem = new MemoryStream();

        mem.Write(this.Username);
        mem.Write(":");
        mem.Write(this.Realm);
        mem.Write(":");
        mem.Write(password);

        return mem.ComputeMd5();
    }

    private SymmetricAlgorithm CreateAlgorithm(byte[] key)
    {
        var key1 = CreateSubKey([.. key.Take(7)]);
        var key2 = CreateSubKey([.. key.Skip(7).Take(7)]);

        var des = TripleDES.Create();
        des.Mode = CipherMode.CBC;
        des.Padding = PaddingMode.None;
        des.Key = [.. key1, .. key2, .. key1];
        des.IV = [.. key.Skip(8)];

        return des;
    }
}
