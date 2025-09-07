using System.Security.Cryptography;

namespace Sasl.ScramSha256;

public class ClientFinalMessage
{
    private const string ClientKey = "Client Key";

    private const string ServerKey = "Server Key";

    public string ChannelBinding { get; set; } = string.Empty;

    public byte[] ChannelBindingRaw
    {
        get => Convert.FromBase64String(this.ChannelBinding);
        set => this.ChannelBinding = Convert.ToBase64String(value);
    }

    public string ClientProof { get; set; } = string.Empty;

    public byte[] ClientProofRaw
    {
        get => Convert.FromBase64String(this.ClientProof);
        set => this.ClientProof = Convert.ToBase64String(value);
    }

    public Dictionary<string, string>? Extensions { get; set; }

    public string Nonce { get; set; } = string.Empty;

    public void SetProof(
        ClientFirstMessage request,
        ServerFirstMessage challenge,
        string password)
    {
        this.Nonce = challenge.Nonce;

        var hashedPassword = this.Hi(
            password.GetBytes(),
            challenge.SaltRaw,
            challenge.IterationCount);

        using var h1 = this.CreateHmac(hashedPassword);
        var clientKey = h1.ComputeHash(ClientKey.GetBytes());

        using var hash = this.CreateHash();
        var storedkey = hash.ComputeHash(clientKey);

        var authMessage =
            request.ToBareString()
            + ","
            + challenge.ToQueryString()
            + ","
            + this.ToQueryStringWithoutProof();

        using var h2 = this.CreateHmac(storedkey);
        var clientSignature = h2.ComputeHash(authMessage.GetBytes());

        var proof = clientKey.Xor(clientSignature).ToArray();
        this.ClientProofRaw = proof;
    }

    public string ToQueryString()
    {
        var builder = new List<string>
        {
            this.ToQueryStringWithoutProof(),
            $"p={this.ClientProof}",
        };

        return string.Join(",", builder);
    }

    public string ToQueryStringWithoutProof()
    {
        var builder = new List<string>
        {
            $"c={this.ChannelBinding}",
            $"r={this.Nonce}",
        };

        if (this.Extensions is not null)
        {
            foreach (var ext in this.Extensions)
            {
                builder.Add($"{ext.Key}={ext.Value}");
            }
        }

        return string.Join(",", builder);
    }

    public bool Verify(
        ClientFirstMessage request,
        ServerFirstMessage challenge,
        ServerFinalMessage result,
        string password)
    {
        var hashedPassword = this.Hi(
            password.GetBytes(),
            challenge.SaltRaw,
            challenge.IterationCount);

        using var h1 = this.CreateHmac(hashedPassword);
        var serverKey = h1.ComputeHash(ServerKey.GetBytes());

        var authMessage =
            request.ToBareString()
            + ","
            + challenge.ToQueryString()
            + ","
            + this.ToQueryStringWithoutProof();

        using var h2 = this.CreateHmac(serverKey);
        var serverSignature = h2.ComputeHash(authMessage.GetBytes());

        return result.ServerSignature.Zip(serverSignature, (a, b) => a == b).All(r => r);
    }

    private HashAlgorithm CreateHash()
    {
        return SHA256.Create();
    }

    private HMAC CreateHmac(byte[] key)
    {
        return new HMACSHA256(key);
    }

    private byte[] Hi(byte[] msg, byte[] salt, uint count)
    {
        using var h = this.CreateHmac(msg);

        var input = salt.Concat(1u.ToBigEndian()).ToArray();
        input = h.ComputeHash(input);

        var output = input;

        for (var i = 1; i < count; i++)
        {
            input = h.ComputeHash(input);
            output = [.. output.Xor(input)];
        }

        return output;
    }
}
