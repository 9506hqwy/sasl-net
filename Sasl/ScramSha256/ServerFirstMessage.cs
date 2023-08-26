namespace Sasl.ScramSha256;

public class ServerFirstMessage
{
    public Dictionary<string, string>? Extensions { get; set; }

    public uint IterationCount { get; set; }

    public string Nonce { get; set; } = string.Empty;

    public string? ReservedMext { get; set; }

    public string Salt { get; set; } = string.Empty;

    public byte[] SaltRaw
    {
        get => Convert.FromBase64String(this.Salt);
        set => this.Salt = Convert.ToBase64String(value);
    }

    public static ServerFirstMessage Parse(QueryReader reader)
    {
        var message = new ServerFirstMessage();

        while (reader.Any())
        {
            var key = reader.ReadKey();
            switch (key.ToLowerInvariant())
            {
                case "i":
                    message.IterationCount = reader.ReadUint();
                    break;
                case "r":
                    message.Nonce = reader.ReadText();
                    break;
                case "m":
                    message.ReservedMext = reader.ReadText();
                    break;
                case "s":
                    message.Salt = reader.ReadText();
                    break;
                default:
                    message.Extensions ??= new Dictionary<string, string>();
                    message.Extensions[key] = reader.ReadText();
                    break;
            }

            reader.NextKey();
        }

        return message;
    }

    public string ToQueryString()
    {
        var builder = new List<string>();

        if (this.ReservedMext is not null)
        {
            builder.Add($"m={this.ReservedMext}");
        }

        builder.Add($"r={this.Nonce}");

        builder.Add($"s={this.Salt}");

        builder.Add($"i={this.IterationCount}");

        if (this.Extensions is not null)
        {
            foreach (var ext in this.Extensions)
            {
                builder.Add($"{ext.Key}={ext.Value}");
            }
        }

        return string.Join(",", builder);
    }
}
