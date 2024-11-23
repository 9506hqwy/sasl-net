namespace Sasl;

public class ServerFinalMessage
{
    public string? Error { get; set; }

    public Dictionary<string, string>? Extensions { get; set; }

    public byte[] ServerSignature
    {
        get => Convert.FromBase64String(this.Verifier);
        set => this.Verifier = Convert.ToBase64String(value);
    }

    public string? Verifier { get; set; }

    public static ServerFinalMessage Parse(QueryReader reader)
    {
        var message = new ServerFinalMessage();

        while (reader.Any())
        {
            var key = reader.ReadKey();
            switch (key.ToLowerInvariant())
            {
                case "e":
                    message.Error = reader.ReadText();
                    break;
                case "v":
                    message.Verifier = reader.ReadText();
                    break;
                default:
                    message.Extensions ??= [];
                    message.Extensions[key] = reader.ReadText();
                    break;
            }

            reader.NextKey();
        }

        return message;
    }
}
