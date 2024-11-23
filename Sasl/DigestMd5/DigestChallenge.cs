namespace Sasl.DigestMd5;

public class DigestChallenge
{
    public string? Algorithm { get; set; }

    public string? Charset { get; set; }

    public string[]? Cipher { get; set; }

    public uint? MaxBuf { get; set; }

    public string? Nonce { get; set; }

    public string[]? Qop { get; set; }

    public string? Realm { get; set; }

    public bool Stale { get; set; }

    public Dictionary<string, string>? Tokens { get; set; }

    public static DigestChallenge Parse(QueryReader reader)
    {
        var challenge = new DigestChallenge();

        while (reader.Any())
        {
            var key = reader.ReadKey();
            switch (key.ToLowerInvariant())
            {
                case "algorithm":
                    challenge.Algorithm = reader.ReadText();
                    break;
                case "charset":
                    challenge.Charset = reader.ReadText();
                    break;
                case "cipher":
                    challenge.Cipher = reader.ReadQList();
                    break;
                case "maxbuf":
                    challenge.MaxBuf = reader.ReadUint();
                    break;
                case "nonce":
                    challenge.Nonce = reader.ReadQText();
                    break;
                case "qop":
                    challenge.Qop = reader.ReadQList();
                    break;
                case "realm":
                    challenge.Realm = reader.ReadQText();
                    break;
                case "stale":
                    challenge.Stale = reader.ReadBoolean(out var _);
                    break;
                default:
                    challenge.Tokens ??= [];

                    // TODO: add `quoted-string` support.
                    challenge.Tokens[key] = reader.ReadText();
                    break;
            }

            reader.NextKey();
        }

        return challenge;
    }
}
