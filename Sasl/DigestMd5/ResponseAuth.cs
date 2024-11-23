namespace Sasl.DigestMd5;

public class ResponseAuth
{
    public string? RspAuth { get; set; }

    public static ResponseAuth Parse(QueryReader reader)
    {
        var auth = new ResponseAuth();

        while (reader.Any())
        {
            var key = reader.ReadKey();
            auth.RspAuth = key.ToLowerInvariant() switch
            {
                "rspauth" => reader.ReadText(),
                _ => throw new NotSupportedException($"Not suppoted query key: {key}"),
            };
            reader.NextKey();
        }

        return auth;
    }
}
