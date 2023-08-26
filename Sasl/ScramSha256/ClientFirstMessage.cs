namespace Sasl.ScramSha256;

public class ClientFirstMessage
{
    public string? AuthzId { get; set; }

    public string Cnonce { get; set; } = string.Empty;

    public Dictionary<string, string>? Extensions { get; set; }

    public string Gs2Binding => this.ToGs2Binding() + ",";

    public string Gs2BindingFlag { get; set; } = "n";

    public string? ReservedMext { get; set; }

    public string Username { get; set; } = string.Empty;

    public static ClientFirstMessage CreateNoBinding(string username)
    {
        return new ClientFirstMessage
        {
            Cnonce = Guid.NewGuid().ToString(),
            Username = username,
        };
    }

    public string ToBareString()
    {
        var builder = new List<string>();

        if (this.ReservedMext is not null)
        {
            builder.Add($"m={this.ReservedMext}");
        }

        builder.Add($"n={this.Username}");

        builder.Add($"r={this.Cnonce}");

        if (this.Extensions is not null)
        {
            foreach (var ext in this.Extensions)
            {
                builder.Add($"{ext.Key}={ext.Value}");
            }
        }

        return string.Join(",", builder);
    }

    public string ToGs2Binding()
    {
        var builder = new List<string>
        {
            this.Gs2BindingFlag,
            this.AuthzId is null ? string.Empty : $"a={this.AuthzId}",
        };

        return string.Join(",", builder);
    }

    public string ToQueryString()
    {
        var builder = new List<string>
        {
            this.ToGs2Binding(),
            this.ToBareString(),
        };

        return string.Join(",", builder);
    }
}
