namespace Sasl.ScramSha256;

using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Authentication.ExtendedProtection;

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

    public byte[] GetChannelBinding(SslStream stream)
    {
        // Acquire `SecPkgContext_Bindings` using `QueryContextAttributesExW`.
        // https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-querycontextattributesw
        using var cbt = this.Gs2BindingFlag switch
        {
            // `SECPKG_ATTR_UNIQUE_BINDINGS`
            "p=tls-unique" => stream.TransportContext.GetChannelBinding(ChannelBindingKind.Unique),

            // `SECPKG_ATTR_ENDPOINT_BINDINGS`
            "p=tls-server-end-point" => stream.TransportContext.GetChannelBinding(ChannelBindingKind.Endpoint),

            // other
            _ => null,
        };

        if (cbt is null)
        {
            return Array.Empty<byte>();
        }

        // cbt is `SecPkgContext_Bindings`.
        // `SecPkgContext_Bindings.Bindings` has `SEC_CHANNEL_BINDINGS` + binding data.
        // binding data is start with `tls-unique:` or `tls-server-end-point:`.
        // https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings
        const int bindHeaderSize = 32;
        int dataHeaderSize = this.Gs2BindingFlag switch
        {
            "p=tls-unique" => "tls-unique:".Length,
            "p=tls-server-end-point" => "tls-server-end-point:".Length,
            _ => throw new InvalidProgramException(),
        };

        // `tls-unique` is 12bytes.
        // `tls-server-end-point` is 32bytes.
        var tokens = new byte[cbt.Size - bindHeaderSize - dataHeaderSize];
        Marshal.Copy(cbt.DangerousGetHandle() + bindHeaderSize + dataHeaderSize, tokens, 0, tokens.Length);

        return tokens;
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
