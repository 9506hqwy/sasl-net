namespace Sasl.DigestMd5;

public class QueryReader
{
    private const char HT = (char)9;
    private const char LF = (char)10;
    private const char CR = (char)13;
    private const char SP = (char)32;

    private string query;

    public QueryReader(byte[] value)
        : this(value.GetString())
    {
    }

    public QueryReader(string value)
    {
        this.query = value;
    }

    public bool Any()
    {
        return this.query.Length != 0;
    }

    public void NextKey()
    {
        this.query = this.query.TrimStart(HT, LF, CR, SP);

        if (this.query.Length > 0)
        {
            this.query = this.query.Substring(1); // skip comma
        }
    }

    public bool ReadBoolean(out string value)
    {
        // true,rest
        value = this.ReadText();
        return value == "true";
    }

    public string ReadKey()
    {
        // [LWS]key[LWS]=rest
        var end = this.query.IndexOf('=');
        var key = this.query.Substring(0, end).Trim(HT, LF, CR, SP);
        QueryReader.CheckValidToken(key);
        this.query = this.query.Substring(end + 1); // +1 (equal)
        return key;
    }

    public string[] ReadQList()
    {
        // "list",rest
        var list = this.ReadQText();
        return list.Split(',').Select(v => v.Trim(HT, LF, CR, SP)).ToArray();
    }

    public string ReadQText()
    {
        // TODO: add `quoted-pair` support.

        // [LWS]"text",rest
        this.query = this.query.TrimStart(HT, LF, CR, SP);
        var end = this.query.IndexOf('"', 1);
        var qtext = this.query.Substring(1, end - 1); // -1 (beginning quote)
        this.query = this.query.Substring(end + 1);

        // ignore after [LWS] because of processing `NextKey`.
        return qtext;
    }

    public string ReadText()
    {
        // [LWS]text[LWS],rest
        var end = this.query.IndexOf(',');
        if (end < 0)
        {
            end = this.query.Length;
        }

        var text = this.query.Substring(0, end);
        this.query = this.query.Substring(end);
        return text.Trim(HT, LF, CR, SP);
    }

    public uint ReadUint()
    {
        // num,rest
        var num = this.ReadText();
        return uint.Parse(num);
    }

    private static void CheckValidToken(string key)
    {
        if (!key.ToCharArray().All(QueryReader.IsValidToken))
        {
            throw new NotSupportedException($"Not suppoted query key: {key}");
        }
    }

    private static bool IsCtrlSeq(char ch)
    {
        return ch < 32;
    }

    private static bool IsSeparators(char ch)
    {
        return
            ch == '('
            || ch == ')'
            || ch == '<'
            || ch == '>'
            || ch == '@'
            || ch == ','
            || ch == ';'
            || ch == ':'
            || ch == '\\'
            || ch == '"'
            || ch == '/'
            || ch == '['
            || ch == ']'
            || ch == '?'
            || ch == '='
            || ch == '{'
            || ch == '}'
            || ch == SP
            || ch == HT;
    }

    private static bool IsValidToken(char ch)
    {
        return
            ch < 128
            && !QueryReader.IsCtrlSeq(ch)
            && !QueryReader.IsSeparators(ch);
    }
}
