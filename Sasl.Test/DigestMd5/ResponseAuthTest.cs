namespace Sasl.DigestMd5.Test;

[TestClass]
public class ResponseAuthTest
{
    [TestMethod]
    public void TestParseRspauth()
    {
        var auth = ResponseAuth.Parse(new QueryReader("rspauth=abc"));
        Assert.AreEqual("abc", auth.RspAuth);
    }

    [TestMethod]
    public void TestParseUnknown()
    {
        var exc = Assert.ThrowsExactly<NotSupportedException>(() => _ = ResponseAuth.Parse(new QueryReader("unknown=abc")));
        Assert.IsNotNull(exc);
    }
}
