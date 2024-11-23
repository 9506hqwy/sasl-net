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
    [ExpectedException(typeof(NotSupportedException))]
    public void TestParseUnknown()
    {
        _ = ResponseAuth.Parse(new QueryReader("unknown=abc"));
    }
}
