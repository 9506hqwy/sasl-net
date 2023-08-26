namespace Sasl.ScramSha256.Test;

[TestClass]
public class ServerFinalMessageTest
{
    [TestMethod]
    public void TestParseError()
    {
        var msg = ServerFinalMessage.Parse(new QueryReader("e=a"));
        Assert.AreEqual("a", msg.Error);
        Assert.IsNull(msg.Extensions);
        Assert.IsNull(msg.Verifier);
    }

    [TestMethod]
    public void TestParseExtensions()
    {
        var msg = ServerFinalMessage.Parse(new QueryReader("a=b"));
        Assert.IsNull(msg.Error);
        Assert.AreEqual("b", msg.Extensions!["a"]);
        Assert.IsNull(msg.Verifier);
    }

    [TestMethod]
    public void TestParseVerifier()
    {
        var msg = ServerFinalMessage.Parse(new QueryReader("v=a"));
        Assert.IsNull(msg.Error);
        Assert.IsNull(msg.Extensions);
        Assert.AreEqual("a", msg.Verifier);
    }
}
