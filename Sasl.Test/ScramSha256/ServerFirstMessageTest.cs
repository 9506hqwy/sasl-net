namespace Sasl.ScramSha256.Test;

[TestClass]
public class ServerFirstMessageTest
{
    [TestMethod]
    public void TestParseExtensions()
    {
        var msg = ServerFirstMessage.Parse(new QueryReader("a=b"));
        Assert.AreEqual("b", msg.Extensions!["a"]);
        Assert.AreEqual(0u, msg.IterationCount);
        Assert.AreEqual(string.Empty, msg.Nonce);
        Assert.IsNull(msg.ReservedMext);
        Assert.AreEqual(string.Empty, msg.Salt);
    }

    [TestMethod]
    public void TestParseIterationCount()
    {
        var msg = ServerFirstMessage.Parse(new QueryReader("i=1"));
        Assert.IsNull(msg.Extensions);
        Assert.AreEqual(1u, msg.IterationCount);
        Assert.AreEqual(string.Empty, msg.Nonce);
        Assert.IsNull(msg.ReservedMext);
        Assert.AreEqual(string.Empty, msg.Salt);
    }

    [TestMethod]
    public void TestParseNonce()
    {
        var msg = ServerFirstMessage.Parse(new QueryReader("r=a"));
        Assert.IsNull(msg.Extensions);
        Assert.AreEqual(0u, msg.IterationCount);
        Assert.AreEqual("a", msg.Nonce);
        Assert.IsNull(msg.ReservedMext);
        Assert.AreEqual(string.Empty, msg.Salt);
    }

    [TestMethod]
    public void TestParseReservedMext()
    {
        var msg = ServerFirstMessage.Parse(new QueryReader("m=a"));
        Assert.IsNull(msg.Extensions);
        Assert.AreEqual(0u, msg.IterationCount);
        Assert.AreEqual(string.Empty, msg.Nonce);
        Assert.AreEqual("a", msg.ReservedMext);
        Assert.AreEqual(string.Empty, msg.Salt);
    }

    [TestMethod]
    public void TestParseSalt()
    {
        var msg = ServerFirstMessage.Parse(new QueryReader("s=a"));
        Assert.IsNull(msg.Extensions);
        Assert.AreEqual(0u, msg.IterationCount);
        Assert.AreEqual(string.Empty, msg.Nonce);
        Assert.IsNull(msg.ReservedMext);
        Assert.AreEqual("a", msg.Salt);
    }

    [TestMethod]
    public void TestToQueryStringExtensions()
    {
        var msg = new ServerFirstMessage
        {
            Extensions = new Dictionary<string, string>
            {
                { "a", "b" },
            },
        };
        Assert.AreEqual("r=,s=,i=0,a=b", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringIterationCount()
    {
        var msg = new ServerFirstMessage
        {
            IterationCount = 1,
        };
        Assert.AreEqual("r=,s=,i=1", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringNonce()
    {
        var msg = new ServerFirstMessage
        {
            Nonce = "a",
        };
        Assert.AreEqual("r=a,s=,i=0", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringReservedMext()
    {
        var msg = new ServerFirstMessage
        {
            ReservedMext = "a",
        };
        Assert.AreEqual("m=a,r=,s=,i=0", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringSalt()
    {
        var msg = new ServerFirstMessage
        {
            Salt = "a",
        };
        Assert.AreEqual("r=,s=a,i=0", msg.ToQueryString());
    }
}
