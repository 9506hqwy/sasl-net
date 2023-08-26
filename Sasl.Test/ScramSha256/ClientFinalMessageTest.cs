namespace Sasl.ScramSha256.Test;

[TestClass]
public class ClientFinalMessageTest
{
    [TestMethod]
    public void TestSetProof()
    {
        var cfirst = new ClientFirstMessage();
        var sfirst = new ServerFirstMessage
        {
            SaltRaw = new byte[] { 0x00, 0x01, 0x02, 0x03 },
            IterationCount = 2,
        };
        var final = new ClientFinalMessage();
        final.SetProof(cfirst, sfirst, "password");
        Assert.IsNotNull(final.ClientProof);
    }

    [TestMethod]
    public void TestToQueryStringChannelBinding()
    {
        var msg = new ClientFinalMessage
        {
            ChannelBinding = "a",
        };
        Assert.AreEqual("c=a,r=,p=", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringClientProof()
    {
        var msg = new ClientFinalMessage
        {
            ClientProof = "a",
        };
        Assert.AreEqual("c=,r=,p=a", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringClientExtensions()
    {
        var msg = new ClientFinalMessage
        {
            Extensions = new Dictionary<string, string>
            {
                { "a", "b" },
            },
        };
        Assert.AreEqual("c=,r=,a=b,p=", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringClientNonce()
    {
        var msg = new ClientFinalMessage
        {
            Nonce = "a",
        };
        Assert.AreEqual("c=,r=a,p=", msg.ToQueryString());
    }
}
