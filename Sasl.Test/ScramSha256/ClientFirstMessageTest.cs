namespace Sasl.ScramSha256.Test;

[TestClass]
public class ClientFirstMessageTest
{
    [TestMethod]
    public void TestToQueryStringAuthzId()
    {
        var msg = new ClientFirstMessage
        {
            AuthzId = "a",
        };
        Assert.AreEqual("n,a=a,n=,r=", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringCnonce()
    {
        var msg = new ClientFirstMessage
        {
            Cnonce = "c",
        };
        Assert.AreEqual("n,,n=,r=c", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringExtensions()
    {
        var msg = new ClientFirstMessage
        {
            Extensions = new Dictionary<string, string>
            {
                { "a", "b" },
            },
        };
        Assert.AreEqual("n,,n=,r=,a=b", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringGs2BindingFlag()
    {
        var msg = new ClientFirstMessage
        {
            Gs2BindingFlag = "y",
        };
        Assert.AreEqual("y,,n=,r=", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringReservedMext()
    {
        var msg = new ClientFirstMessage
        {
            ReservedMext = "r",
        };
        Assert.AreEqual("n,,m=r,n=,r=", msg.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringUsername()
    {
        var msg = new ClientFirstMessage
        {
            Username = "u",
        };
        Assert.AreEqual("n,,n=u,r=", msg.ToQueryString());
    }
}
