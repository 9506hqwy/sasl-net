namespace Sasl.DigestMd5.Test;

[TestClass]
public class DigestChallengeTest
{
    [TestMethod]
    public void TestParseAlgorithm()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("algorithm=md5-sess"));
        Assert.AreEqual("md5-sess", challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseAlgorithmLws()
    {
        var challenge = DigestChallenge.Parse(new QueryReader(" algorithm = md5-sess "));
        Assert.AreEqual("md5-sess", challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseCharset()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("charset=utf-8"));
        Assert.IsNull(challenge.Algorithm);
        Assert.AreEqual("utf-8", challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseCipher1()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("cipher=\"3des\""));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        CollectionAssert.AreEqual(new string[] { "3des" }, challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseCipher2()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("cipher=\"3des,rc4\""));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        CollectionAssert.AreEqual(new string[] { "3des", "rc4" }, challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseMaxbuf()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("maxbuf=1"));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.AreEqual(1u, challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseNonce()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("nonce=\"abc\""));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.AreEqual("abc", challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseNonceLws()
    {
        var challenge = DigestChallenge.Parse(new QueryReader(" nonce = \"abc\" "));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.AreEqual("abc", challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseQop1()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("qop=\"auth\""));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        CollectionAssert.AreEqual(new string[] { "auth" }, challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseQop2()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("qop=\"auth, auth-int\""));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        CollectionAssert.AreEqual(new string[] { "auth", "auth-int" }, challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseRealm()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("realm=\"abc\""));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.AreEqual("abc", challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseStale()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("stale=true"));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsTrue(challenge.Stale);
        Assert.IsNull(challenge.Tokens);
    }

    [TestMethod]
    public void TestParseTokens()
    {
        var challenge = DigestChallenge.Parse(new QueryReader("abc=\"xyz\""));
        Assert.IsNull(challenge.Algorithm);
        Assert.IsNull(challenge.Charset);
        Assert.IsNull(challenge.Cipher);
        Assert.IsNull(challenge.MaxBuf);
        Assert.IsNull(challenge.Nonce);
        Assert.IsNull(challenge.Qop);
        Assert.IsNull(challenge.Realm);
        Assert.IsFalse(challenge.Stale);
        Assert.AreEqual("\"xyz\"", challenge.Tokens!["abc"]);
    }
}
