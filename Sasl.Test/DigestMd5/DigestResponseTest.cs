namespace Sasl.DigestMd5.Test;

[TestClass]
public class DigestResponseTest
{
    [TestMethod]
    public void TestCreateFromRc4AuthConf()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        Assert.IsNull(response.AuthzId);
        Assert.AreEqual(challenge.Charset, response.Charset);
        Assert.AreEqual("rc4", response.Cipher);
        Assert.IsNotNull(response.Cnonce);
        Assert.AreEqual("digest-uri", response.DigestUri);
        Assert.AreEqual(1u, response.MaxBuf);
        Assert.AreEqual("00000001", response.Nc);
        Assert.AreEqual("auth-conf", response.Qop);
        Assert.AreEqual("realm", response.Realm);
        Assert.IsNull(response.Response);
        Assert.IsNull(response.Tokens);
        Assert.IsNull(response.Username);
    }

    [TestMethod]
    public void TestCreateFrom3DesAuthInt()
    {
        var challenge = this.CreateChallenge(
            new string[] { "3des" },
            new string[] { "auth-int" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        Assert.IsNull(response.AuthzId);
        Assert.AreEqual(challenge.Charset, response.Charset);
        Assert.AreEqual("3des", response.Cipher);
        Assert.IsNotNull(response.Cnonce);
        Assert.AreEqual("digest-uri", response.DigestUri);
        Assert.AreEqual(1u, response.MaxBuf);
        Assert.AreEqual("00000001", response.Nc);
        Assert.AreEqual("auth-int", response.Qop);
        Assert.AreEqual("realm", response.Realm);
        Assert.IsNull(response.Response);
        Assert.IsNull(response.Tokens);
        Assert.IsNull(response.Username);
    }

    [TestMethod]
    public void TestCreateFromDesAuth()
    {
        var challenge = this.CreateChallenge(
            new string[] { "des" },
            new string[] { "auth" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        Assert.IsNull(response.AuthzId);
        Assert.AreEqual(challenge.Charset, response.Charset);
        Assert.AreEqual("des", response.Cipher);
        Assert.IsNotNull(response.Cnonce);
        Assert.AreEqual("digest-uri", response.DigestUri);
        Assert.AreEqual(1u, response.MaxBuf);
        Assert.AreEqual("00000001", response.Nc);
        Assert.AreEqual("auth", response.Qop);
        Assert.AreEqual("realm", response.Realm);
        Assert.IsNull(response.Response);
        Assert.IsNull(response.Tokens);
        Assert.IsNull(response.Username);
    }

    [TestMethod]
    public void TestCreateFromRc456None()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4-56" },
            new string[0]);
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        Assert.IsNull(response.AuthzId);
        Assert.AreEqual(challenge.Charset, response.Charset);
        Assert.AreEqual("rc4-56", response.Cipher);
        Assert.IsNotNull(response.Cnonce);
        Assert.AreEqual("digest-uri", response.DigestUri);
        Assert.AreEqual(1u, response.MaxBuf);
        Assert.AreEqual("00000001", response.Nc);
        Assert.IsNull(response.Qop);
        Assert.AreEqual("realm", response.Realm);
        Assert.IsNull(response.Response);
        Assert.IsNull(response.Tokens);
        Assert.IsNull(response.Username);
    }

    [TestMethod]
    public void TestCreateFromRc440None()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4-40" },
            new string[0]);
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        Assert.IsNull(response.AuthzId);
        Assert.AreEqual(challenge.Charset, response.Charset);
        Assert.AreEqual("rc4-40", response.Cipher);
        Assert.IsNotNull(response.Cnonce);
        Assert.AreEqual("digest-uri", response.DigestUri);
        Assert.AreEqual(1u, response.MaxBuf);
        Assert.AreEqual("00000001", response.Nc);
        Assert.IsNull(response.Qop);
        Assert.AreEqual("realm", response.Realm);
        Assert.IsNull(response.Response);
        Assert.IsNull(response.Tokens);
        Assert.IsNull(response.Username);
    }

    [TestMethod]
    public void TestCreateFromNoneNone()
    {
        var challenge = this.CreateChallenge(
            new string[0],
            new string[0]);
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        Assert.IsNull(response.AuthzId);
        Assert.AreEqual(challenge.Charset, response.Charset);
        Assert.IsNull(response.Cipher);
        Assert.IsNotNull(response.Cnonce);
        Assert.AreEqual("digest-uri", response.DigestUri);
        Assert.AreEqual(1u, response.MaxBuf);
        Assert.AreEqual("00000001", response.Nc);
        Assert.IsNull(response.Qop);
        Assert.AreEqual("realm", response.Realm);
        Assert.IsNull(response.Response);
        Assert.IsNull(response.Tokens);
        Assert.IsNull(response.Username);
    }

    [TestMethod]
    [ExpectedException(typeof(NotSupportedException))]
    public void TestCreateFromNoneUnknown()
    {
        var challenge = this.CreateChallenge(
            new string[0],
            new string[] { "unknown" });
        DigestResponse.CreateFrom(challenge, "digest-uri");
    }

    [TestMethod]
    [ExpectedException(typeof(NotSupportedException))]
    public void TestCreateFromUnknownNone()
    {
        var challenge = this.CreateChallenge(
            new string[] { "unknown" },
            new string[0]);
        DigestResponse.CreateFrom(challenge, "digest-uri");
    }

    [TestMethod]
    public void TestGetClientSealingKey()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        response.SetResponse("username", "password");
        var key = response.GetClientSealingKey("password");
        Assert.IsNotNull(key);
    }

    [TestMethod]
    public void TestGetClientSigningKey()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        response.SetResponse("username", "password");
        var key = response.GetClientSigningKey("password");
        Assert.IsNotNull(key);
    }

    [TestMethod]
    public void TestGetServerSealingKey()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        response.SetResponse("username", "password");
        var key = response.GetServerSealingKey("password");
        Assert.IsNotNull(key);
    }

    [TestMethod]
    public void TestGetServerSigningKey()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        response.SetResponse("username", "password");
        var key = response.GetServerSigningKey("password");
        Assert.IsNotNull(key);
    }

    [TestMethod]
    public void TestSetResponse()
    {
        var challenge = this.CreateChallenge(
            new string[] { "rc4" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        response.SetResponse("username", "password");
        Assert.AreEqual("username", response.Username);
        Assert.IsNotNull(response.Response);
    }

    [TestMethod]
    public void TestToQueryStringUsername()
    {
        var res = new DigestResponse
        {
            Username = "a",
        };
        Assert.AreEqual("username=\"a\"", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringUsernameRealm()
    {
        var res = new DigestResponse
        {
            Username = "a",
            Realm = "b",
        };
        Assert.AreEqual("username=\"a\",realm=\"b\"", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringRealm()
    {
        var res = new DigestResponse
        {
            Realm = "a",
        };
        Assert.AreEqual("realm=\"a\"", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringNonce()
    {
        var res = new DigestResponse
        {
            Nonce = "a",
        };
        Assert.AreEqual("nonce=\"a\"", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringCnonce()
    {
        var res = new DigestResponse
        {
            Cnonce = "a",
        };
        Assert.AreEqual("cnonce=\"a\"", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringNonceCount()
    {
        var res = new DigestResponse
        {
            Nc = "a",
        };
        Assert.AreEqual("nc=a", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringQop()
    {
        var res = new DigestResponse
        {
            Qop = "a",
        };
        Assert.AreEqual("qop=a", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringDigestUri()
    {
        var res = new DigestResponse
        {
            DigestUri = "a",
        };
        Assert.AreEqual("digest-uri=\"a\"", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringResponse()
    {
        var res = new DigestResponse
        {
            Response = "a",
        };
        Assert.AreEqual("response=a", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringMaxbuf()
    {
        var res = new DigestResponse
        {
            MaxBuf = 1,
        };
        Assert.AreEqual("maxbuf=1", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringCharset()
    {
        var res = new DigestResponse
        {
            Charset = "a",
        };
        Assert.AreEqual("charset=a", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringCipher()
    {
        var res = new DigestResponse
        {
            Cipher = "a",
        };
        Assert.AreEqual("cipher=a", res.ToQueryString());
    }

    [TestMethod]
    public void TestToQueryStringAuthzId()
    {
        var res = new DigestResponse
        {
            AuthzId = "a",
        };
        Assert.AreEqual("authzid=\"a\"", res.ToQueryString());
    }

    [TestMethod]
    public void TestClientEncryptServerDescript()
    {
        const string password = "password";
        var challenge = this.CreateChallenge(
            new string[] { "3des" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        response.SetResponse("username", password);
        var enc = response.CreateEncryptor(Mode.Client, password);
        var dec = response.CreateDecryptor(Mode.Server, password);

        var plain = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var cipher = enc.Encrypt(plain);
        var plain2 = dec.Decrypt(cipher);

        CollectionAssert.AreEqual(plain, plain2);
    }

    [TestMethod]
    public void TestServerEncryptClientDescript()
    {
        const string password = "password";
        var challenge = this.CreateChallenge(
            new string[] { "3des" },
            new string[] { "auth-conf" });
        var response = DigestResponse.CreateFrom(challenge, "digest-uri");
        response.SetResponse("username", password);
        var enc = response.CreateEncryptor(Mode.Server, password);
        var dec = response.CreateDecryptor(Mode.Client, password);

        var plain = new byte[] { 0x01, 0x02, 0x03, 0x04 };

        var cipher = enc.Encrypt(plain);
        var plain2 = dec.Decrypt(cipher);

        CollectionAssert.AreEqual(plain, plain2);
    }

    private DigestChallenge CreateChallenge(string[] cipher, string[] qop)
    {
        return new DigestChallenge
        {
            Charset = "utf-8",
            Cipher = cipher,
            MaxBuf = 1,
            Nonce = "nonce",
            Qop = qop,
            Realm = "realm",
        };
    }
}
