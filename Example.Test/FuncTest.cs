namespace Example.Test;

[TestClass]
public class FuncTest
{
    [TestMethod]
    public void TestAdd()
    {
        Assert.AreEqual(3, Func.Add(2, 1));
    }

    [TestMethod]
    public void TestSub()
    {
        Assert.AreEqual(1, Func.Sub(2, 1));
    }
}
