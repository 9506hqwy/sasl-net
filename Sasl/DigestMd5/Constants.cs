namespace Sasl.DigestMd5;

internal static class Constants
{
    internal const string ClientSealingKey = "Digest H(A1) to client-to-server sealing key magic constant";
    internal const string ClientSigningKey = "Digest session key to client-to-server signing key magic constant";

    internal const string ServerSealingKey = "Digest H(A1) to server-to-client sealing key magic constant";
    internal const string ServerSigningKey = "Digest session key to server-to-client signing key magic constant";

    internal const string Method = "AUTHENTICATE";
    internal const string EmptyHash = "00000000000000000000000000000000";

    internal const string QopAuth = "auth";
    internal const string QopAuthInt = "auth-int";
    internal const string QopAuthConf = "auth-conf";

    internal const string Cipher3Des = "3des";
    internal const string CipherDes = "des";
    internal const string CipherRc4 = "rc4";
    internal const string CipherRc440 = "rc4-40";
    internal const string CipherRc456 = "rc4-56";

    internal const string NonceCountInit = "00000001";

    internal const ushort Version = 1;

    internal const int SealingHMacSize = 10;
}
