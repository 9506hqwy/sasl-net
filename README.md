# SASL (RFC 4422) for .Net

This library is SASL for .NET Standard 2.0.

## Supported mechanism

- DIGEST-MD5
- SCRAM-SHA-256

## References

- [Simple Authentication and Security Layer (SASL)](https://www.rfc-editor.org/rfc/rfc4422.txt)
- [Using Digest Authentication as a SASL Mechanism)](https://www.rfc-editor.org/rfc/rfc2831.txt)
  - [Moving DIGEST-MD5 to Historic](https://www.rfc-editor.org/rfc/rfc6331.txt)
- [Salted Challenge Response Authentication Mechanism (SCRAM)](https://www.rfc-editor.org/rfc/rfc5802.txt)
  - [SCRAM-SHA-256 and SCRAM-SHA-256-PLUS](https://www.rfc-editor.org/rfc/rfc7677.txt)
- [On the Use of Channel Bindings to Secure Channels](https://www.rfc-editor.org/rfc/rfc5056.txt)
  - [Channel Bindings for TLS](https://www.rfc-editor.org/rfc/rfc5929.txt)
    - tls-unique: Finished message
      - [Keying Material Exporters for Transport Layer Security (TLS)](https://www.rfc-editor.org/rfc/rfc5705.txt)
    - tls-server-end-point: サーバー証明書のサムプリント
  - [Channel Bindings for TLS 1.3](https://www.rfc-editor.org/rfc/rfc9266.txt)
- [Using Generic Security Service Application Program Interface (GSS-API)](https://www.rfc-editor.org/rfc/rfc5801.txt)
  - [Clarifications and Extensions to the Generic Security Service Application Program Interface (GSS-API) for the Use of Channel Bindings](https://www.rfc-editor.org/rfc/rfc5554.txt)
