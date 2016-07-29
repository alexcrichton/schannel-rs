schannel-rs [![Build status](https://ci.appveyor.com/api/projects/status/vefyauaf0oj10swu/branch/master?svg=true)](https://ci.appveyor.com/project/steffengy/schannel-rs/branch/master)
=====

[Documentation](http://steffengy.github.io/schannel-rs/doc/schannel/)

Schannel bindings to allow https without openssl on windows, more to come.
Currently this only supports the client-side.
A simplified version of using the schannel API, can be found [here](http://www.codeproject.com/Articles/2642/SSL-TLS-client-server-for-NET-and-SSL-tunnelling)

### Running tests

Most tests can be executed with a `cargo test`, but some tess require SSL
certificates to be trusted in the root store on Windows. For this reason, a
vanilla `cargo test` on a fresh checkout will likely fail tests. There are two
options here:

1. Export the `SCHANNEL_RS_SKIP_SERVER_TESTS=1` environment variable, forcing
   the test suite to skip all related tests.
2. Add the `test/schannel-ca.crt` certificate to the root trust store on
   Windows. This can be done by executing `start test/schannel-ca.crt` (or
   double-clicking on it) and then:

    * Confirm it will be stored only with the current user
    * Select to install to a custom certificate store
    * Select the "Trusted Root Certificate Authorities" store
    * Finish the import

   The installed certificate should be installed as "schannel-rs root CA", and
   should be deletable at any time.

   Tests should then all pass successfully, and you can optionally remove this
   certificate from your root trust store after testing is done. Note that the
   private key for this certificate is long gone, so the only signed certificate
   should be `test/localhost.crt`.
