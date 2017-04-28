# TestSSLServer

## Overview

**TestSSLServer** is a command-line tool which contacts a SSL/TLS server
and obtains some information on its configuration. It aims at providing
(part of) the functionality of Internet-based tools like [Qualys SSL
Server Test](https://www.ssllabs.com/ssltest/), but without the
requirement of the server being Internet-reachable. You can use
TestSSLServer on your internal network, to test your servers while they
are not (yet) accessible from the outside.

Gathered information includes the following:

 - Supported protocol versions (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1 and
   TLS 1.2 are tested).

 - For each protocol version, the supported cipher suites; an attempt
   is also made at determining the algorithm used by the server to
   select the cipher suite.

 - Certificate(s) used by the server, which are then locally decoded to
   determine key type, size, and hash function used in the signature.

 - Type and size of ephemeral Diffie-Hellman parameters (or elliptic
   curve for ECDHE cipher suites).

 - Support of Deflate compression.

The analysis is performed by repeatedly connecting to the target server,
with different variants of `ClientHello` messages, and analysing the
server's answer. It shall be noted that TestSSLServer includes no
cryptographic algorithm whatsoever; as such, it is incapable of
completing any SSL/TLS handshake. It sends a `ClientHello`, then obtains
the server's response up to the next `ServerHelloDone` message, at which
points it closes the connection.

**Note:** although the information which is gathered from the server is
nominally public, some server administrators could be somewhat dismayed
at your using the tool on their servers, and there may be laws against
it (in the same way that port scanning third-party servers with `nmap`
is a matter of delicacy, both morally and legally). You should use
TestSSLServer only to scan your own servers, and that's what it was
designed to do.

## License

License is MIT-like: you acknowledge that the code is provided without
any guarantee of anything, and that I am not liable for anything which
follows from using it. Subject to these conditions, you can do whatever
you want with the code. See the `LICENSE` file in the source code for
the legal wording.

## Installation

The source code is obtained from
[GitHub](https://github.com/pornin/TestSSLServer/); use the "Download
ZIP" to obtain a fresh snapshot, or use `git` to clone the repository.
In the source tree, you will find the simple build scripts, `build.cmd`
(for Windows) and `build.sh` (for Linux and OS X).

The Windows script invokes the command-line compiler (`csc.exe`) that is
found in the v2.0.50727 .NET framework. This framework is installed by
default on Windows 7. More recent versions of Windows do not have the
.NET 2.0 framework, but a more recent version (4.x or later). Though
these framework versions are not completely compatible with each other,
TestSSLServer uses only features that work identically on both, so you
can compile TestSSLServer with either .NET version. The resulting
TestSSLServer.exe is stand-alone and needs no further "installation";
you simply copy the file where you want it to be, and run it from a
console (`cmd.exe`) with the appropriate arguments.

The Linux / OS X script tries to invoke the Mono C# compiler under the
names `mono-csc` (which works on Ubuntu) and `dmcs` (which works on OS
X). On Ubuntu, install the `mono-devel` package; it should pull as
dependencies the runtime and the compiler. On OS X, fetch a package from
the [Mono project](http://www.mono-project.com/) and install it; it
should provide the `mono` command-line tool to run compiled asemblies,
and `dmcs` to invoke the C# compiler.

## Usage

On Windows, the compiled `TestSSLServer.exe` file can be launched as
is. On Linux and OS X, use `mono TestSSLServer.exe`.

General usage:

    TestSSLServer.exe [ options ] servername [ port ]

The `servername` is the name of IP address of the target server. If the
`port` is not specified, then 443 is used.

Options are:

 - `-h`

   Print an helper message. You also get it by running the tool without
   any argument.

 - `-v`

   Enable verbose operations. During data gathering, TestSSLServer will
   print some information that documents the actions; in particular, it
   will display an extra "`.`" character for each connection.

 - `-all`

   Gather information for all possible cipher suites. By default,
   TestSSLServer only tests for the cipher suites that it knows about,
   which are the (currently) 323 cipher suites registered at the
   [IANA](http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4).
   With the `-all` command-line flag, TestSSLServer will test for all
   possible 65533 cipher suites (excluding the special cipher suites
   0x0000, 0x00FF and 0x5600, which are not real cipher suites).

 - `-min version`

   Test only protocol versions greater than or equal to the specified
   version (the version is specified as a string: `SSLv2`, `SSLv3`,
   `TLSv1`, `TLSv1.1` or `TLSv1.2`).

 - `-max version`

   Test only protocol versions lower than or equal to the specified
   version (the version is specified as a string: `SSLv2`, `SSLv3`,
   `TLSv1`, `TLSv1.1` or `TLSv1.2`).

 - `-sni name`

   Set the "server name" to be sent as part of the Server Name Extension
   (SNI) in the `ClientHello` message. By default, the SNI will contain
   a copy of the `servername` command-line parameter; this option allows
   to override the name. By using the name "`-`", the SNI extension is
   disabled.

 - `-certs`

   In the output report, include the full server certificate(s) in PEM
   format.

 - `-t delay`

   Set the timeout delay (in seconds). This timeout is applied when
   waiting for response bytes from the server, for the SSLv2 test
   connection, and for the SSLv3/TLS connections until an actual
   SSL-like answer was obtained (a ServerHello or an alert). If the
   timeout is reached for SSLv3/TLS, then the server is assumed to
   implement a non-SSL protocol, and processing stops.

   By default, a 20-second delay is applied, so that connecting to a
   non-SSL server may not stall for more than 40 seconds. Use 0 to
   deactivate the timeout (read will block indefinitely).

 - `-prox name:port`

   Use the specified HTTP proxy to perform connections to the server.
   (TestSSLServer does not support proxy authentication yet.)

 - `-proxssl`

   Use SSL/TLS to open the connection to the HTTP proxy.

 - `-ec`

   Add a "supported curves" extension to the `ClientHello` for most
   connections, testing extension-less EC support only at the end of the
   process. This is the default and it maximizes the chances of
   detection of elliptic-curve based cipher suites: some servers might
   not allow negotiation of an EC cipher suite in the absence of the
   extension.

 - `-noec`

   Do not add a "supported curves" extension in the `ClientHello` for
   most connections. That extension will be added only for some specific
   connections at the end, and only if the server still selected some
   EC-based suites. This option should be used only if a target server
   appears to be allergic to elliptic curves and refuses to respond in
   the presence of the "supported curves" extension.

   Using this extension may miss some supported cipher suites, if the
   server does not support EC-based suites without the client extension.

 - `-text fname`

   Produce a text report (readable by humans) into the designated
   file. If `fname` is "`-`", then the report is written on standard
   output.

   If neither `-text` nor `-json` is used, the text report will be
   written on standard output.

 - `-json fname`

   Produce a JSON report (parsable) into the designated file. If `fname`
   is "`-`", then the report is written on standard output.

   If neither `-text` nor `-json` is used, the text report will be
   written on standard output.

 - `-log fname`

   Produce a text-based log of all connection attempts (hexadecimal dump
   of all bytes in both directions) in the specified file.

For example, to make a text report in file "test.txt" for server
"www.example.com" on port 443, use:

    TestSSLServer.exe -v -text test.txt www.example.com 443

## JSON Format

A single JSON object is produced. It contains the following fields:

 - **connectionName**: a string value that contains the server name
   (as used for opening the connection)

 - **connectionPort**: the server port, as a number.

 - **SNI**: the server name used in the SNI extension. This is `null`
   if no SNI extension was sent.

 - **SSLv2**: present only if the server supports SSL 2.0, this
   field is a sub-object with the following contents:

   - **suites**: an array of objects, for all SSL 2.0 cipher suites
     supported by the server, in the order the server sent them (in
     SSL 2.0, that order has no real significance because the client
     selects the cipher suite, not the server). Each such object
     contains two fields:

     - **id**: the cipher suite identifier (24-bit integer)

     - **name**: the cipher suite symbolic name

 - **SSLv3**, **TLSv1.0**, **TLSv1.1** and **TLSv1.2**: each of these
   fields is defined if and only if the corresponding protocol version
   is supported. When defined, the value is an object with the following
   contents:

   - **suiteSelection**: a string value, that is either `client`,
     `server` or `complex`. If the value is `client`, then the server
     uses the client's preferred order of cipher suite, selecting the
     first in the `ClientHello` message that the server also supports.
     If the value is `server`, then the server enforces its own
     preferences, using its most preferred cipher suite among those
     supported by the client. If the selection algorithm follows neither
     model, then the value of this field is `complex`.

   - **suites**: an array of objects, for all cipher suites supported by
     that version. If the suite selection algorithm is `server`, then
     the suites are listed in the server's preference order (most
     preferred comes first); otherwise, the array order has no
     significance. Each array element represents a cipher suite, and
     is an object with the following fields:

     - **id**: the cipher suite identifier (16-bit integer)

     - **name**: the cipher suite symbolic name. If the cipher suite
       is not known by TestSSLServer, then the symbolic name will
       begin with "`UNKNOWN_SUITE`" followed by the suite value.

     If the cipher suite is known to TestSSLServer, the following fields
     also appear:

     - **strength**: the encryption strength, as an integer from 0 to 3.
       0 is "unencrypted", 1 is "very weak" (40-bit keys), 2 is "less
       weak" (56-bit DES), and 3 is "strong" (in practice, 112-bit keys
       or more). Strength 1 can be broken by basic amateurs; strength 2
       can still be broken but requires dedication and a hardware budget
       of several thousands of dollars. Strength 3 is way beyond
       existing technology, even if billions of dollars are thrown at
       the effort.

     - **forwardSecrecy**: a boolean value which is `true` if the key
       exchange uses ephemeral key pairs, which are discarded after
       usage. When a suite providing forward secrecy is used, theft of
       the server's secrets cannot help with decrypting past sessions.

     - **anonymous**: a boolean value which is `true` for cipher suites
       that do NOT imply server authentication. Such cipher suites are
       thus inherently vulnerable to server impersonation.

     - **serverKeyType**: a symbolic string that qualifies the type of
       the server "permanent" key (corresponding to its certificate).
       This is "RSA", "DSA", "DH", "EC" (for elliptic curves), or
       "none". Note that PSK and SRP cipher suites may have type "none"
       (there is no server certificate) but can still ensure server
       authentication through a shared secret.

 - **ssl2Cert**: if SSL 2.0 is supported, then this field is en object
   that describes the server certificate as used in SSL 2.0. This is a
   single certificate, since SSL 2.0 does not allow for sending a
   chain. See below for certificate object contents.

 - **ssl3Chains**: an array of all certificate chains used by the
   server (for SSL 3.0 and later versions). Each chain is an object
   that contains the following fields:

   - **length**: the chain length (a number).

   - **decoded**: a boolean value which is `false` if at least one
     certificate could not be decoded by TestSSLServer. If that field
     is `true`, then the three next fields (namesMatch, includesRoot
     and signHashes) are present.

   - **namesMatch**: a boolean value which is `true` when all the
     names match along the chain (the subjectDN field of each certificate
     is identical to the issuerDN field of the previous certificate in
     the chain; note that SSL/TLS chains are in "reverse order", the
     server certificate itself coming first).

   - **includesRoot**: a boolean value which is `true` if the last
     certificate in the chain appears to be self-issued (its subjectDN
     and issuerDN are identical). Root certificates are traditionally
     self-issued.

   - **signHashes**: an array of strings, which are the names of the
     hash functions used for the signatures of all certificates in
     the chain (not counting self-issued certificates).

   - **certificates**: an array of objects, for all the certificates in
     the chain, in the order they appeared in the `Certificate` message
     from the server. In SSL/TLS, the server's certificate should appear
     first, and each subsequent certificate belongs to a Certification
     Authority that issued the previous certificate. The root
     certificate may or may not appear at the end of the list (the TLS
     standard allows both its presence and its omission).

     Each certificate object contains the following fields:

     - **tumbprint**: the SHA-1 hash of the encoded certificate, in
       uppercase hexadecimal. This value should match the thumbprints
       computed by Microsoft's code.

     - **decodable**: a boolean value which is `true` if that specific
       certificate could be decoded successfully.

     - **decodeError**: that field is present only if the certificate
       could NOT be decoded; it is a string value that qualifies the
       decoding error.

     - **PEM**: the complete certificate in PEM format (Base64 with
       header and footer); this field is present only if TestSSLServer
       was invoked with the `-certs` command-line option.

     All the following fields appear only if the certificate could be
     decoded:

     - **serialHex**: the certificate serial number (uppercase
       hexadecimal, with a leading zero added if needed to have
       an even number of digits).

     - **subject**: the certificate subjectDN, in standard string
       representation (RFC 4514).

     - **issuer**: the certificate issuerDN, in standard string
       representation (RFC 4514).

     - **validFrom**: the date and time of start of validity for
       the certificate; format is "yyyy-MM-dd HH:mm:ss UTC" and
       contains the date in UTC.

     - **validTo**: the date and time of end of validity for
       the certificate; format is "yyyy-MM-dd HH:mm:ss UTC" and
       contains the date in UTC.

     - **keyType**: the type of public key in the certificate;
       this is "RSA", "DSA", "EC", or "UNKOWN" if the public key
       type was not recognized.

     - **keySize**: the size of the public key, in bits. For RSA, this
       is the size of the composite modulus. For DSA, this is the size
       of the prime moduls. For elliptic curves (EC), this is the value
       _k_ such that 2<sup>_k_</sup> is closest to the order of the
       subgroup of prime order produced by the conventional generator.

     - **keyCurve**: if the key type is EC (elliptic curve) and uses
       a "named curve", then this is the curve symbolic name (if
       TestSSLServer recognized it) or the curve OID (if it did not).

     - **signHash**: the name of the hash function used for the
       signature applied to this certificate. If the hash function
       could not be recognized, this string will be "UNKNOWN".

     - **serverNames**: this field is present only for the first
       certificate of the chain (the server's own certificate); it is an
       array of strings, containing all the names of type `dNSName` in
       the certificate's Server Alternative Names extension. If the
       certificate does not have a SAN extension, or if its SAN
       extension does not contain any `dNSName`, then this array
       contains only the Common Name from the subjectDN (or is empty if
       the subjectDN does not contain any Common Name either).

       These names are supposed to be checked by the client, to match
       the expected server name (e.g. from the URL, if the client is a
       Web browser).

 - **deflateCompress**: a boolean value set to `true` if the server
   appears to support Deflate compression.

 - **serverTime**: the estimated notion of time by the server. In the
   SSL/TLS handshake, the client and server send each other the current
   time, counted in seconds since the Epoch (January 1st, 1970, at
   midnight). Not all implementation follow this convention. If the
   server explicitly declined sending its sytem type, this field will
   contain "none". If the server sent random bytes instead of its
   system time, then this field will contain "random". If the server
   really sent its system time, then that time will be represented
   as "yyyy-MM-dd HH:mm:ss UTC".

   (The measure is actually an average of the offset between the
   client's time and the server's time, over all successful handshakes;
   the specified time is the result of applying that offset to the
   client's time when the report is generated.)

 - **serverTimeOffsetMillis**: the offset between the server's time and
   the client's time, in milliseconds. This field is present only if the
   server indeed sends its system time. Since the time field in a
   SSL/TLS handshake is an integral number of seconds, it is expected
   that the offset may reach several hundreds of milliseconds, even if
   the client and server are perfectly synchronized.

 - **secureRenegotiation**: a boolean value, set to `true` if the server
   supports the Secure Renegotiation extension (RFC 5746).

 - **rfc7366EtM**: a boolean value, set to `true` if the server supports
   the Encrypt-then-MAC extension (RFC 7366). This extension is
   nominally a good thing; however, OpenSSL versions 1.1.0a to 1.1.0d
   are affected by a bug in which support of this extension allows a
   denial-of-service attack. TestSSLServer does _not_ test for this
   vulnerability, since, when present, it crashes the server. If
   TestSSLServer reports support for the extension, then you should
   check that the server does not use a vulnerable OpenSSL version.

 - **ssl2HelloFormat**: a boolean value, set to `true` if the server
   supports a ClientHello for SSLv3+ sent in SSLv2 format. Some old
   clients support for SSLv2 and SSLv3, and send the ClientHello in
   SSLv2 format. Supporting this format for the ClientHello only is not
   a problem (contrary to full SSLv2 support), but it is recommended to
   ultimately drop that format, notably because the SSLv2 format has no
   room for TLS extensions.

 - **minDHSize**: the size (in bits) of the smallest Diffie-Hellman
   modulus that the server is willing to use in a cipher suite that uses
   ephemeral DH parameters. This field is present only if such a
   cipher suite is supported by the server.

 - **kxReuseDH**: a boolean value, set to `true` if the server was
   detected to reuse DH parameters (for DHE or DH\_anon cipher suites).
   This field is present only if such a cipher suite is supported by the
   server. Note that DH parameters reuse is not guaranteed to be
   detected, especially in some load-balancing setups.

 - **minECSize**: the size (in bits) of the smallest elliptic curve that
   the server is willing to use in an ECDHE cipher suite. This field is
   present only if the server supports an ECDHE cipher suite, and takes
   into account only the handshakes in which the client did NOT send a
   "supported curves" extension: this size thus qualifies the elliptic
   curves that the servers spontaneously selects.

 - **minECSizeExt**: the size (in bits) of the smallest elliptic curve
   that the server accepts to use for an ECDHE cipher suite, in the
   presence of a "supported curve" extension from the client. If there
   is no such curve, then this field is not present.

 - **kxReuseECDH**: a boolean value, set to `true` if the server was
   detected to reuse ECDH parameters (for ECDHE or ECDH\_anon cipher
   suites). This field is present only if such a cipher suite is
   supported by the server. Note that ECDH parameters reuse is not
   guaranteed to be detected, especially in some load-balancing setups.

 - **namedCurves**: this field is an array that contains the list of
   named elliptic curves that the server supports. It is included only
   if that list is not empty. Each array element is an object that
   contains the following fields:

   - **name**: the curve symbolic name.

   - **size**: the curve size (in bits).

   - **spontaneous**: a boolean value which is `true` if the server
     spontaneously selects that curve (without a "supported curve"
     extension from the client).

   If the server can send explicit curve parameters (curve equation
   parameters and similar values, instead of a symbolic name), then the
   array may contain the curves "explicitPrime" and "explicitChar2", for
   the two types of curves supported by SSL/TLS. These special curves do
   not have a "spontaneous" field because their parameters are, by
   definition, chosen by the server.

 - **warnings**: this field is an array of "warnings" which are elements
   that TestSSLServer deems worth mentioning. Each warning is an object
   that contains two fields:

   - **id**: the symbolic identifier for the warning (5 characters).

   - **text**: the warning message, for human consumption.

## Warnings

Each "warning" indicates a condition which may imply a vulnerability
of some kind.

 - **CP001**: Server supports compression.

   Compression makes data length depend on data contents, thereby
   leaking information, since encryption does not hide length. This can
   be leveraged in some contexts to reveal secret values (attack
   "CRIME"). SSL/TLS-level compression should be disabled. Compression,
   if used at all in a protocol, should be applied at the application
   level (e.g. HTTP compression), with great care.

 - **CS001**: Server supports unencrypted cipher suites.

   The server accepts to use cipher suites with no encryption of data
   at all.

 - **CS002**: Server supports very weak cipher suites (40 bits).

   The server accepts to use cipher suites whose encryption can be
   efficiently broken by amateurs.

 - **CS003**: Server supports very weak cipher suites (56 bits).

   The server accepts to use cipher suites whose encryption can be
   broken by small organizations.

 - **CS004**: Server supports unrecognized cipher suites (unknown strength).

   Among the cipher suites supported by the server are suites about which
   TestSSLServer has no knowledge. Their encryption strength cannot be
   reported.

 - **CS005**: Server supports RC4.

   RC4 has known biases which can be used to leak secret elements in
   case of repeated connections with the same contents; this might
   be applicable to Web contexts. RC4 is explicitly prohibited by
   RFC 7465.

 - **CS006**: Server supports cipher suites with no forward secrecy.

   The server accepts to use some cipher suites that do not ensure
   forward secrecy; an ulterior compromise of the server's private key
   may thus endanger the confidentiality of past sessions.

 - **PV001**: Server needs short ClientHello.

   TestSSLServer detected that the server was allergic to perfectly
   standard but somewhat large `ClientHello` messages. This indicates
   a server implementation strategy with a too small input buffer.

 - **PV002**: Server supports SSL 2.0.

   SSL 2.0 has severe issues, and is explicitly forbidden by RFC 6176.
   Recently, a new padding oracle attack has been described, which
   leverages a SSL 2.0 server to decrypt a TLS key exchange, thus
   demonstrating that SSL 2.0 support is harmful even when it is not
   actually used by normal clients.

 - **PV003**: Server supports SSL 3.0.

   SSL 3.0 has an unfixable flaw in its support for block ciphers in CBC
   mode, allowing for a leak on encrypted data (attack "Poodle"). SSL
   3.0 should not be used. Recent clients and servers can use a
   mechanism (fallback detection) to ensure that an active attacker will
   not force them to use SSL 3.0 even though they both support a more
   recent protocol. However, clients and server which are not able to
   use at least TLS 1.0 are very old, since TLS 1.0 was defined in 1999.
   It is thus recommended to disable SSL 3.0 support.

 - **PV004**: Server does not tolerate extensions.

   TestSSLServer could not complete any handshake when it sends
   extensions in the `ClientHello`, but removing them allowed the
   handshake to complete. This is a server flaw that indicates and
   old and unmaintained software base.

 - **PV005**: Server claims to support SSL 2.0, but with no cipher suite.

   This may happen on some servers where SSL 2.0 was not fully
   deactivated, but all cipher suites were removed from what it
   supports. The server sends an empty list, so it does not _really_
   support SSL 2.0, it merely claims to do so. Some other SSL scanning
   tools wrongly indicate this occurrence as "supports SSL 2.0", which
   is why this warning is included.

 - **RN001**: Server does not support secure renegotiation.

   The server does not appear to support the Secure Renegotiation
   extension (RFC 5746). Depending on whether the server supports
   renegotiations at all, and on the client authentication model
   implemented by the server, this may allow some active attacks.

 - **SK001**: Some Server Key Exchange messages could not be processed.
 
   At least one of the `ServerKeyExchange` messages sent by the server
   could not be understood by TestSSLServer. Any assessment of security
   is thus incomplete.

 - **SK002**: Server uses DH parameters smaller than 2048 bits.

   DH parameters which are too small are potentially vulnerable to
   offline breaks, thereby revealing the contents of recorded sessions.
   A minimum size of 2048 bits is recommended for Diffie-Hellman.

 - **SK003**: Server chooses ECDH parameters smaller than 192 bits.

   When the cipher suite uses ephemeral ECDH parameters, and the client
   does not send a "supported curves" extension, the server may elect to
   use a curve which is sufficiently small to allow offline breakage.
   The server should choose curves of at least 192 bits.

 - **SK004**: Server supports ECDH parameters smaller than 192 bits
   (if requested).

   When the client sends a "supported curves" extension, it can induce
   the server to use with ECDHE a curve of insufficient size to ensure
   protection against offline breakage. This is less serious than the
   SK003 warning, since the client has to ask for such curves
   explicitly.

 - **XC001**: At least one of the non-self-issued certificates sent by
   the server is signed with, as support hash function, a weak or
   deprecated hash function (MD2, MD5 or SHA-1), or a hash function that
   was not recognized.

## Text Output

When use with the `-text` option (or no output option at all),
TestSSLServer produces a text report which contains the same information
as the JSON report, with a layout meant for immediate human consumption.

The text report begins with the information about the server name and
port, and SNI extension contents. Then follow the supported versions
and, for each of them, the supported cipher suites. For instance,
you may get this:

      SSLv3:
         server selection: uses client preferences
         3-- (key:  RSA)  RSA_WITH_RC4_128_SHA
         3-- (key:  RSA)  RSA_WITH_3DES_EDE_CBC_SHA
         3f- (key:  RSA)  DHE_RSA_WITH_3DES_EDE_CBC_SHA
         3-- (key:  RSA)  RSA_WITH_AES_128_CBC_SHA
         3f- (key:  RSA)  DHE_RSA_WITH_AES_128_CBC_SHA
         3-- (key:  RSA)  RSA_WITH_AES_256_CBC_SHA
         3f- (key:  RSA)  DHE_RSA_WITH_AES_256_CBC_SHA
         3-- (key:  RSA)  RSA_WITH_CAMELLIA_128_CBC_SHA
         3f- (key:  RSA)  DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
         3-- (key:  RSA)  RSA_WITH_CAMELLIA_256_CBC_SHA
         3f- (key:  RSA)  DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
         3-- (key:  RSA)  RSA_WITH_SEED_CBC_SHA
         3f- (key:  RSA)  DHE_RSA_WITH_SEED_CBC_SHA
         3f- (key:  RSA)  ECDHE_RSA_WITH_RC4_128_SHA
         3f- (key:  RSA)  ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
         3f- (key:  RSA)  ECDHE_RSA_WITH_AES_128_CBC_SHA
         3f- (key:  RSA)  ECDHE_RSA_WITH_AES_256_CBC_SHA
      TLSv1.0: idem

This output means that both SSL 3.0 and TLS 1.0 are supported. For
SSL 3.0, TestSSLServer noticed that the server faithfully follows the
client preferences; the cipher suites are then listed in no particular
order (in fact, they are ordered by their numerical 16-bit identifier).
For each cipher suite, the first three characters are synthetic flags
about the cipher suite:

 - First character is 0, 1, 2 or 3, for the strength of the symmetric
   encryption (0 is unencrypted, 1 is very weak, 2 is weak, and 3 is
   strong).

 - Second character is "`f`" if the suite offers forward secrecy, "`-`"
   otherwise.

 - Third character is "`A`" if the suite is anonymous (server is NOT
   authenticated), "`-`" otherwise.

This, "`3f-`" is good, and anything else is worrying to some degree.

The "`TLSv1.0: idem`" line means that TLS 1.0 is also supported, with
exactly the same list of cipher suites (and selection algorithm) as
SSL 3.0; otherwise, TestSSLServer would have listed the suite in the
same way as it did for SSL 3.0.

After the protocol versions and cipher suites, TestSSLServer lists out
the certificate chains sent by the server. Most servers will always send
the same chain, but some may have alternate chains (e.g. if the server
has both a RSA certificate and an ECDSA certificate, and chooses one or
the other depending on the selected cipher suite). Each chain is printed
out; certificates are given in SSL/TLS order (first certificate is the
server's own certificate, followed by the CA certificate which issued
it, and so on). For each certificate, the thumbprint, serial number,
subject and issuer DN, validity dates, key type, key size, curve name
(if appropriate), and hash function for signature, are printed,
optionally followed by the full certificate (PEM format) if requested
with `-certs`. The server names (`dNSName` in SAN extension) are also
printed for the first certificate in each chain.

After the certificate chains, TestSSLServer prints some more information,
as detailed for the JSON output: compression support, server system time,
support for secure renegotiation, minimum sizes for DH and ECDH parameters,
and supported named curves.

Finally, the list of warnings is printed, ordered by their 5-character
symbolic identifiers.

## Some Notes

### BEAST Attack

A previous version of TestSSLServer was "testing for BEAST". I removed
the explicit test because it was perennially misinterpreted, and the
remedy is worse.

BEAST attack is a _Chosen Plaintext Attack_ in which the attacker can
both observe the connection from the outside, _and_ dynamically choose
part of the data that gets encrypted in the tunnel; the target is a
secret data element that also gets encrypted at a predictable place. The
practical setup is hostile Javascript that issues requests to an
external server, and tries to extract the cookie value sent to that
server. The attack applies when using a block cipher in CBC mode with
SSL 3.0 or TLS 1.0 (TLS 1.1 and later are immune because they use
per-record random IV, while previous versions use the last block of each
record as IV for the next).

The BEAST attack no longer works, for two reasons:

 1. Actual exploit requires choosing the exact value of some specific
 bytes in the plaintext, and a Javascript code running in a Web browser
 under the cover of the SOP (Same Origin Policy) cannot do that. The
 demonstration had to resort to using a draft version of the WebSockets
 protocol, or a hole in the Java VM implementation, to be able to
 leverage the attacks. Both methods have long been fixed (and if they
 still apply on your browser, then your browser has not been updated for
 several years and you have a lot of much bigger holes to worry about).

 2. SSL/TLS libraries have implemented a generic workaround known as
 the "1/n-1 split", by which each record, upon sending, is split into
 two successive records, the first one containing a single byte of
 plaintext. The "1/n-1 split" is, conceptually, reusing a the MAC on
 each record as a randomization source for the IV for CBC encryption,
 which prevents the attack.

One should note that the BEAST attack happens on the client side, not on
the server. Nevertheless, there is a fashion for testing _the server_
for "BEAST vulnerability". The idea is that the server _may_ save a
vulnerable client, by enforcing use of a non-CBC cipher suite even if
the client would prefer a CBC cipher suite. Correspondingly, some tools
give good grades to servers that act that way.

Unfortunately, this is all wrong. As pointed out above, the BEAST attack
should not work, regardless of the server cipher suite selection
algorithm. On the other hand, enforcing a non-CBC cipher suite in SSL
3.0 and TLS 1.0 means using RC4, which has very real biases that are
_not_ fixed (and not fixable) in modern libraries. Trying to make the
server "BEAST secure" really means _lowering_ encryption security, not
increasing it. So don't do that.

If someone talks to you about BEAST, point them to the paragraph above.
Alternatively, if the auditor hordes prove impermeable to science and
just want to tick boxes in their checklists, disable SSL 3.0 and TLS 1.0
support altogether. You should not allow SSL 3.0 anyway.

### Weak Suites and Keys

In SSL/TLS, client and server negotiate security parameters. Therefore,
if both support strong cipher suites and keys, all should be fine,
even if they would potentially support weak cipher suites as well?

Not so fast. The handshake is protected: once the cryptography has
occurred, the client and server send verification messages (`Finished`),
protected by the newly negotiated algorithms and keys, and the contents
of these messages are basically a hash of all preceding messages,
including the `ClientHello`. Therefore, alterations by attackers, who
try to make client and server negotiate a weak cipher suite, should be
detected at that point. _Unless_ the weak cipher suite is so weak that
it can be broken right away, dynamically, so that the attacker can then
unravel the encryption in real time, and "fix" the `Finished` messages.

This is exactly what was done with the so-called "Logjam" and "FREAK"
attacks, that rely on support of export cipher suites with awfully weak
key exchange parameters (512-bit RSA or DH).

On a similar note, a recent attack ("DROWN" -- yet another example of
that weird fashion of witty acronyms) leverages SSL 2.0 support to break
a TLS key exchange that used the same private key. That attack is a
clear example of how support for a weak protocol version can be harmful
even if normal clients do not use it.

Therefore, **all weak cipher suites and keys should be disabled**.

### Un-warned Conditions

TestSSLServer's warnings are supposed to point at conditions for which
an actual vulnerability or possible weakness has been demonstrated. It
won't warn about configurations that are merely unfashionable. The most
conspicuous example is cipher suites that use MD5. MD5 is very weak with
regards to _collisions_; but when a cipher suite uses MD5 (e.g.
`RSA_WITH_RC4_128_MD5`), it does so as part of HMAC, and there is no
known way to break HMAC/MD5. Therefore, TestSSLServer does not emit a
warning for MD5 usage in a cipher suite, even though some other
SSL-testing tools may give a "bad grade" when MD5 is encountered.

`RSA_WITH_RC4_128_MD5` would still get a warning, though, because of
its use of RC4. And use of MD5 in the signature of a certificate would
also be reported, because that one can be unsafe.

### Untested Conditions

TestSSLServer does not try to push the server implementation to its
limits. Its goal is not to find implementation flaws, only configuration
flaws.

For instance, TestSSLServer does not try to test the quality of the
random generation on the server side; it does not either check that the
sent DH or ECDH parameters, or the server's public/private key pair, are
mathematically sound.

Since TestSSLServer never completes any handshake, it cannot test for
post-handshake options, in particular whether the server would allow
renegotiations at all.

Some tests that TestSSLServer does not perform right now, but may
implement in a future version:

 - Detection of support of other extensions such as Maximum Fragment
   Length, Truncated HMAC, or OCSP stapling.

 - Detection of reuse of (EC)DH parameters. In DHE and ECDHE cipher
   suites, the server sends ephemeral key exchange parameters, but it
   may keep them around for some time. The longer such parameters are
   reused, the less "forward secure" the connection becomes, so this is
   a trade-off between efficiency and security.

 - Support for session tickets (RFC 5077).

 - Better analysis of X.509 certificates. TestSSLServer could, for
   instance, try to validate the server chain with the platform-provided
   facilities (System.Security.Cryptography.X509Certificates). Ideally,
   it would include its own, extension X.509 validation library, but
   this is considerable work, both for development and maintenance, so
   it will probably not happen any time soon (or ever).

## Author

Question and comments can be sent to: Thomas Pornin `<pornin@bolet.org>`

Sometimes I even answer.
