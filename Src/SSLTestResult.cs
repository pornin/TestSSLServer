using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/*
 * An instance of SSLTestResult contains the data obtained from a
 * test connection.
 */

class SSLTestResult {

	/*
	 * Protocol version selected by the server (in the ServerHello).
	 */
	internal int Version {
		get {
			return version;
		}
	}

	/*
	 * Protocol version used by the server for record headers.
	 */
	internal int RecordVersion {
		get {
			return recordVersion;
		}
	}

	/*
	 * Server time, from the server random.
	 * (Expressed in milliseconds since Jan 1st, 1970, 00:00:00 UTC,
	 * skipping leap seconds.)
	 */
	internal long TimeMillis {
		get {
			return timeMillis;
		}
	}

	/*
	 * Session ID sent by the server.
	 */
	internal byte[] SessionID {
		get {
			return sessionID;
		}
	}

	/*
	 * Cipher suite selected by the server.
	 */
	internal int SelectedCipherSuite {
		get {
			return selectedCipherSuite;
		}
	}

	/*
	 * This flag is set to true if the cipher suite selected by
	 * the server was among the suites sent by the client. Some
	 * flawed servers try to use cipher suites not advertised by
	 * the client.
	 */
	internal bool CipherSuiteInClientList {
		get {
			return cipherSuiteInClientList;
		}
		set {
			cipherSuiteInClientList = value;
		}
	}

	/*
	 * True if the server selected deflate compression.
	 */
	internal bool DeflateCompress {
		get {
			return deflateCompress;
		}
	}

	/*
	 * Secure renegotiation information sent by the server (null if
	 * no such extension was sent).
	 */
	internal byte[] RenegotiationInfo {
		get {
			return renegInfo;
		}
	}

	/*
	 * Set to true if the server sent a ServerKeyExchange that we
	 * could not understand.
	 */
	internal bool UnknownSKE {
		get {
			return unknownSKE;
		}
	}

	/*
	 * True if the server sent a ServerHello but then failed to
	 * complete the handshake (some flawed servers do that, usually
	 * because of a misconfiguration that pretends that a particular
	 * cipher suite is supported, but some needed piece is missing
	 * on the server).
	 */
	internal bool FailedAfterHello {
		get {
			return failedAfterHello;
		}
	}

	/*
	 * The server certificate. May be null if the server sent an
	 * empty chain, or for cipher suites which do not use
	 * certificates.
	 */
	internal byte[] Certificate {
		get {
			return certificate;
		}
	}

	/*
	 * Get certificate chain in the order returned by the server
	 * (nominally reverse order). This is null if the server did
	 * not send any Certificate message.
	 */
	internal byte[][] CertificateChain {
		get {
			return certificateChain;
		}
	}

	/*
	 * Get the size used for a classic DHE key exchange (also applies to
	 * DH_anon and SRP). If there was no such key exchange, then 0
	 * is returned.
	 */
	internal int DHSize {
		get {
			return dhSize;
		}
	}

	/*
	 * Get the size used for an ECDHE key exchange (also applies to
	 * ECDH_anon). If there was no such key exchange, then 0 is
	 * returned.
	 */
	internal int ECSize {
		get {
			return ecSize;
		}
	}

	/*
	 * Get the curve used for an ECDHE key exchange (also applies to
	 * ECDH_anon). This is set only if a named curved was used, and
	 * the curve was recognized; otherwise, this property returns
	 * null.
	 */
	internal SSLCurve Curve {
		get {
			return curve;
		}
	}

	/*
	 * Set to true if the server sent an "explicit prime" curve.
	 */
	internal bool CurveExplicitPrime {
		get {
			return curveExplicitPrime;
		}
	}

	/*
	 * Set to true if the server sent an "explicit char2" curve.
	 */
	internal bool CurveExplicitChar2 {
		get {
			return curveExplicitChar2;
		}
	}

	int version;
	int recordVersion;
	long timeMillis;
	byte[] sessionID;
	int selectedCipherSuite;
	bool cipherSuiteInClientList;
	bool deflateCompress;
	byte[] renegInfo;
	bool unknownSKE;
	bool failedAfterHello;
	byte[] certificate;
	byte[][] certificateChain;
	int dhSize;
	int ecSize;
	bool curveExplicitPrime;
	bool curveExplicitChar2;
	SSLCurve curve;

	/*
	 * A new empty instance.
	 */
	internal SSLTestResult()
	{
	}

	/*
	 * Parse messages from the server: from ServerHello to
	 * ServerHelloDone.
	 */
	internal void Parse(SSLRecord rec)
	{
		rec.SetExpectedType(M.HANDSHAKE);

		/*
		 * First parse a ServerHello.
		 */
		HMParser sh = new HMParser(rec);
		if (sh.MessageType != M.SERVER_HELLO) {
			throw new Exception("Not a ServerHello");
		}
		version = sh.Read2();
		byte[] serverRandom = sh.ReadBlobFixed(32);
		timeMillis = 1000 * (long)M.Dec32be(serverRandom, 0);
		sessionID = sh.ReadBlobVar(1);
		if (sessionID.Length > 32) {
			throw new Exception("Oversized session ID");
		}
		selectedCipherSuite = sh.Read2();
		int cm = sh.Read1();
		if (cm == 0) {
			deflateCompress = false;
		} else if (cm == 1) {
			deflateCompress = true;
		} else {
			throw new Exception(
				"Unknown compression method: " + cm);
		}
		if (!sh.EndOfStruct) {
			sh.OpenVar(2);
			Dictionary<int, bool> d = new Dictionary<int, bool>();
			while (!sh.EndOfStruct) {
				int extType = sh.Read2();
				if (d.ContainsKey(extType)) {
					throw new Exception(
						"Duplicate extension: "
						+ extType);
				}
				d[extType] = true;
				sh.OpenVar(2);
				switch (extType) {
				case M.EXT_SERVER_NAME:
					ParseEmptyServerName(sh);
					break;
				case M.EXT_RENEGOTIATION_INFO:
					ParseRenegInfo(sh);
					break;
				case M.EXT_SUPPORTED_CURVES:
					ParseSupportedCurves(sh);
					break;
				case M.EXT_SUPPORTED_EC_POINTS:
					ParseSupportedECPoints(sh);
					break;
				default:
					throw new Exception(
						"Unknown extension: "
						+ extType);
				}
				sh.Close();
			}
			sh.Close();
		}
		sh.Close();

		/*
		 * Read other messages, up to the ServerHelloDone.
		 */
		try {
			bool seenSHD = false;
			while (!seenSHD) {
				HMParser hm = new HMParser(rec);
				switch (hm.MessageType) {
				case M.CERTIFICATE:
					ParseCertificate(hm);
					break;
				case M.SERVER_KEY_EXCHANGE:
					ParseServerKeyExchange(hm);
					break;
				case M.CERTIFICATE_REQUEST:
					ParseCertificateRequest(hm);
					break;
				case M.SERVER_HELLO_DONE:
					hm.Close();
					seenSHD = true;
					break;
				default:
					hm.Close(true);
					break;
				}
			}
		} catch {
			failedAfterHello = true;
		}

		recordVersion = rec.GetInVersion();
	}

	void ParseEmptyServerName(HMParser sh)
	{
		/*
		 * The SNI extension from the server is supposed to have
		 * empty contents.
		 */
	}

	void ParseRenegInfo(HMParser sh)
	{
		renegInfo = sh.ReadBlobVar(1);
	}

	void ParseSupportedCurves(HMParser sh)
	{
		/*
		 * TODO: see if we should parse this information. The
		 * server sends that extension after seeing the client's
		 * ClientHello, so it may "lie" about its actual abilities.
		 */
		sh.SkipRemainder();
	}

	void ParseSupportedECPoints(HMParser sh)
	{
		/*
		 * TODO: see if we should parse this information. The
		 * server sends that extension after seeing the client's
		 * ClientHello, so it may "lie" about its actual abilities.
		 */
		sh.SkipRemainder();
	}

	void ParseCertificate(HMParser hm)
	{
		if (certificateChain != null) {
			throw new Exception("Duplicate Certificate message");
		}
		List<byte[]> chain = new List<byte[]>();
		hm.OpenVar(3);
		while (!hm.EndOfStruct) {
			chain.Add(hm.ReadBlobVar(3));
		}
		hm.Close();
		hm.Close();
		certificateChain = chain.ToArray();
		certificate = (chain.Count > 0) ? chain[0] : null;
	}

	void ParseServerKeyExchange(HMParser hm)
	{
		try {
			ParseServerKeyExchangeInner(hm);
		} catch (Exception e) {
			throw e;
		}
	}

	void ParseServerKeyExchangeInner(HMParser hm)
	{
		CipherSuite cs;
		if (!CipherSuite.ALL.TryGetValue(selectedCipherSuite, out cs)) {
			unknownSKE = true;
			hm.Close(true);
			return;
		}
		if (cs.IsDHE) {
			/*
			 * If this is DHE_PSK, then there is first a
			 * "key hint" to skip.
			 */
			if (cs.IsPSK) {
				hm.ReadBlobVar(2);
			}

			/*
			 * DH parameters: p, g, y. We are only interested
			 * in p.
			 */
			byte[] p = hm.ReadBlobVar(2);
			dhSize = M.BitLength(p);
			hm.ReadBlobVar(2);
			hm.ReadBlobVar(2);
			if (cs.ServerKeyType != "none") {
				if (version >= M.TLSv12) {
					/*
					 * Hash-and-sign identifiers.
					 */
					hm.Read2();
				}
				hm.ReadBlobVar(2);
			}
		} else if (cs.IsECDHE) {
			/*
			 * If this is ECDHE_PSK, then there is first a
			 * "key hint" to skip.
			 */
			if (cs.IsPSK) {
				hm.ReadBlobVar(2);
			}

			/*
			 * Read curve type: one byte.
			 */
			switch (hm.Read1()) {
			case 1:
				/*
				 * explicit_prime: p, a, b, G,
				 * order, cofactor.
				 */
				hm.ReadBlobVar(1);
				hm.ReadBlobVar(1);
				hm.ReadBlobVar(1);
				hm.ReadBlobVar(1);
				ecSize = M.AdjustedBitLength(hm.ReadBlobVar(1));
				hm.ReadBlobVar(1);
				curveExplicitPrime = true;
				break;
			case 2:
				/* explicit_char2 */
				hm.Read2();
				switch (hm.Read1()) {
				case 1:
					/* trinomial */
					hm.ReadBlobVar(1);
					break;
				case 2:
					/* pentanomial */
					hm.ReadBlobVar(1);
					hm.ReadBlobVar(1);
					hm.ReadBlobVar(1);
					break;
				default:
					hm.Close(true);
					unknownSKE = true;
					return;
				}
				hm.ReadBlobVar(1);
				hm.ReadBlobVar(1);
				hm.ReadBlobVar(1);
				ecSize = M.AdjustedBitLength(hm.ReadBlobVar(1));
				hm.ReadBlobVar(1);
				curveExplicitChar2 = true;
				break;
			case 3:
				/*
				 * named_curve.
				 */
				int id = hm.Read2();
				if (SSLCurve.ALL.TryGetValue(id, out curve)) {
					ecSize = curve.Size;
				} else {
					curve = null;
					hm.Close(true);
					unknownSKE = true;
					return;
				}
				break;
			default:
				hm.Close(true);
				unknownSKE = true;
				return;
			}

			/*
			 * Read public key: one curve point.
			 */
			hm.ReadBlobVar(1);
			if (cs.ServerKeyType != "none") {
				if (version >= M.TLSv12) {
					/*
					 * Hash-and-sign identifiers.
					 */
					hm.Read2();
				}
				hm.ReadBlobVar(2);
			}
		} else if (cs.IsRSAExport) {
			/*
			 * If cipher suite uses RSA key exchange and is
			 * flagged "export" then it may send an ephemeral
			 * RSA key pair, which will be weak and probably
			 * not very ephemeral, since RSA key pair generation
			 * is kinda expensive.
			 *
			 * Format: modulus, public exponent, signature.
			 */
			hm.ReadBlobVar(2);
			hm.ReadBlobVar(2);
			if (version >= M.TLSv12) {
				/*
				 * Hash-and-sign identifiers.
				 */
				hm.Read2();
			}
			hm.ReadBlobVar(2);
		} else if (cs.IsSRP) {
			/*
			 * SRP parameters are: N, g, s, B. N is the
			 * modulus.
			 */
			dhSize = M.BitLength(hm.ReadBlobVar(2));
			hm.ReadBlobVar(2);
			hm.ReadBlobVar(1);
			hm.ReadBlobVar(2);

			/*
			 * RFC 5054 says that there is a signature,
			 * except if the server sent no certificate. What
			 * happens at the encoding level is unclear, so
			 * we skip the remaining bytes.
			 */
			hm.SkipRemainder();
		} else if (cs.IsPSK) {
			/*
			 * Key hint from the server.
			 */
			hm.ReadBlobVar(2);
		} else {
			throw new IOException("Unexpected ServerKeyExchange");
		}
		hm.Close();
	}

	void ParseCertificateRequest(HMParser hm)
	{
		// TODO: extract CA names.
		hm.Close(true);
	}
}
