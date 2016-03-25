using System;
using System.Collections.Generic;

class SupportedCipherSuites {

	internal int[] Suites {
		get {
			return suites;
		}
		set {
			suites = value;
		}
	}

	internal bool PrefClient {
		get {
			return prefClient;
		}
		set {
			prefClient = value;
		}
	}

	internal bool PrefServer {
		get {
			return prefServer;
		}
		set {
			prefServer = value;
		}
	}

	int[] suites;
	bool prefClient;
	bool prefServer;

	internal SupportedCipherSuites(int[] suites)
	{
		this.suites = suites;
		prefClient = false;
		prefServer = false;
	}

	/*
	 * Among the supported cipher suites, get the list of suites
	 * that are known to use elliptic curves for the key exchange.
	 */
	internal int[] GetKnownECSuites()
	{
		List<int> r = new List<int>();
		foreach (int s in suites) {
			CipherSuite cs;
			if (!CipherSuite.ALL.TryGetValue(s, out cs)) {
				continue;
			}
			if (cs.IsECDHE) {
				r.Add(s);
			}
		}
		return r.ToArray();
	}

	internal bool Equals(SupportedCipherSuites scs)
	{
		if (scs == null) {
			return false;
		}
		if (prefClient != scs.prefClient
			|| prefServer != scs.prefServer)
		{
			return false;
		}
		return M.Equals(suites, scs.suites);
	}

	internal static bool Equals(
		SupportedCipherSuites scs1, SupportedCipherSuites scs2)
	{
		if (scs1 == scs2) {
			return true;
		}
		if (scs1 == null || scs2 == null) {
			return false;
		}
		return scs1.Equals(scs2);
	}
}
