package cmonster.browsers;

import java.io.File;
import java.util.HashSet;
import java.util.Set;

import cmonster.cookies.Cookie;
import cmonster.cookies.DecryptedCookie;
import cmonster.cookies.EncryptedCookie;

public class SafariBrowser extends Browser {
	
	@Override
	public String getName() {
		return "Safari";
	}
	
	@Override
    public Set<Cookie> getCookiesForDomain(String name, String domain) {
        return null;
    }

    @Override
	protected Set<File> getCookieStores() {
		HashSet<File> cookieStores = new HashSet<File>();

		// TODO: implement
		
		return cookieStores;
	}

	@Override
	protected Set<Cookie> processCookies(File cookieStore, String domainFilter) {
		// TODO: Implement
		return null;
	}

	@Override
	protected DecryptedCookie decrypt(EncryptedCookie encryptedCookie) {
		// TODO: Implement
		return null;
	}
	
}
