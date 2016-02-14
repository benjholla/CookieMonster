package cmonster.cookies;

import java.io.File;
import java.util.Date;

public class EncryptedCookie extends Cookie {

	public EncryptedCookie(String name, byte[] encryptedValue, Date expires, String path, String domain, boolean secure, boolean httpOnly, File cookieStore) {
		super(name, encryptedValue, expires, path, domain, secure, httpOnly, cookieStore);
	}

	@Override
	public boolean isDecrypted() {
		return false;
	}
	
	@Override
	public String toString() {
		return "Cookie [name=" + name + " (encrypted)]";
	}

}
