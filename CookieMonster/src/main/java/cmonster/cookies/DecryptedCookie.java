package cmonster.cookies;

import java.io.File;
import java.util.Date;

public class DecryptedCookie extends EncryptedCookie {

	protected String decryptedValue;
	
	public DecryptedCookie(String name, byte[] encryptedValue, String decryptedValue, Date expires, String path, String domain, boolean secure, boolean httpOnly, File cookieStore) {
		super(name, encryptedValue, expires, path, domain, secure, httpOnly, cookieStore);
		this.decryptedValue = decryptedValue;
		this.value = decryptedValue;
	}
	
	public String getDecryptedValue(){
		return decryptedValue;
	}
	
	@Override
	public boolean isDecrypted() {
		return true;
	}
	
	@Override
	public String toString() {
		return "Cookie [name=" + name + ", value=" + decryptedValue + "]";
	}

}
