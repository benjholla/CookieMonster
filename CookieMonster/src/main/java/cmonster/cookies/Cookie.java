package cmonster.cookies;
import java.io.File;
import java.util.Date;

public abstract class Cookie {

	protected String name;
	protected byte[] encryptedValue;
	protected Date expires;
	protected String path;
	protected String domain;
	protected boolean secure;
	protected boolean httpOnly;
	protected File cookieStore;
	
	public Cookie(String name, byte[] encryptedValue, Date expires, String path, String domain, boolean secure, boolean httpOnly, File cookieStore) {
		this.name = name;
		this.encryptedValue = encryptedValue;
		this.expires = expires;
		this.path = path;
		this.domain = domain;
		this.secure = secure;
		this.httpOnly = httpOnly;
		this.cookieStore = cookieStore;
	}
	
	public String getName() {
		return name;
	}

	public byte[] getEncryptedValue() {
		return encryptedValue;
	}

	public Date getExpires() {
		return expires;
	}

	public String getPath() {
		return path;
	}

	public String getDomain() {
		return domain;
	}

	public boolean isSecure() {
		return secure;
	}

	public boolean isHttpOnly() {
		return httpOnly;
	}
	
	public File getCookieStore(){
		return cookieStore;
	}
	
	public abstract boolean isDecrypted();

}
