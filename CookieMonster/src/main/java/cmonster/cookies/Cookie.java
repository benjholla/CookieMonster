package cmonster.cookies;
import java.io.File;
import java.util.Date;

public abstract class Cookie {

	String name;
	private byte[] encryptedValue;
	private Date expires;
	private String path;
	private String domain;
	private boolean secure;
	private boolean httpOnly;
	private File cookieStore;
	
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
