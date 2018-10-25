package cmonster.cookies;
import java.io.File;
import java.util.Date;

public class Cookie {

	protected String name;
	protected String value;
	protected Date expires;
	protected String path;
	protected String domain;
	protected boolean secure;
	protected boolean httpOnly;
	protected File cookieStore;
	
	/**
	 * Represents an unencrypted cookie
	 * @param name
	 * @param value
	 * @param expires
	 * @param path
	 * @param domain
	 * @param secure
	 * @param httpOnly
	 * @param cookieStore
	 */
	public Cookie(String name, String value, Date expires, String path, String domain, boolean secure, boolean httpOnly, File cookieStore) {
		this.name = name;
		this.value = value;
		this.expires = expires;
		this.path = path;
		this.domain = domain;
		this.secure = secure;
		this.httpOnly = httpOnly;
		this.cookieStore = cookieStore;
	}
	
	public Cookie(String name, Date expires, String path, String domain, boolean secure, boolean httpOnly, File cookieStore) {
		this.name = name;
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
	
	public String getValue() {
		return value;
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

	@Override
	public String toString() {
		return "Cookie [name=" + name + ", value=" + value + "]";
	}
}
