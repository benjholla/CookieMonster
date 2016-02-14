package cmonster.browsers;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import cmonster.cookies.Cookie;
import cmonster.cookies.DecryptedCookie;
import cmonster.cookies.EncryptedCookie;
import cmonster.utils.OS;

import com.sun.jna.platform.win32.Crypt32Util;

/**
 * An implementation of Chrome cookie decryption logic for Mac, Windows, and Linux installs 
 * 
 * References: 
 * 1) http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
 * 2) https://github.com/markushuber/ssnoob
 * 
 * @author Ben Holland
 */
public class ChromeBrowser implements Browser {

	private String chromeKeyringPassword = null;
	
	/**
	 * Returns all cookies
	 */
	public Set<Cookie> getCookies() {
		HashSet<Cookie> cookies = new HashSet<Cookie>();
		for(File cookieStore : getCookieStores()){
			cookies.addAll(processCookies(cookieStore, null));
		}
		return cookies;
	}
	
	/**
	 * Returns cookies for a given domain
	 */
	public Set<Cookie> getCookiesForDomain(String domain) {
		HashSet<Cookie> cookies = new HashSet<Cookie>();
		for(File cookieStore : getCookieStores()){
			cookies.addAll(processCookies(cookieStore, domain));
		}
		return cookies;
	}
	
	/**
	 * Returns a set of cookie store locations
	 * @return
	 */
	protected Set<File> getCookieStores() {
		HashSet<File> cookieStores = new HashSet<File>();
		
		// pre Win7
		cookieStores.add(new File(System.getProperty("user.home") + "\\Application Data\\Google\\Chrome\\User Data\\Default\\Cookies"));
		
		// Win 7+
		cookieStores.add(new File(System.getProperty("user.home") + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies"));

		// Mac
		cookieStores.add(new File(System.getProperty("user.home") + "/Library/Application Support/Google/Chrome/Default/Cookies"));
		
		// Linux
		cookieStores.add(new File(System.getProperty("user.home") + "/.config/chromium/Default/Cookies"));
		
		return cookieStores;
	}
	
	/**
	 * Processes all cookies in the cookie store for a given domain or all domains if domainFilter is null
	 * @param cookieStore
	 * @param domainFilter
	 * @return
	 */
	protected Set<Cookie> processCookies(File cookieStore, String domainFilter) {
		HashSet<Cookie> cookies = new HashSet<Cookie>();
		if(cookieStore.exists()){
			Connection connection = null;
			try {
				File cookieStoreCopy = new File(".cookies.db");
				cookieStoreCopy.delete();
				Files.copy(cookieStore.toPath(), cookieStoreCopy.toPath());
				// load the sqlite-JDBC driver using the current class loader
				Class.forName("org.sqlite.JDBC");
				// create a database connection
				connection = DriverManager.getConnection("jdbc:sqlite:" + cookieStoreCopy.getAbsolutePath());
				Statement statement = connection.createStatement();
				statement.setQueryTimeout(30); // set timeout to 30 seconds
				ResultSet result = null;
				if(domainFilter == null || domainFilter.isEmpty()){
					result = statement.executeQuery("select * from cookies");
				} else {
					result = statement.executeQuery("select * from cookies where host_key like \"%" + domainFilter + "%\"");
				}
				while (result.next()) {
					String name = result.getString("name");
					byte[] encryptedBytes = result.getBytes("encrypted_value");
					String path = result.getString("path");
					String domain = result.getString("host_key");
					boolean secure = result.getBoolean("secure");
					boolean httpOnly = result.getBoolean("httponly");
					Date expires = result.getDate("expires_utc");

					EncryptedCookie encryptedCookie = new EncryptedCookie(name,
																		  encryptedBytes, 
																	      expires,
																	      path, 
																	      domain, 
																	      secure,
																	      httpOnly, 
																	      cookieStore);
					
					DecryptedCookie decryptedCookie = decrypt(encryptedCookie);
					
					if(decryptedCookie != null){
						cookies.add(decryptedCookie);
					} else {
						cookies.add(encryptedCookie);
					}
					cookieStoreCopy.delete();
				}
			} catch (Exception e) {
				e.printStackTrace();
				// if the error message is "out of memory",
				// it probably means no database file is found
			} finally {
				try {
					if (connection != null){
						connection.close();
					}
				} catch (SQLException e) {
					// connection close failed
				}
			}
		}
		return cookies;
	}

	/**
	 * Decrypts an encrypted cookie
	 * @param c
	 * @return
	 */
	protected DecryptedCookie decrypt(EncryptedCookie c) {
		byte[] decryptedBytes = null;
		if(OS.isWindows()){
			try {
				decryptedBytes = Crypt32Util.cryptUnprotectData(c.getEncryptedValue());
			} catch (Exception e){
				decryptedBytes = null;
			}
		} else if(OS.isLinux()){
			try {
				byte[] salt = "saltysalt".getBytes();
				char[] password = "peanuts".toCharArray();
				char[] iv = new char[16];
				Arrays.fill(iv, ' ');
				int keyLength = 16;

				int iterations = 1;

				PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength * 8);
				SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
				
				byte[] aesKey = pbkdf2.generateSecret(spec).getEncoded();
				
				SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
				
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(new String(iv).getBytes()));
				
				// if cookies are encrypted "v10" is a the prefix (has to be removed before decryption)
				byte[] encryptedBytes = c.getEncryptedValue();
				if (new String(c.getEncryptedValue()).startsWith("v10")) {
					encryptedBytes = Arrays.copyOfRange(encryptedBytes, 3, encryptedBytes.length);
				}
				decryptedBytes = cipher.doFinal(encryptedBytes);
			} catch (Exception e) {
				decryptedBytes = null;
			}
		} else if(OS.isMac()){
			// access the decryption password from the keyring manager
			if(chromeKeyringPassword == null){
				try {
					chromeKeyringPassword = getMacKeyringPassword("Chrome Safe Storage");
				} catch (IOException e) {
					decryptedBytes = null;
				}
			}
			try {
				byte[] salt = "saltysalt".getBytes();
				char[] password = chromeKeyringPassword.toCharArray();
				char[] iv = new char[16];
				Arrays.fill(iv, ' ');
				int keyLength = 16;

				int iterations = 1003;

				PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength * 8);
				SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
				
				byte[] aesKey = pbkdf2.generateSecret(spec).getEncoded();
				
				SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");
				
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(new String(iv).getBytes()));
				
				// if cookies are encrypted "v10" is a the prefix (has to be removed before decryption)
				byte[] encryptedBytes = c.getEncryptedValue();
				if (new String(c.getEncryptedValue()).startsWith("v10")) {
					encryptedBytes = Arrays.copyOfRange(encryptedBytes, 3, encryptedBytes.length);
				}
				decryptedBytes = cipher.doFinal(encryptedBytes);
			} catch (Exception e) {
				decryptedBytes = null;
			}
		}
		
		if(decryptedBytes == null){
			return null;
		} else {		
			return new DecryptedCookie(c.getName(),
									   c.getEncryptedValue(),
									   new String(decryptedBytes),
									   c.getExpires(),
									   c.getPath(),
									   c.getDomain(),
									   c.isSecure(),
									   c.isHttpOnly(),
									   c.getCookieStore());
		}
	}

	/**
	 * Accesses the apple keyring to retrieve the Chrome decryption password
	 * @param application
	 * @return
	 * @throws IOException
	 */
	private static String getMacKeyringPassword(String application) throws IOException {
		Runtime rt = Runtime.getRuntime();
		String[] commands = {"security", "find-generic-password","-w", "-s", application};
		Process proc = rt.exec(commands);
		BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
		String result = "";
		String s = null;
		while ((s = stdInput.readLine()) != null) {
			result += s;
		}
		return result;
	}

}
