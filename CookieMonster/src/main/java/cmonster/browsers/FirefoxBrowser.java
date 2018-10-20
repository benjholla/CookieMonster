package cmonster.browsers;

import java.io.File;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import cmonster.cookies.Cookie;
import cmonster.cookies.DecryptedCookie;
import cmonster.cookies.EncryptedCookie;

public class FirefoxBrowser extends Browser {

	@Override
	public String getName() {
		return "Firefox";
	}
	
	@Override
	public Set<Cookie> getCookiesForDomain(String name, String domain) {
		HashSet<Cookie> cookies = new HashSet<>();
		for (File cookieStore : getCookieStores()) {
			cookies.addAll(getCookiesByName(cookieStore, name, domain));
		}
		return cookies;
	}

    @Override
	protected Set<File> getCookieStores() {
		HashSet<File> cookieStores = new HashSet<File>();
		File baseDirectory = new File(System.getProperty("user.home") + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\");
		if(baseDirectory.exists()) {
			for(File profile : baseDirectory.listFiles()) {
				if(profile.isDirectory() && profile.getName().endsWith(".default")) {
					for(File file : profile.listFiles()) {
						if(file.isFile() && file.getName().equals("cookies.sqlite")) {
							cookieStores.add(file);
						}
					}
				}
			}
		}
		return cookieStores;
	}
    
    private Set<Cookie> getCookiesByName(File cookieStore, String name, String domainFilter) {
        HashSet<Cookie> cookies = new HashSet<>();
        if (cookieStore.exists()) {
            Connection connection = null;
            try {
                cookieStoreCopy.delete();
                Files.copy(cookieStore.toPath(), cookieStoreCopy.toPath());
                // load the sqlite-JDBC driver using the current class loader
                Class.forName("org.sqlite.JDBC");
                // create a database connection
                connection = DriverManager.getConnection("jdbc:sqlite:" + cookieStoreCopy.getAbsolutePath());
                Statement statement = connection.createStatement();
                statement.setQueryTimeout(30); // set timeout to 30 seconds
                ResultSet result;
                if (domainFilter == null || domainFilter.isEmpty()) {
                    result = statement.executeQuery(String.format("select * from moz_cookies where name = '%s'", name));
                } else {
                    result = statement.executeQuery("select * from moz_cookies where name = '" + name + "' and host like '%" + domainFilter + "'");
                }
                while (result.next()) {
                    parseCookieFromResult(cookieStore, cookies, result);
                }
            } catch (Exception e) {
                e.printStackTrace();
                // if the error message is "out of memory",
                // it probably means no database file is found
            } finally {
                try {
                    if (connection != null) {
                        connection.close();
                    }
                } catch (SQLException e) {
                    // connection close failed
                }
            }
        }
        return cookies;
    }

	@Override
	protected Set<Cookie> processCookies(File cookieStore, String domainFilter) {
		 HashSet<Cookie> cookies = new HashSet<>();
	        if (cookieStore.exists()) {
	            Connection connection = null;
	            try {
	                cookieStoreCopy.delete();
	                Files.copy(cookieStore.toPath(), cookieStoreCopy.toPath());
	                // load the sqlite-JDBC driver using the current class loader
	                Class.forName("org.sqlite.JDBC");
	                // create a database connection
	                connection = DriverManager.getConnection("jdbc:sqlite:" + cookieStoreCopy.getAbsolutePath());
	                Statement statement = connection.createStatement();
	                statement.setQueryTimeout(30); // set timeout to 30 seconds
	                ResultSet result;
	                if (domainFilter == null || domainFilter.isEmpty()) {
	                    result = statement.executeQuery("select * from moz_cookies");
	                } else {
	                    result = statement.executeQuery("select * from moz_cookies where host like \"%" + domainFilter + "%\"");
	                }
	                while (result.next()) {
	                    parseCookieFromResult(cookieStore, cookies, result);
	                }
	            } catch (Exception e) {
	                e.printStackTrace();
	                // if the error message is "out of memory",
	                // it probably means no database file is found
	            } finally {
	                try {
	                    if (connection != null) {
	                        connection.close();
	                    }
	                } catch (SQLException e) {
	                    // connection close failed
	                }
	            }
	        }
	        return cookies;
	}

	private void parseCookieFromResult(File cookieStore, HashSet<Cookie> cookies, ResultSet result) throws SQLException {
		String name = result.getString("name");
		String value = result.getString("value");
		String path = result.getString("path");
		String domain = result.getString("host");
		boolean secure = result.getBoolean("isSecure");
		boolean httpOnly = result.getBoolean("isHttpOnly");
		Date expires = result.getDate("expiry");
		cookies.add(new Cookie(name, value, expires, path, domain, secure, httpOnly, cookieStore));
	}

	@Override
	protected DecryptedCookie decrypt(EncryptedCookie encryptedCookie) {
		return null;
	}
}
