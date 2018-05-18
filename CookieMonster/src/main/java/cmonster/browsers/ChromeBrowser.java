package cmonster.browsers;

import cmonster.cookies.Cookie;
import cmonster.cookies.DecryptedCookie;
import cmonster.cookies.EncryptedCookie;
import cmonster.utils.OS;
import com.sun.jna.platform.win32.Crypt32Util;
import org.apache.maven.shared.utils.io.DirectoryScanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.sql.*;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * An implementation of Chrome cookie decryption logic for Mac, Windows, and Linux installs
 * <p>
 * References:
 * 1) http://n8henrie.com/2014/05/decrypt-chrome-cookies-with-python/
 * 2) https://github.com/markushuber/ssnoob
 *
 * @author Ben Holland
 */
public class ChromeBrowser extends Browser {

    private String chromeKeyringPassword = null;

    /**
     * Returns a set of cookie store locations
     */
    @Override
    protected Set<File> getCookieStores() {
        HashSet<File> cookieStores = new HashSet<>();
        String userHome = System.getProperty("user.home");

        String[] cookieDirectories = {
            "/AppData/Local/Google/Chrome/User Data",
            "/Application Data/Google/Chrome/User Data",
            "/Library/Application Support/Google/Chrome",
            "/.config/chromium"
        };

        for (String cookieDirectory : cookieDirectories) {
            String baseDir = userHome + cookieDirectory;
            String[] files = getCookieDbFiles(baseDir);
            if (files != null && files.length > 0) {
                for (String file : files) {
                    cookieStores.add(new File(baseDir + "/" + file));
                }
            }
        }

        return cookieStores;
    }

    /**
     * In come case, people could set profile for browsers, would create custom cookie files
     * @param baseDir
     * @author <a href="mailto:kbalbertyu@gmail.com">Albert Yu</a> 5/26/2017 1:40 PM
     */
    private String[] getCookieDbFiles(String baseDir) {
        String[] files = null;
        File filePath = new File(baseDir);
        if (filePath.exists() && filePath.isDirectory()) {
            DirectoryScanner ds = new DirectoryScanner();
            String[] includes = {"*/Cookies"};
            ds.setIncludes(includes);
            ds.setBasedir(new File(baseDir));
            ds.setCaseSensitive(true);
            ds.scan();
            files = ds.getIncludedFiles();
        }
        return files;
    }


    /**
     * Processes all cookies in the cookie store for a given domain or all
     * domains if domainFilter is null
     */
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
                    result = statement.executeQuery("select * from cookies");
                } else {
                    result = statement.executeQuery("select * from cookies where host_key like \"%" + domainFilter + "%\"");
                }
                while (result.next()) {
                    String name = result.getString("name");
                    parseCookieFromResult(cookieStore, name, cookies, result);
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

    /**
     * Returns cookies for cookie key with given domain
     */
    @Override
    public Set<Cookie> getCookiesForDomain(String name, String domain) {
        HashSet<Cookie> cookies = new HashSet<>();
        for(File cookieStore : getCookieStores()){
            cookies.addAll(getCookiesByName(cookieStore, name, domain));
        }
        return cookies;
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
                    result = statement.executeQuery(String.format("select * from cookies where name = '%s'", name));
                } else {
                    result = statement.executeQuery("select * from cookies where name = '" + name + "' and host_key like '%" + domainFilter + "'");
                }
                while (result.next()) {
                    parseCookieFromResult(cookieStore, name, cookies, result);
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

    private void parseCookieFromResult(File cookieStore, String name, HashSet<Cookie> cookies, ResultSet result) throws SQLException {
        byte[] encryptedBytes = result.getBytes("encrypted_value");
        String path = result.getString("path");
        String domain = result.getString("host_key");
        boolean secure = determineSecure(result);
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

        if (decryptedCookie != null) {
            cookies.add(decryptedCookie);
        } else {
            cookies.add(encryptedCookie);
        }
        cookieStoreCopy.delete();
    }

    private boolean determineSecure(ResultSet result) throws SQLException {
        boolean secure;
        try {
            secure = result.getBoolean("secure");
        } catch (SQLException e) {
            secure = result.getBoolean("is_secure");
        }
        return secure;
    }

    /**
     * Decrypts an encrypted cookie
     */
    @Override
    protected DecryptedCookie decrypt(EncryptedCookie encryptedCookie) {
        byte[] decryptedBytes = null;
        if (OS.isWindows()) {
            try {
                decryptedBytes = Crypt32Util.cryptUnprotectData(encryptedCookie.getEncryptedValue());
            } catch (Exception e) {
                decryptedBytes = null;
            }
        } else if (OS.isLinux()) {
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
                byte[] encryptedBytes = encryptedCookie.getEncryptedValue();
                if (new String(encryptedCookie.getEncryptedValue()).startsWith("v10")) {
                    encryptedBytes = Arrays.copyOfRange(encryptedBytes, 3, encryptedBytes.length);
                }
                decryptedBytes = cipher.doFinal(encryptedBytes);
            } catch (Exception e) {
                decryptedBytes = null;
            }
        } else if (OS.isMac()) {
            // access the decryption password from the keyring manager
            if (chromeKeyringPassword == null) try {
                chromeKeyringPassword = getMacKeyringPassword("Chrome Safe Storage");
            } catch (IOException ignored) {
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
                byte[] encryptedBytes = encryptedCookie.getEncryptedValue();
                if (new String(encryptedCookie.getEncryptedValue()).startsWith("v10")) {
                    encryptedBytes = Arrays.copyOfRange(encryptedBytes, 3, encryptedBytes.length);
                }
                decryptedBytes = cipher.doFinal(encryptedBytes);
            } catch (Exception e) {
                decryptedBytes = null;
            }
        }

        if (decryptedBytes == null) {
            return null;
        } else {
            return new DecryptedCookie(encryptedCookie.getName(),
                encryptedCookie.getEncryptedValue(),
                new String(decryptedBytes),
                encryptedCookie.getExpires(),
                encryptedCookie.getPath(),
                encryptedCookie.getDomain(),
                encryptedCookie.isSecure(),
                encryptedCookie.isHttpOnly(),
                encryptedCookie.getCookieStore());
        }
    }

    /**
     * Accesses the apple keyring to retrieve the Chrome decryption password
     *
     * @param application
     * @return
     * @throws IOException
     */
    private static String getMacKeyringPassword(String application) throws IOException {
        Runtime rt = Runtime.getRuntime();
        String[] commands = {"security", "find-generic-password", "-w", "-s", application};
        Process proc = rt.exec(commands);
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        StringBuilder result = new StringBuilder();
        String s;
        while ((s = stdInput.readLine()) != null) {
            result.append(s);
        }
        return result.toString();
    }
}
