package cmonster.browsers;

import java.io.BufferedReader;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.jna.platform.win32.Crypt32Util;

import cmonster.cookies.Cookie;
import cmonster.cookies.DecryptedCookie;
import cmonster.cookies.EncryptedCookie;
import cmonster.utils.OS;

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
	
	@Override
	public String getName() {
		return "Chrome";
	}

    private String chromeKeyringPassword = null;
	private byte[] windowsMasterKey;

	public ChromeBrowser() {
        super();

        if (OS.isWindows()) {
            // Inspired by https://stackoverflow.com/a/65953409/1631104

            // Get encrypted master key
            String pathLocalState = System.getProperty("user.home") + "/AppData/Local/Google/Chrome/User Data/Local State".replaceAll("/", Matcher.quoteReplacement(File.separator));
            File localStateFile = new File(pathLocalState);

            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode jsonNode = null;
            try {
                jsonNode = objectMapper.readTree(localStateFile);
            } catch (IOException e) {
                throw new IllegalStateException("Failed to load JSON from Chrome Local State file", e);
            }

            String encryptedMasterKeyWithPrefixB64 = jsonNode.at("/os_crypt/encrypted_key").asText();

            // Remove prefix (DPAPI)
            byte[] encryptedMasterKeyWithPrefix = Base64.getDecoder().decode(encryptedMasterKeyWithPrefixB64);
            byte[] encryptedMasterKey = Arrays.copyOfRange(encryptedMasterKeyWithPrefix, 5, encryptedMasterKeyWithPrefix.length);

            // Decrypt and store the master key for use later
            this.windowsMasterKey = Crypt32Util.cryptUnprotectData(encryptedMasterKey);
        }
    }

    /**
     * Returns a set of cookie store locations
     */
    @Override
    protected Set<File> getCookieStores() {
        HashSet<File> cookieStores = new HashSet<>();
        String userHome = System.getProperty("user.home");

        String[] cookieDirectories = {
            "/AppData/Local/Google/Chrome/User Data".replaceAll("/", Matcher.quoteReplacement(File.separator)),
            "/Application Data/Google/Chrome/User Data".replaceAll("/", Matcher.quoteReplacement(File.separator)),
            "/Library/Application Support/Google/Chrome".replaceAll("/", Matcher.quoteReplacement(File.separator)),
            "/.config/chromium".replaceAll("/", Matcher.quoteReplacement(File.separator))
        };

        for (String cookieDirectory : cookieDirectories) {
            String baseDir = userHome + cookieDirectory;
            cookieStores.addAll(getCookieDbFiles(baseDir));
        }

        return cookieStores;
    }

    /**
     * In some cases, people set profiles for browsers, which would creates custom cookie files
     * @param baseDir
     */
    private List<File> getCookieDbFiles(String baseDir) {
        File filePath = new File(baseDir);
        if (filePath.exists() && filePath.isDirectory()) {
        	return Arrays.stream(filePath.listFiles(new FilenameFilter() {
        	    @Override
        	    public boolean accept(File dir, String name) {
        	        return name.endsWith("Cookies");
        	    }
        	})).collect(Collectors.toList());
        }
        return List.of();
    }

    /**
     * Processes all cookies in the cookie store for a given domain or all
     * domains if domainFilter is null/empty
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
        boolean httpOnly = determineHttpOnly(result);
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

    private boolean determineHttpOnly(ResultSet result) throws SQLException {
        boolean secure;
        try {
            secure = result.getBoolean("is_httponly");
        } catch (SQLException e) {
            secure = result.getBoolean("httponly");
        }
        return secure;
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
            // Separate prefix (v10), nonce and ciphertext/tag
            byte[] nonce = Arrays.copyOfRange(encryptedCookie.getEncryptedValue(), 3, 3 + 12);
            byte[] ciphertextTag = Arrays.copyOfRange(encryptedCookie.getEncryptedValue(), 3 + 12,
                    encryptedCookie.getEncryptedValue().length);

            // Decrypt
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, nonce);
                SecretKeySpec keySpec = new SecretKeySpec(windowsMasterKey, "AES");

                cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
                decryptedBytes = cipher.doFinal(ciphertextTag);
            }
            catch (Exception e) {
                throw new IllegalStateException("Error decrypting", e);
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
                byte[] iv = new byte[16];
                Arrays.fill(iv, (byte)' ');
                int keyLength = 16;

                int iterations = 1003;

                PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength * 8);
                SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");

                byte[] aesKey = pbkdf2.generateSecret(spec).getEncoded();

                SecretKeySpec keySpec = new SecretKeySpec(aesKey, "AES");

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));

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
