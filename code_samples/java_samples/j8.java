// InsecureService.java
// Training example with multiple issues: hardcoded creds, weak crypto, poor auth

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class InsecureService {

    private static final String USER = "admin";
    private static final String PASS = "admin123"; // hardcoded credential

    public static boolean checkAuth(String u, String p) {
        // naive auth: compares raw strings
        return USER.equals(u) && PASS.equals(p);
    }

    public static String weakHash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5"); // weak algorithm
            byte[] digest = md.digest(input.getBytes());
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java InsecureService <user> <pass>");
            return;
        }
        String u = args[0];
        String p = args[1];
        if (checkAuth(u, p)) {
            System.out.println("Authenticated: Welcome " + u);
            System.out.println("Server token: " + "server-token-XYZ"); // additional hardcoded token
        } else {
            System.out.println("Auth failed");
        }
        // Note: naive serialization example could be placed here; avoid using default Java serialization with untrusted data.
    }
}
