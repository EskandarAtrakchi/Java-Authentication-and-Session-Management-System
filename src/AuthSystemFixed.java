import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Secure AuthSystem
 * - PBKDF2WithHmacSHA256 password hashing with per-user salt
 * ## PBKDF2WithHmacSHA256: unique per-user salt ensures that identical passwords produce distinct hashes
 * - Constant-time comparisons
 * - Fake hash verification to prevent user enumeration
 * - Account lockout after configurable failed attempts
 * - Cryptographically secure session tokens stored as hashes
 * 
 * NOTE: I will not use any external databases, for example MySQL, I will keep using the in-memory maps as in the original code for simplicity.
 */
public class AuthSystemFixed {

    private static final SecureRandom RNG = new SecureRandom();

    // PBKDF2 parameters
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";
    private static final int SALT_LEN = 16; // this is bytes
    private static final int DERIVED_KEY_LEN = 32 * 8; // this is bits
    private static final int ITERATIONS = 200_000; // reasonable modern cost

    // setting the lockout policy.
    private static final int MAX_FAILED_ATTEMPTS = 2;
    private static final long LOCKOUT_DURATION_MS = 15 * 60 * 1000L; // 15 minutes

    // Session policy
    private static final int SESSION_TOKEN_BYTES = 32; // 256-bit token
    private static final long SESSION_TTL_MS = 30 * 60 * 1000L; // 30 minutes

    // In-memory stores (thread safe) as I said above I will not change the structure of the database, I will keep it storage within 
    private final Map<String, User> users = new ConcurrentHashMap<>();
    // store SHA-256(sessionToken) -> Session
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    private static class User {
        final byte[] salt;             // per-user salt
        final byte[] passwordHash;     // result of PBKDF2
        final int iterations;
        volatile int failedAttempts = 0; //no violations allowed
        volatile long lockoutExpiry = 0L; // timestamp until which account is locked and no violations allowed 

        //taking the same structure as the original code and adding to it iterations and salt 
        User(byte[] salt, byte[] passwordHash, int iterations) {
            this.salt = salt;
            this.passwordHash = passwordHash;
            this.iterations = iterations;
        }
    }

    //adding the session class to store the username and expiry time
    private static class Session {
        final String username;
        final long expiry;

        // constructor to initialize session
        Session(String username, long expiry) {
            this.username = username;
            this.expiry = expiry;
        }
    }

    /**
     * Registers a new user. Returns true on success, false if username exists.
     */
    public boolean register(String username, String password) {
        if (username == null || password == null) return false;
        // Avoid race by putIfAbsent
        if (users.containsKey(username)) return false;

        byte[] salt = generateSalt();
        byte[] hash = derivePassword(password.toCharArray(), salt, ITERATIONS, DERIVED_KEY_LEN);
        User user = new User(salt, hash, ITERATIONS);
        return users.putIfAbsent(username, user) == null;
        // putIfAbsent: If the specified key is not already associated with a value (or is mapped to null) associates it with the given value and returns null, else returns the current value.


    }

    /**
     * Attempts login. Returns a session token on success, null on failure.
     * I want to do this method to avoid user enumeration and uses constant time comparisons.
     */
    public String login(String username, String password) {
        if (username == null || password == null) return null;

        User user = users.get(username);

        // If user not found, perform a fake PBKDF2 to make timing similar, I know this might seem unnecessary but it's important for security and timing, so I had to add it.
        if (user == null) {
            // fake salt and hash
            byte[] fakeSalt = new byte[SALT_LEN];
            RNG.nextBytes(fakeSalt);
            byte[] fakeHash = derivePassword(password.toCharArray(), fakeSalt, ITERATIONS, DERIVED_KEY_LEN);
            // compare to another random value in constant time
            byte[] randomCompare = new byte[fakeHash.length];
            RNG.nextBytes(randomCompare);
            constantTimeEquals(fakeHash, randomCompare);
            return null; // Generic failure
        }

        // Check lockout
        long now = System.currentTimeMillis();
        if (user.lockoutExpiry > now) {
            // still locked
            // Perform a fake verification to keep timing consistent
            byte[] fakeHash = derivePassword(password.toCharArray(), user.salt, user.iterations, DERIVED_KEY_LEN);
            constantTimeEquals(fakeHash, user.passwordHash);
            return null;
        }

        // Verify password using PBKDF2 with user's salt & iterations
        byte[] candidateHash = derivePassword(password.toCharArray(), user.salt, user.iterations, DERIVED_KEY_LEN);
        boolean match = constantTimeEquals(candidateHash, user.passwordHash);

        if (match) {
            // Reset counters on success
            user.failedAttempts = 0;
            user.lockoutExpiry = 0L;
            // create session
            String token = generateSessionToken();
            String tokenHash = sha256Base64(token);
            sessions.put(tokenHash, new Session(username, now + SESSION_TTL_MS));
            return token; // raw token returned to client — server keeps only its hash
        } else {
            // increment failed attempts and possibly lock
            int attempts = ++user.failedAttempts;
            if (attempts >= MAX_FAILED_ATTEMPTS) {
                user.lockoutExpiry = now + LOCKOUT_DURATION_MS;
                user.failedAttempts = 0; // reset count after lock
            }
            return null;
        }
    }

    /**
     * Validates a session token. Returns associated username if valid, otherwise null.
     */
    public String validateSession(String token) {
        if (token == null) return null;
        String tokenHash = sha256Base64(token);
        Session s = sessions.get(tokenHash);
        if (s == null) return null;
        long now = System.currentTimeMillis();
        if (s.expiry < now) {
            sessions.remove(tokenHash);
            return null;
        }
        return s.username;
    }

    //////////////////////// Helper crypto utilities ////////////////////////

    private static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LEN];
        RNG.nextBytes(salt);
        return salt;
    }

    private static String generateSessionToken() {
        byte[] tokenBytes = new byte[SESSION_TOKEN_BYTES];
        RNG.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    private static byte[] derivePassword(char[] password, byte[] salt, int iterations, int keyLenBits) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyLenBits);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(KDF_ALGO);
            byte[] key = skf.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("KDF failure", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a, b);
    }

    private static String sha256Base64(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(d);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
