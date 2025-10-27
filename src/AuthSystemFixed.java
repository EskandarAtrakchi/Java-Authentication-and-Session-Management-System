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
 * - PBKDF2WithHmacSHA256: unique per-user salt ensures that identical passwords produce distinct hashes
 * - Constant-time comparisons
 * - Fake hash verification to prevent user enumeration
 * - Account lockout after configurable failed attempts
 * - Cryptographically secure session tokens stored as hashes
 * 
 * NOTE: I will not use any external databases, for example MySQL, I will keep using the in-memory maps as in the original code for simplicity. I will also be storing hashes on server (for security)
 */
public class AuthSystemFixed {

    // Secure random generator generates 256bit tokens for session using SecureRandom and stored as SHA-256 hashes, each session includes a 30 minutes expiration and stored in server (means as long as the code is running) is also validated by hash lookup
    private static final SecureRandom SecureRandomGenerator = new SecureRandom();
    // setting the lockout policy.
    private static final int maxAttempts = 2;
    private static final long lockoutDurationMS = 15 * 60 * 1000L; // 15 minutes
     // Session policy
    private static final int sessionTokenBytes = 32; // 256-bit token
    private static final long sessionTimeInMinutes = 30 * 60 * 1000L; // 30 minutes
    // PBKDF2 parameters
    private static final String encryptionAlgo = "PBKDF2WithHmacSHA256";
    private static final int saltLength = 16; // this is bytes
    private static final int keyLengthBits = 32 * 8; // this is bits
    private static final int Iterations = 200_000; // reasonable modern cost

    // In-memory stores (thread safe) as I said above I will not change the structure of the database, I will keep it storage within 

    /*
     * in the original code it is like this 
     * private Map<String, User> users = new HashMap<>();
     * In-memory "database" of users I will change it to make sure shared data stays correct and safe, even if multiple tasks are running together (multi-threaded environments)
     */
    private final Map<String, User> users = new ConcurrentHashMap<>();
    // store SHA-256(sessionToken) -> Session
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    /*
     * static class User {
        String password; // Stored in plain text
        int loginAttempts = 0;
        
        User(String password) {
            this.password = password;
        }
    }
        this original structure is vulnerable to several attacks as I explained above, so I will change it to store the salt and the hashed password using PBKDF2 along with the number of iterations used.
     */
    private static class User {
        final byte[] salt;             // per-user salt
        final byte[] passwordHash;     // result of PBKDF2
        final int Iterations;
        volatile int failedAttempts = 0; //no violations allowed
        volatile long lockoutExpiry = 0L; // timestamp until which account is locked and no violations allowed 

        //taking the same structure as the original code and adding to it Iterations and salt 
        User(byte[] salt, byte[] passwordHash, int Iterations) {
            this.salt = salt;
            this.passwordHash = passwordHash;
            this.Iterations = Iterations;
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
     public boolean register(String username, String password) {
        if (users.containsKey(username)) {
            return false;
        }
        users.put(username, new User(password));
        return true;
    }
    
    the original code for register method is vulnerable to several issues as I explained above, so I will change it to include the following enhancements:
    // 1. Added null checks for username/password to prevent malformed user entries.
    // 2. Added salted PBKDF2 password hashing instead of storing plaintext passwords.
    // 3. Added unique per-user salt and iteration count for stronger security.
    // 4. Switched to putIfAbsent() to prevent duplicate accounts
    // 5. Avoids duplicate username creation even under simultaneous registration attempts.
    */
    public boolean register(String username, String password) {
        if (username == null || password == null) return false;
        // Avoid race by putIfAbsent
        if (users.containsKey(username)) return false;

        byte[] salt = generateSalt();
        byte[] hash = derivePassword(password.toCharArray(), salt, Iterations, keyLengthBits);
        User user = new User(salt, hash, Iterations);
        
        return users.putIfAbsent(username, user) == null;
    }

    /**
     * Attempts login. Returns a session token on success, null on failure.
     * the following enhancements added to the original code::
     *  Enhanced with timing-attack protection, PBKDF2 hashing, account lockout,
     * constant-time comparison, and secure session token handling.
     */
    public String login(String username, String password) {
        if (username == null || password == null) return null;

        User user = users.get(username);

        // Perform fake PBKDF2 and constant-time compare to mitigate timing attacks
        // when username does not exist (prevents user enumeration)
        if (user == null) {
            // fake salt and hash
            byte[] fakeSalt = new byte[saltLength];
            SecureRandomGenerator.nextBytes(fakeSalt);
            byte[] fakeHash = derivePassword(password.toCharArray(), fakeSalt, Iterations, keyLengthBits);
            // compare to another random value in constant time
            byte[] randomCompare = new byte[fakeHash.length];
            SecureRandomGenerator.nextBytes(randomCompare);
            constantTimeEquals(fakeHash, randomCompare);
            return null; // Generic failure
        }

        // Check lockout
        long now = System.currentTimeMillis();
        // Check if account is currently locked due to repeated failures
        if (user.lockoutExpiry > now) {
            // still locked
            // Perform a fake verification to keep timing consistent
            byte[] fakeHash = derivePassword(password.toCharArray(), user.salt, user.Iterations, keyLengthBits);
            constantTimeEquals(fakeHash, user.passwordHash);
            return null;
        }

        // Derive hash using stored salt & iterations (PBKDF2)
        byte[] candidateHash = derivePassword(password.toCharArray(), user.salt, user.Iterations, keyLengthBits);

        // Constant-time comparison to prevent timing side-channels
        boolean match = constantTimeEquals(candidateHash, user.passwordHash);

        if (match) {
            // Reset security counters after successful authentication
            user.failedAttempts = 0;
            user.lockoutExpiry = 0L;
            // Generate strong session token; store only its hash for security
            String token = generateSessionToken();
            String tokenHash = sha256Base64(token);
            sessions.put(tokenHash, new Session(username, now + sessionTimeInMinutes));
            return token; // raw token returned to client — server keeps only its hash
        } else {
            // Increment failed attempts and trigger lockout when two attempts reached
            int attempts = ++user.failedAttempts;
            if (attempts >= maxAttempts) {
                user.lockoutExpiry = now + lockoutDurationMS;
                user.failedAttempts = 0; // reset count after lock
            }
            return null;
        }
    }

    /**
     * Validates a session token. Returns associated username if valid, otherwise null.
     */
    public String validateSession(String token) {

        // Reject null token immediately
        if (token == null) return null;
        // Hash the token before lookup; server never stores raw tokens
        String tokenHash = sha256Base64(token);
        // Retrieve the stored session
        Session s = sessions.get(tokenHash);
        // Token not found or tampered
        if (s == null) return null;
        long now = System.currentTimeMillis();
        // Check expiration time to prevent infinite session reuse
        if (s.expiry < now) {
            // Cleanup expired session
            sessions.remove(tokenHash); 
            return null;
        }
        // Valid, active session — return associated username
        return s.username;
    }


    //////////////////////// Helper crypto utilities ////////////////////////

    // Security Enhancements will be Implemented:
    // - Cryptographically secure random salts
    // - PBKDF2 password hashing with high iteration count
    // - Constant-time comparisons to prevent timing leakage
    // - Session tokens stored only as SHA-256 hashes
    // - URL-safe Base64 tokens with strong entropy

    /**
     * Generates a cryptographically secure random salt for password hashing.
     * Salts prevent rainbow-table attacks by ensuring identical passwords hash differently.
    */
    private static byte[] generateSalt() {
        byte[] salt = new byte[saltLength];
        SecureRandomGenerator.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a high-entropy, URL-safe session token.
     * Uses secure random bytes and Base64 URL encoding without padding
     * to minimize predictability and avoid unsafe characters.
    */
    private static String generateSessionToken() {
        byte[] tokenBytes = new byte[sessionTokenBytes];
        SecureRandomGenerator.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }

    /**
     * Derives a secure password hash using PBKDF2 with hash stretching.
     * Incorporates salt, iteration count, and output length to resist brute-force attacks.
     * Clears password chars afterwards to reduce lingering sensitive data in memory.
    */
    private static byte[] derivePassword(char[] password, byte[] salt, int Iterations, int keyLenBits) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, Iterations, keyLenBits);
            SecretKeyFactory skf = SecretKeyFactory.getInstance(encryptionAlgo);
            byte[] key = skf.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("KDF failure", e);
        }
    }

    /**
     * Compares two byte arrays in constant time to prevent timing attacks.
     * Avoids giving attackers clues based on processing speed differences.
    */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Computes a SHA-256 hash of the input and encodes it as URL-safe Base64.
     * Used to store session tokens securely without keeping the raw secret.
    */
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