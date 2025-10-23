import java.util.HashMap;
import java.util.Map;

public class AuthSystemOriginal {
    // In-memory "database" of users
    private Map<String, User> users = new HashMap<>();
    
    static class User {
        String password; // Stored in plain text
        int loginAttempts = 0;
        
        User(String password) {
            this.password = password;
        }
    }

    /**
     * Registers a new user. 
     * @return true if successful, false if user exists.
     */
    public boolean register(String username, String password) {
        if (users.containsKey(username)) {
            return false;
        }
        users.put(username, new User(password));
        return true;
    }

    /**
     * Authenticates a user.
     * @return Session ID on success, null on failure.
     */
    public String login(String username, String password) {
        // Check if user exists
        if (!users.containsKey(username)) {
            return null; // Early return reveals valid users
        }
        
        User user = users.get(username);
        
        // Check password (vulnerable to timing attack)
        if (user.password.equals(password)) {
            user.loginAttempts = 0; // Reset on success
            // Generate a simple session token
            return "session_" + username + "_" + System.currentTimeMillis();
        } else {
            user.loginAttempts++;
            return null;
        }
    }

    /**
     * Checks if a session token is valid.
     */
    public boolean isSessionValid(String sessionToken) {
        return sessionToken != null && sessionToken.startsWith("session_");
    }
}
