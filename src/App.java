import java.util.Scanner;

class App {

    public static void main(String[] args) {
        //create instance of the class to use it 
        AuthSystemFixed asf = new AuthSystemFixed();
        try (Scanner scanner = new Scanner(System.in)) {
            System.out.println("=== Secure Auth System ===");
            
            // Registration
            System.out.print("Enter username to register: ");
            String username = scanner.nextLine();
            System.out.print("Enter password: ");
            String password = scanner.nextLine();
            
            boolean registered = asf.register(username, password);
            if (registered) {
                System.out.println("Registration successful!");
            } else {
                System.out.println("Registration failed (username may already exist).");
            }
            
            // Login
            System.out.print("\nEnter username to login: ");
            String loginUser = scanner.nextLine();
            System.out.print("Enter password: ");
            String loginPass = scanner.nextLine();
            
            String token = asf.login(loginUser, loginPass);
            if (token != null) {
                System.out.println("Login successful!");
                System.out.println("Your session token: " + token);
            } else {
                System.out.println("Login failed (invalid credentials or account locked).");
            }
            
            // Validate session
            if (token != null) {
                System.out.print("\nEnter your session token to validate: ");
                String tokenInput = scanner.nextLine();
                
                String validatedUser = asf.validateSession(tokenInput);
                if (validatedUser != null) {
                    System.out.println("Session valid! User: " + validatedUser);
                } else {
                    System.out.println("Session invalid or expired.");
                }
            }
        }
        System.out.println("\nprogramme finished.");
    }
}
