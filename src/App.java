public class App {
    public static void main(String[] args) {
    AuthSystemFixed auth = new AuthSystemFixed();

    boolean registered = auth.register("alice", "password123");
    System.out.println("Registered: " + registered);

    String token = auth.login("alice", "password123");
    System.out.println("Login token: " + token);

    String username = auth.validateSession(token);
    System.out.println("Validated username: " + username);
}

}
