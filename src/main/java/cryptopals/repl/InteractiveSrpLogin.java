package cryptopals.repl;

import static cryptopals.CommonConstants.G;
import static cryptopals.CommonConstants.K;
import static cryptopals.CommonConstants.N;

import cryptopals.tool.sec05.c36.SRPClient;
import cryptopals.tool.sec05.c36.SRPServer;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;

import java.io.PrintStream;
import java.util.Scanner;

@RequiredArgsConstructor
public class InteractiveSrpLogin {
    private final Scanner s;
    private final PrintStream out;
    private final SRPServer server;

    public void startConsole() {
        out.println("Welcome to SRP Login.");
        String input;
        do {
            out.println("Enter desired activity: register login exit");
            input = s.nextLine();
            if (StringUtils.equals("register", input)) {
                performSrpRegistration();
            } else if (StringUtils.equals("login", input)) {
                performLogin();
            } else if (!StringUtils.equals("exit", input)) {
                out.println("unrecognized command");
            }
        } while (!StringUtils.equals(input, "exit"));
        out.println("goodbye");
    }

    private void performSrpRegistration() {
        out.println("Welcome to the SRP Registration.\nPlease enter your desired username: ");
        final String u = s.nextLine();
        out.println("Please enter desired password: ");
        final String p = s.nextLine();

        final SRPClient c = new SRPClient(u, server.getNetwork(), G, K, N);
        c.register(u, p, server.getName());
    }

    private void performLogin() {
        out.println("Welcome to the SRP Login\nPlease enter your username: ");
        final String u = s.nextLine();
        out.println("Please enter desired password: ");
        final String p = s.nextLine();

        final SRPClient c = new SRPClient(u, server.getNetwork(), G, K, N);
        boolean success;
        try {
            success = c.authenticateSecurely(u, p, server.getName());
        } catch (Exception e) {
            success = false;
        }
        final String message = success ? "Login successful. Welcome aboard" :
                "Login failed. Authentication unsuccessful.";

        out.println(message);
    }
}
