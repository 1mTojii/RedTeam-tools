import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.IOException;

/**
 * PortScanner is a simple TCP scan tool i coded in java a python version is coming soon too :).
 * this is just a super duper very shitty version of nmap. It just connects to ports nothing else.
 * Usage:
 *   javac PortScanner.java
 *   java PortScanner <host> <startPort> <endPort>
 *
 * Example:
 *   java PortScanner scanme.nmap.org 20 100
 */
public class PortScanner {

    static final int DEFAULT_TIMEOUT_MS = 500;

    public static void main(String[] args) {
        if (args.length < 3) {
            System.out.println("Usage: java PortScanner <host> <sPort> <ePort>");
            return;
        }
        String host = args[0];
        int sPort;
        int ePort;

        try {
            sPort = Integer.parseInt(args[1]);
            ePort = Integer.parseInt(args[2]);
        } catch (NumberFormatException e) {
            System.out.println("Ports must be valid numbers.");
            return;
        }

        if (sPort > ePort) {
            System.out.println("sPort must be less than or equal to ePort.");
            return;
        }

        scanRange(host, sPort, ePort, DEFAULT_TIMEOUT_MS);
    }

    /**
     * simple boolean that checks if the port is open or not
     */
    static boolean isPortOpen(String host, int port, int timeoutMs) {
        try (Socket socket = new Socket()) {
            // connect() blocks until either:
            //  - it succeeds (port is open)
            //  - it's refused (IOException. the port is closed)
            //  - it times out (SocketTimeoutException. mostly due to filters or firewalls)
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (SocketTimeoutException e) {
            return false; // timed out -- treat as closed/filtered
        } catch (IOException e) {
            return false; // connection actively refused -- closed
        }
    }

    /**
     * Scans a range of ports on the given host and prints results as it goes.
     */
    static void scanRange(String host, int startPort, int endPort, int timeoutMs) {
        System.out.println("Scanning " + host + " from port " + startPort + " to " + endPort + " ...\n");

        int openCount = 0;
        long startTime = System.currentTimeMillis();

        for (int port = startPort; port <= endPort; port++) {
            boolean open = isPortOpen(host, port, timeoutMs);
            if (open) {
                System.out.println("Port " + port + " -- OPEN");
                openCount++;
            }

            // Progress indicator every 100 ports so it doesn't look frozen
            // on larger ranges.
            if ((port - startPort + 1) % 100 == 0) {
                System.out.println("  ... scanned " + (port - startPort + 1) + " ports so far");
            }
        }

        long elapsedMs = System.currentTimeMillis() - startTime;

        System.out.println("\n------------------------------------------------------------");
        System.out.println("Scan complete.");
        System.out.println("  ports scanned : " + (endPort - startPort + 1));
        System.out.println("  open ports    : " + openCount);
        System.out.println("  time taken    : " + (elapsedMs / 1000.0) + "s");
        System.out.println("------------------------------------------------------------");
    }
}
