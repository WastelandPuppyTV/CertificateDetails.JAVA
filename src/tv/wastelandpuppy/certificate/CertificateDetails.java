package tv.wastelandpuppy.certificate;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class CertificateDetails {

    // ANSI escape codes for colors
    public static final String RESET = "\u001B[0m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String CYAN = "\u001B[36m";

    public static X509Certificate getCertificate(String hostname, int port) throws Exception {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, port)) {
            socket.startHandshake();
            Certificate[] certs = socket.getSession().getPeerCertificates();
            return (X509Certificate) certs[0];
        }
    }

    public static List<String> extractSANs(X509Certificate certificate) throws CertificateParsingException {
        List<String> sans = new ArrayList<>();
        Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
        if (altNames != null) {
            for (List<?> altName : altNames) {
                Integer type = (Integer) altName.get(0);
                Object value = altName.get(1);
                if (value instanceof String) {
                    sans.add(type + ": " + value);
                }
            }
        }
        return sans;
    }

    public static String extractCommonName(X509Certificate certificate) throws Exception {
        String dn = certificate.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }
        return null;
    }

    public static void main(String[] args) {
        String inputFilePath = "hosts.csv";
        String outputFilePath = "certs.csv";

        if (args.length > 0) {
            inputFilePath = args[0];
        }
        if (args.length > 1) {
            outputFilePath = args[1];
        }

        List<String[]> results = new ArrayList<>();

        File inputFile = new File(inputFilePath);
        if (!inputFile.exists()) {
            System.err.println(RED + "File not found: " + inputFilePath + RESET);
            return;
        }

        System.out.println(CYAN + "Starting certificate processing..." + RESET);

        try (BufferedReader br = new BufferedReader(new FileReader(inputFile))) {
            String line;
            br.readLine(); // Skip header
            while ((line = br.readLine()) != null) {
                String[] nextLine = line.split(",");
                String hostname = nextLine[0];
                int port = Integer.parseInt(nextLine[1].trim());
                System.out.println(YELLOW + "----------------------------------------" + RESET);
                System.out.println(BLUE + "Processing: " + hostname + ":" + port + RESET);
                try {
                    X509Certificate certificate = getCertificate(hostname, port);
                    String commonName = extractCommonName(certificate);
                    List<String> sans = extractSANs(certificate);

                    if (sans.isEmpty()) {
                        results.add(new String[]{hostname, String.valueOf(port), commonName, "", ""});
                    } else {
                        for (String san : sans) {
                            results.add(new String[]{hostname, String.valueOf(port), commonName, san, ""});
                        }
                    }
                    System.out.println(GREEN + "Successfully processed: " + hostname + ":" + port + RESET);
                } catch (Exception e) {
                    results.add(new String[]{hostname, String.valueOf(port), "error", "error", e.toString()});
                    System.err.println(RED + "Error processing: " + hostname + ":" + port + " - " + e.getMessage() + RESET);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Write the CSV output to a file
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputFilePath))) {
            writer.println("hostname,port,subject common name,subject alternate name,comment");
            for (String[] result : results) {
                writer.println(String.join(",", result));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println(CYAN + "Results written to " + outputFilePath + RESET);
    }
}