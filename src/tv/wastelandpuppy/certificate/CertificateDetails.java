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

    // Default file names
    private static final String DEFAULT_INPUT_FILE = "hosts.csv";
    private static final String DEFAULT_OUTPUT_FILE = "certs.csv";

    // ANSI escape codes for colors
    public static final String RESET = "\u001B[0m";
    public static final String RED = "\u001B[31m";
    public static final String GREEN = "\u001B[32m";
    public static final String YELLOW = "\u001B[33m";
    public static final String BLUE = "\u001B[34m";
    public static final String CYAN = "\u001B[36m";

    public static void main(String[] args) {
        String inputFilePath = getInputFilePath(args);
        String outputFilePath = getOutputFilePath(args);
        
        List<String[]> results = new ArrayList<>();

        File inputFile = new File(inputFilePath);
        if (!inputFile.exists()) {
            System.err.println(RED + "File not found: " + inputFilePath + RESET);
            return;
        }

        System.out.println(CYAN + "Starting certificate processing..." + RESET);

        results.addAll(processHosts(inputFile));
        writeResultsToFile(outputFilePath, results);

        System.out.println(CYAN + "Results written to " + outputFilePath + RESET);
    }

    private static List<String[]> processHosts(File inputFile) {
        ArrayList<String[]> resultLines = new ArrayList<String[]>();
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(inputFile))) {
            String line;
            bufferedReader.readLine(); // Skip header
            while ((line = bufferedReader.readLine()) != null) {
                String[] columns = line.split(",");
                String hostname = columns[0];
                int port = Integer.parseInt(columns[1].trim());
                List<String[]> hostResults = processHost(hostname, port);
                resultLines.addAll(hostResults);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return resultLines;
    }

    public static List<String[]> processHost(String hostname, int port) {
        List<String[]> resultLines = new ArrayList<>();
        System.out.println(YELLOW + "----------------------------------------" + RESET);
        System.out.println(BLUE + "Processing: " + hostname + ":" + port + RESET);
        try {
            X509Certificate certificate = getCertificate(hostname, port);
            String commonName = extractCommonName(certificate);
            List<String> subjectAlternativeNames = extractSubjectAlternativeNames(certificate);

            if (subjectAlternativeNames.isEmpty()) {
                resultLines.add(new String[] { hostname, String.valueOf(port), commonName, "", "" });
            } else {
                for (String san : subjectAlternativeNames) {
                    resultLines.add(new String[] { hostname, String.valueOf(port), commonName, san, "" });
                }
            }
            System.out.println(GREEN + "Successfully processed: " + hostname + ":" + port + RESET);
        } catch (Exception e) {
            resultLines.add(new String[] { hostname, String.valueOf(port), "error", "error", e.toString() });
            System.err.println(RED + "Error processing: " + hostname + ":" + port + " - " + e.getMessage() + RESET);
        }
        return resultLines;
    }

    public static X509Certificate getCertificate(String hostname, int port) throws Exception {
        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostname, port)) {
            sslSocket.startHandshake();
            Certificate[] certificates = sslSocket.getSession().getPeerCertificates();
            return (X509Certificate) certificates[0];
        }
    }

    public static String extractCommonName(X509Certificate certificate) throws Exception {
        String distinguishedName = certificate.getSubjectX500Principal().getName();
        for (String part : distinguishedName.split(",")) {
            if (part.trim().startsWith("CN=")) {
                return part.trim().substring(3);
            }
        }
        return null;
    }

    public static List<String> extractSubjectAlternativeNames(X509Certificate certificate)
            throws CertificateParsingException {
        List<String> subjectAlternativeNames = new ArrayList<>();
        Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
        if (altNames != null) {
            for (List<?> altName : altNames) {
                Integer type = (Integer) altName.get(0);
                Object value = altName.get(1);
                if (value instanceof String) {
                    subjectAlternativeNames.add(type + ": " + value);
                }
            }
        }
        return subjectAlternativeNames;
    }

    private static String getOutputFilePath(String[] args) {
        String outputFilePath = DEFAULT_OUTPUT_FILE;

        if (args.length > 1) {
            outputFilePath = args[1];
        }
        return outputFilePath;
    }

    private static String getInputFilePath(String[] args) {
        String inputFilePath = DEFAULT_INPUT_FILE;

        if (args.length > 0) {
            inputFilePath = args[0];
        }
        return inputFilePath;
    }

    public static void writeResultsToFile(String outputFilePath, List<String[]> results) {
        try (PrintWriter printWriter = new PrintWriter(new FileWriter(outputFilePath))) {
            printWriter.println("hostname,port,subject common name,subject alternate name,comment");
            for (String[] result : results) {
                printWriter.println(String.join(",", result));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}