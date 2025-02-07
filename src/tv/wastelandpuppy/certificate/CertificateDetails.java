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
        List<String[]> results = new ArrayList<>();
        String filePath = "hosts.csv"; // Update this path if necessary

        File file = new File(filePath);
        if (!file.exists()) {
            System.err.println("File not found: " + filePath);
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            br.readLine(); // Skip header
            while ((line = br.readLine()) != null) {
                String[] nextLine = line.split(",");
                String hostname = nextLine[0];
                int port = Integer.parseInt(nextLine[1]);
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
                } catch (Exception e) {
                    results.add(new String[]{hostname, String.valueOf(port), "error", "error", e.toString()});
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Write the CSV output to a file
        try (PrintWriter writer = new PrintWriter(new FileWriter("certificate_details.csv"))) {
            writer.println("hostname,port,subject common name,subject alternate name,comment");
            for (String[] result : results) {
                writer.println(String.join(",", result));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Results written to certificate_details.csv");
    }
}