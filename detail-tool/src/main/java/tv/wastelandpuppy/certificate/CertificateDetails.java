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

    public static X509Certificate getCertificate(String hostname) throws Exception {
        SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        try (SSLSocket socket = (SSLSocket) factory.createSocket(hostname, 443)) {
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
                if (altName.get(1) instanceof String) {
                    sans.add((String) altName.get(1));
                }
            }
        }
        return sans;
    }

    public static String extractCommonName(X509Certificate certificate) throws Exception {
        String dn = certificate.getSubjectX500Principal().getName();
        for (String part : dn.split(",")) {
            if (part.startsWith("CN=")) {
                return part.substring(3);
            }
        }
        return null;
    }

    public static void main(String[] args) {
        List<String[]> results = new ArrayList<>();
        String filePath = "hosts.txt"; // Update this path if necessary

        File file = new File(filePath);
        if (!file.exists()) {
            System.err.println("File not found: " + filePath);
            return;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String hostname;
            while ((hostname = br.readLine()) != null) {
                try {
                    X509Certificate certificate = getCertificate(hostname);
                    String commonName = extractCommonName(certificate);
                    List<String> sans = extractSANs(certificate);

                    if (sans.isEmpty()) {
                        results.add(new String[]{hostname, commonName, "", ""});
                    } else {
                        for (String san : sans) {
                            results.add(new String[]{hostname, commonName, san, ""});
                        }
                    }
                } catch (Exception e) {
                    results.add(new String[]{hostname, "error", "error", e.getMessage()});
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Write the CSV output to a file
        try (PrintWriter writer = new PrintWriter(new FileWriter("certificate_details.csv"))) {
            writer.println("hostname,subject common name,subject alternate name,comment");
            for (String[] result : results) {
                writer.println(String.join(",", result));
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Results written to certificate_details.csv");
    }
}