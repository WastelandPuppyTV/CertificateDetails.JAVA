package tv.wastelandpuppy.certificate;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.x500.X500Principal;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class CertificateDetails {

    public static Map<String, Object> getCertificate(String hostname) {
        Map<String, Object> result = new HashMap<>();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(hostname, 443), 10000);
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            SSLSocket sslSocket = (SSLSocket) factory.createSocket(socket, hostname, 443, true);
            sslSocket.startHandshake();
            Certificate[] certs = sslSocket.getSession().getPeerCertificates();
            X509Certificate cert = (X509Certificate) certs[0];
            result.put("certificate", cert);
            result.put("error", null);
        } catch (IOException e) {
            result.put("certificate", null);
            result.put("error", "Error retrieving certificate for " + hostname + ": " + e.getMessage());
        }
        return result;
    }

    public static List<String> extractSANs(X509Certificate certificate) {
        List<String> sans = new ArrayList<>();
        try {
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            if (altNames != null) {
                for (List<?> altName : altNames) {
                    if (altName.get(1) instanceof String) {
                        sans.add((String) altName.get(1));
                    }
                }
            }
        } catch (CertificateParsingException e) {
            // Handle exception
        }
        return sans;
    }

    public static String extractCommonName(X509Certificate certificate) {
        try {
            X500Principal principal = certificate.getSubjectX500Principal();
            LdapName ldapName = new LdapName(principal.getName());
            for (Rdn rdn : ldapName.getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) {
                    return rdn.getValue().toString();
                }
            }
        } catch (InvalidNameException e) {
            // Handle exception
        }
        return null;
    }

    public static void main(String[] args) {
        List<Map<String, Object>> results = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader("hosts.txt"))) {
            String hostname;
            while ((hostname = reader.readLine()) != null) {
                hostname = hostname.trim();
                if (!hostname.isEmpty()) {
                    Map<String, Object> certResult = getCertificate(hostname);
                    X509Certificate certificate = (X509Certificate) certResult.get("certificate");
                    if (certificate != null) {
                        String commonName = extractCommonName(certificate);
                        List<String> sans = extractSANs(certificate);
                        Map<String, Object> result = new HashMap<>();
                        result.put("hostname", hostname);
                        result.put("common_name", commonName != null ? commonName : "Error");
                        result.put("subject_alternative_names", !sans.isEmpty() ? sans : List.of("Error"));
                        results.add(result);
                    } else {
                        Map<String, Object> result = new HashMap<>();
                        result.put("hostname", hostname);
                        result.put("error", certResult.get("error"));
                        results.add(result);
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (FileWriter writer = new FileWriter("certificate_details.json")) {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            gson.toJson(results, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }

        System.out.println("Results written to certificate_details.json");
    }
}