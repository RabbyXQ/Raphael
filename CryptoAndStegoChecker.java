import java.io.*;
import java.nio.file.*;
import java.util.regex.*;

public class CryptoAndStegoChecker {

    private static final String BASE64_REGEX = "([A-Za-z0-9+/=]{4})*";
    private static final String[] FAMOUS_CRYPTO_ALGORITHMS = {
            "aes", "rsa", "des", "blowfish", "md5", "sha", "ecdsa", "tripledes", "hmac"
    };

    private static final String[] CRYPTO_TERMS = {
            "rsa", "prime", "encrypt", "decrypt", "cipher", "aes", "des", "blowfish", "hash", "md5", "sha", "ecdsa", "rsa", "tripledes", "rsa"
    };

    // Analyzes a file for steganography
    private static void checkForSteganography(String filePath) throws IOException {
        System.out.println("Checking for Steganography in: " + filePath);

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for base64 encoding (steganographic data)
                if (isBase64String(line)) {
                    System.out.println("[Steganography] Base64-like string detected in line: " + line);
                }

                // Check for steganographic patterns (like 'stego', 'hidden', 'secret')
                if (line.toLowerCase().contains("stego") || line.toLowerCase().contains("hidden") || line.toLowerCase().contains("secret")) {
                    System.out.println("[Steganography] Suspicious steganographic pattern detected in line: " + line);
                }
            }
        }
    }

    // Analyzes a file for cryptographic patterns
    private static void checkForCryptoPatterns(String filePath) throws IOException {
        System.out.println("Checking for Crypto Patterns in: " + filePath);

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for famous cryptographic algorithms
                for (String algorithm : FAMOUS_CRYPTO_ALGORITHMS) {
                    if (line.toLowerCase().contains(algorithm)) {
                        System.out.println("[Crypto] Famous algorithm detected in line: " + line);
                    }
                }

                // Check for custom cryptographic terms
                for (String term : CRYPTO_TERMS) {
                    if (line.toLowerCase().contains(term)) {
                        System.out.println("[Crypto] Custom crypto-related term detected in line: " + line);
                    }
                }
            }
        }
    }

    // Helper function to check if a string is Base64-encoded
    private static boolean isBase64String(String data) {
        Pattern pattern = Pattern.compile(BASE64_REGEX);
        Matcher matcher = pattern.matcher(data);
        return matcher.matches();
    }

    // Analyzes a directory for all XML files and checks them for cryptographic and steganographic patterns
    public static void analyzeDirectory(String dirPath) throws IOException {
        Files.walk(Paths.get(dirPath))
                .filter(path -> path.toString().endsWith(".xml"))
                .forEach(path -> {
                    try {
                        System.out.println("\nAnalyzing file: " + path);
                        checkForSteganography(path.toString());
                        checkForCryptoPatterns(path.toString());
                    } catch (Exception e) {
                        System.err.println("Error processing file: " + path);
                        e.printStackTrace();
                    }
                });
    }

    // Analyzes the META-INF directory for suspicious files or patterns
    static void checkForMetaInf(String dirPath) throws IOException {
        Path metaInfPath = Paths.get(dirPath, "META-INF");

        // Check if META-INF directory exists
        if (Files.exists(metaInfPath) && Files.isDirectory(metaInfPath)) {
            System.out.println("Checking META-INF directory in: " + dirPath);

            // Walk through META-INF files and check them for cryptographic or steganographic patterns
            Files.walk(metaInfPath)
                    .filter(path -> path.toString().endsWith(".MF") || path.toString().endsWith(".RSA") || path.toString().endsWith(".SF"))
                    .forEach(path -> {
                        try {
                            System.out.println("Analyzing file in META-INF: " + path);
                            checkForSteganography(path.toString());
                            checkForCryptoPatterns(path.toString());
                        } catch (IOException e) {
                            System.err.println("Error processing file in META-INF: " + path);
                            e.printStackTrace();
                        }
                    });
        } else {
            System.out.println("META-INF directory not found or not a directory.");
        }
    }

}
