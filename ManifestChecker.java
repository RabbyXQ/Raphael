import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import soot.*;

public class ManifestChecker {

    // Define some suspicious permissions for demonstration
    private static final String[] SUSPICIOUS_PERMISSIONS = {
            "android.permission.INTERNET",
            "android.permission.SEND_SMS",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.CAMERA"
    };

    /**
     * Checks the AndroidManifest.xml for suspicious activities such as dangerous permissions
     * or exported components (activities, services, or receivers).
     *
     * @param manifestPath The path to the AndroidManifest.xml file.
     * @return A message indicating the result of the analysis.
     * @throws Exception If there is an error while parsing or reading the manifest.
     */
    public static String checkManifestForMaliciousActivity(String manifestPath) throws Exception {
        File manifestFile = new File(manifestPath);
        if (!manifestFile.exists()) {
            return "Manifest file not found!";
        }

        // Initialize XML parser to read the AndroidManifest.xml file
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(manifestFile);

        // Check for suspicious permissions
        NodeList permissionNodes = document.getElementsByTagName("uses-permission");
        for (int i = 0; i < permissionNodes.getLength(); i++) {
            Element permissionElement = (Element) permissionNodes.item(i);
            String permissionName = permissionElement.getAttribute("android:name");

            // Check if the permission is suspicious
            for (String suspiciousPermission : SUSPICIOUS_PERMISSIONS) {
                if (permissionName.equals(suspiciousPermission)) {
                    return "Warning: Suspicious permission found - " + permissionName;
                }
            }
        }

        // Check for suspicious exported activities
        NodeList activityNodes = document.getElementsByTagName("activity");
        for (int i = 0; i < activityNodes.getLength(); i++) {
            Element activityElement = (Element) activityNodes.item(i);
            String activityName = activityElement.getAttribute("android:name");
            String exported = activityElement.getAttribute("android:exported");

            // Check if exported activities are suspicious
            if ("true".equals(exported)) {
                return "Warning: Exported activity found - " + activityName;
            }
        }

        // Check for suspicious exported receivers
        NodeList receiverNodes = document.getElementsByTagName("receiver");
        for (int i = 0; i < receiverNodes.getLength(); i++) {
            Element receiverElement = (Element) receiverNodes.item(i);
            String receiverName = receiverElement.getAttribute("android:name");
            String exported = receiverElement.getAttribute("android:exported");

            // Check if exported receiver components are suspicious
            if ("true".equals(exported)) {
                return "Warning: Exported receiver found - " + receiverName;
            }
        }

        // Check for suspicious services
        NodeList serviceNodes = document.getElementsByTagName("service");
        for (int i = 0; i < serviceNodes.getLength(); i++) {
            Element serviceElement = (Element) serviceNodes.item(i);
            String serviceName = serviceElement.getAttribute("android:name");
            String exported = serviceElement.getAttribute("android:exported");

            // Check if exported service components are suspicious
            if ("true".equals(exported)) {
                return "Warning: Exported service found - " + serviceName;
            }
        }

        // If no suspicious items found
        return "Manifest seems clean. No suspicious activities detected.";
    }

    // Obfuscation Detection
    private static void inspectForObfuscation(SootClass sootClass) {
        // Detect classes with suspiciously short or random names
        if (sootClass.getName().matches("[a-zA-Z0-9]{1,3}")) {
            System.out.println("  [Obfuscation] Suspicious class name detected: " + sootClass.getName());
        }

        // Detect fields with suspiciously short or random names
        for (SootField field : sootClass.getFields()) {
            if (field.getName().matches("[a-zA-Z0-9]{1,3}")) {
                System.out.println("  [Obfuscation] Suspicious field name detected: " + field.getName());
            }
        }
    }

    // Steganography Detection (for Class and Field Names)
    private static void inspectForSteganography(SootClass sootClass) {
        // Detect classes with "stego" in their name
        if (sootClass.getName().matches(".*stego.*")) {
            System.out.println("  [Steganography] Suspicious steganography pattern detected in class: " + sootClass.getName());
        }

        // Detect fields with "stego" in their name
        for (SootField field : sootClass.getFields()) {
            if (field.getName().matches(".*stego.*")) {
                System.out.println("  [Steganography] Suspicious steganography pattern detected in field: " + field.getName());
            }
        }
    }

    // Detecting Prime Factor Cryptos (RSA, Prime-based)
    private static void detectPrimeFactorCryptos(SootClass sootClass) {
        if (sootClass.getName().matches(".*(rsa|prime).*")) {
            System.out.println("  [Prime Factor Crypto] Suspicious prime factor or RSA pattern detected in class: " + sootClass.getName());
        }
    }

    // Custom Crypto Algorithm Detection
    private static void detectCustomCryptoAlgorithms(SootClass sootClass) {
        if (sootClass.getName().matches(".*(encrypt|decrypt|cipher).*")) {
            System.out.println("  [Custom Crypto] Custom encryption/decryption methods detected in class: " + sootClass.getName());
        }
    }

    // Encrypted String Detection
    private static void detectEncryptedStrings(SootClass sootClass) {
        for (SootField field : sootClass.getFields()) {
            String fieldName = field.getName();
            if (fieldName.matches(".*(base64|xor|rot13).*")) {
                System.out.println("  [Encrypted String] Suspicious encrypted string pattern detected in field: " + fieldName);
            }
        }
    }

    // Analyze SootClass for various security issues
    public static void analyzeClasses(SootClass sootClass) {
        inspectForObfuscation(sootClass);   // Check for obfuscation patterns in class and fields
        inspectForSteganography(sootClass); // Check for steganography patterns in class and fields
        detectPrimeFactorCryptos(sootClass); // Check for RSA or prime-based crypto algorithms
        detectCustomCryptoAlgorithms(sootClass); // Check for custom encryption algorithms
        detectEncryptedStrings(sootClass); // Detect base64, xor, rot13 encryption methods
    }


}
