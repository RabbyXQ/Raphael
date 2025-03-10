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
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_CONTACTS",
            "android.permission.WRITE_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.WRITE_CALL_LOG",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.BLUETOOTH_ADMIN",
            "android.permission.BLUETOOTH",
            "android.permission.BLUETOOTH_CONNECT",
            "android.permission.BLUETOOTH_SCAN",
            "android.permission.BLUETOOTH_ADVERTISE",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.ACCESS_WIFI_STATE",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.READ_HISTORY_BOOKMARKS",
            "android.permission.WRITE_HISTORY_BOOKMARKS",
            "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.GET_ACCOUNTS",
            "android.permission.USE_CREDENTIALS",
            "android.permission.MANAGE_ACCOUNTS",
            "android.permission.AUTHENTICATE_ACCOUNTS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.PACKAGE_USAGE_STATS",
            "android.permission.KILL_BACKGROUND_PROCESSES",
            "android.permission.WAKE_LOCK",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.READ_PRIVILEGED_PHONE_STATE",
            "android.permission.QUERY_ALL_PACKAGES",
            "android.permission.BIND_VPN_SERVICE",
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.READ_MEDIA_AUDIO",
            "android.permission.READ_MEDIA_VIDEO",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.MEDIA_CONTENT_CONTROL",
            "android.permission.NFC",
            "android.permission.NFC_TRANSACTION_EVENT",
            "android.permission.READ_CALENDAR",
            "android.permission.WRITE_CALENDAR",
            "android.permission.READ_FRAME_BUFFER",
            "android.permission.CAPTURE_AUDIO_OUTPUT",
            "android.permission.CAPTURE_VIDEO_OUTPUT",
            "android.permission.CAPTURE_SECURE_VIDEO_OUTPUT",
            "android.permission.BROADCAST_SMS",
            "android.permission.BROADCAST_WAP_PUSH",
            "android.permission.BROADCAST_STICKY",
            "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
            "android.permission.READ_LOGS",
            "android.permission.SET_WALLPAPER",
            "android.permission.SET_WALLPAPER_HINTS",
            "android.permission.USE_FINGERPRINT",
            "android.permission.USE_BIOMETRIC"
    };


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
