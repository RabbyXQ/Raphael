import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import soot.*;

public class ManifestChecker {

    private static String CSV_FILE = "menifest_results.csv";



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

    private static void saveToCSV(String manifestPath, String result) {
        try (BufferedWriter writer = Files.newBufferedWriter(Paths.get(CSV_FILE), StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
            writer.write(manifestPath + "," + result.replace(",", ";"));
            writer.newLine();
            System.out.println("Results saved to " + CSV_FILE);
        } catch (IOException e) {
            System.err.println("Error writing to CSV: " + e.getMessage());
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



    public static String checkManifestForMaliciousActivity(String manifestPath) throws Exception {
        File manifestFile = new File(manifestPath);
        if (!manifestFile.exists()) {
            return "Manifest file not found!";
        }

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(manifestFile);

        NodeList permissionNodes = document.getElementsByTagName("uses-permission");
        List<String[]> suspiciousItems = new ArrayList<>();

        for (int i = 0; i < permissionNodes.getLength(); i++) {
            Element permissionElement = (Element) permissionNodes.item(i);
            String permissionName = permissionElement.getAttribute("android:name");
            if (Arrays.asList(SUSPICIOUS_PERMISSIONS).contains(permissionName)) {
                suspiciousItems.add(new String[]{"Suspicious permission", permissionName});
            }
        }

        NodeList activityNodes = document.getElementsByTagName("activity");
        for (int i = 0; i < activityNodes.getLength(); i++) {
            Element activityElement = (Element) activityNodes.item(i);
            if ("true".equals(activityElement.getAttribute("android:exported"))) {
                suspiciousItems.add(new String[]{"Exported activity", activityElement.getAttribute("android:name")});
            }
        }

        // Write to CSV file
        File csvFile = new File("suspicious_manifest_activity.csv");
        try (FileWriter writer = new FileWriter(csvFile);
             CSVWriter csvWriter = new CSVWriter(writer)) {
            csvWriter.writeNext(new String[]{"Type", "Value"}); // Header row
            for (String[] item : suspiciousItems) {
                csvWriter.writeNext(item);
            }
            csvWriter.close();
        }

        return suspiciousItems.isEmpty() ? "Manifest seems clean." : "Suspicious activities logged to CSV.";
    }





    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("Usage: java ManifestChecker <path-to-AndroidManifest.xml>");
            return;
        }

        String manifestPath = args[0];
        try {
            String result = checkManifestForMaliciousActivity(manifestPath);
            System.out.println(result);
            saveToCSV(manifestPath, result);
        } catch (Exception e) {
            System.err.println("Error processing manifest file: " + e.getMessage());
        }
    }


}
