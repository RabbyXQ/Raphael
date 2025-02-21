import jadx.core.utils.exceptions.JadxException;
import org.apache.commons.math3.complex.Complex;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import soot.util.Chain;

import java.awt.*;
import java.awt.image.BufferedImage;
import java.util.*;
import java.util.List;
import java.util.zip.*;
import java.io.*;
import java.nio.file.*;
import java.util.regex.*;

import org.apache.commons.math3.transform.*;

import javax.imageio.ImageIO;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class Main {
    public static void main(String[] args) throws IOException, JadxException {
        // Paths
        String xapkPath = "/Users/macbook/IdeaProjects/Soot/src/0ac73aa8c95fe19eae64e0e130ca1d9a.apk";
        String androidJars = "/Users/macbook/Library/Android/sdk/platforms/";
        String androidJarVersion = "android-33";

        String apkPath = null;

        // Check if the file is an APK or XAPK
        if (xapkPath.endsWith(".xapk")) {
            // Extract APK from XAPK
            apkPath = extractApkFromXapk(xapkPath);
            if (apkPath == null) {
                System.err.println("Failed to extract APK from XAPK.");
                return;
            }
        } else if (xapkPath.endsWith(".apk")) {
            apkPath = xapkPath;
        } else {
            System.err.println("Unsupported file format. Only APK and XAPK are supported.");
            return;
        }

        if (apkPath == null) {
            System.err.println("Failed to extract APK.");
            return;
        }

        // Extract and Analyze .so Files
        String soExtractPath = extractSoFiles(apkPath);
        if (soExtractPath != null) {
            analyzeSoFiles(soExtractPath);
        }

        runJadx(apkPath);


        String manifest = parseManifest(getManifest("output_jadx"));

        try {
            String manifestCheckResult = ManifestChecker.checkManifestForMaliciousActivity("output_jadx/resources/AndroidManifest.xml");
            System.out.println(manifestCheckResult);
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            // Example usage for directory analysis (XML files)
            String directoryPath = "output_jadx/resources/res";
            CryptoAndStegoChecker.analyzeDirectory(directoryPath);

            // Analyze the META-INF directory (if present)
            CryptoAndStegoChecker.checkForMetaInf(directoryPath);
        } catch (IOException e) {
            System.err.println("Error processing directory: " + e.getMessage());
            e.printStackTrace();
        }
        // Example: After loading the classes into the scene
        for (SootClass sootClass : Scene.v().getClasses()) {
            ManifestChecker.analyzeClasses(sootClass);  // Analyze each class for security issues
        }

        // Configure Soot
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_android_jars(androidJars);
        Options.v().set_force_android_jar(androidJars + androidJarVersion + "/android.jar");
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_keep_line_number(true);
        Options.v().set_no_bodies_for_excluded(false);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_validate(true);

        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();

        // Analyze Classes
        Chain<SootClass> classes = Scene.v().getClasses();
        for (SootClass sootClass : classes) {
            System.out.println("Inspecting Class: " + sootClass.getName());
            inspectForObfuscation(sootClass);
            inspectForSteganography(sootClass);
            inspectForCrypticPatterns(sootClass);
            detectJavaScript(sootClass);
            detectJNI(sootClass);
            detectPrimeFactorCryptos(sootClass);  // Prime factor detection
            detectCustomCryptoAlgorithms(sootClass);  // Custom crypto algorithm detection
            detectEncryptedStrings(sootClass);  // Encrypted string detection
        }

        // Save all the analysis data as a Fourier image
        saveAnalysisDataAsFourierImage();
        double obfuscationRate = calculateObfuscationRate(Scene.v().getClasses());
        System.out.println("Obfuscation Rate: " + obfuscationRate + "%");

        double stegoRate = calculateStegoRate(apkPath, soExtractPath);
        System.out.println("Steganography Rate: " + stegoRate + "%");
        generateCallGraph();
        saveCallGraphToDotFile();
    }


    public static void runJadx(String apkPath) throws IOException {
        try {
            // Provide the path to your APK file here
            JadxRunner.runJadx(apkPath);
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getManifest(String path){
        File file = new File(path+"/resources/AndroidManifest.xml");
        if (file.exists()) {
            try {
                // Read the content of the AndroidManifest.xml file
                return new String(Files.readAllBytes(file.toPath()));
            } catch (IOException e) {
                e.printStackTrace();
                return "Error reading the file.";
            }
        }
        return "Not Found";
    }

    public static String parseManifest(String manifest) {
        try {
            // Convert the manifest string to InputStream
            InputStream inputStream = new ByteArrayInputStream(manifest.getBytes("UTF-8"));

            // Parse the XML document
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(inputStream);

            // Extract Activities
            NodeList activityList = doc.getElementsByTagName("activity");
            for (int i = 0; i < activityList.getLength(); i++) {
                Element activityElement = (Element) activityList.item(i);
                System.out.println("Activity: " + activityElement.getAttribute("android:name"));
            }

            // Extract Permissions
            NodeList permissionList = doc.getElementsByTagName("uses-permission");
            for (int i = 0; i < permissionList.getLength(); i++) {
                Element permissionElement = (Element) permissionList.item(i);
                System.out.println("Permission: " + permissionElement.getAttribute("android:name"));
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return manifest;
    }

    private static void saveCallGraphToDotFile() {
        CallGraph callGraph = Scene.v().getCallGraph();
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("./src/call_graph.dot"))) {
            writer.write("digraph G {\n");
            for (Edge edge : callGraph) {
                SootMethod src = (SootMethod) edge.getSrc();
                SootMethod tgt = (SootMethod) edge.getTgt();
                writer.write("  \"" + src.getSignature() + "\" -> \"" + tgt.getSignature() + "\";\n");
            }
            writer.write("}\n");
            System.out.println("Call graph saved as call_graph.dot.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private static void generateCallGraph() {
        CallGraph callGraph = Scene.v().getCallGraph();
        System.out.println("Method Call Graph:");

        // Iterate through each edge in the call graph
        for (Edge edge : callGraph) {
            SootMethod src = (SootMethod) edge.getSrc();
            SootMethod tgt = (SootMethod) edge.getTgt();
            System.out.println(src.getSignature() + " calls " + tgt.getSignature());
        }
    }


    // Extract APK from XAPK
    private static String extractApkFromXapk(String xapkPath) {
        String outputDir = "/Users/macbook/IdeaProjects/Soot/src/extracted";
        try (ZipFile zipFile = new ZipFile(xapkPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().toLowerCase().endsWith(".apk")) {
                    File extractedFile = new File(outputDir, new File(entry.getName()).getName());
                    extractedFile.getParentFile().mkdirs();
                    try (InputStream in = zipFile.getInputStream(entry);
                         FileOutputStream out = new FileOutputStream(extractedFile)) {
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = in.read(buffer)) != -1) {
                            out.write(buffer, 0, len);
                        }
                    }
                    return extractedFile.getAbsolutePath();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }





    // Detecting cryptic patterns in classes and fields (for obfuscation or unusual behavior)
    private static void inspectForCrypticPatterns(SootClass sootClass) {
        // Check for suspicious class names
        if (sootClass.getName().matches("[a-zA-Z0-9]{1,3}")) {
            System.out.println("  [Cryptic Pattern] Suspicious class name detected: " + sootClass.getName());
        }

        // Check for suspicious field names
        for (SootField field : sootClass.getFields()) {
            if (field.getName().matches("[a-zA-Z0-9]{1,3}")) {
                System.out.println("  [Cryptic Pattern] Suspicious field name detected: " + field.getName());
            }
        }
    }


    // Extract .so Files from APK
    private static String extractSoFiles(String apkPath) {
        String soOutputDir = apkPath + "_so_files";
        new File(soOutputDir).mkdirs();
        try (ZipFile zipFile = new ZipFile(apkPath)) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".so")) {
                    File soFile = new File(soOutputDir, new File(entry.getName()).getName());
                    soFile.getParentFile().mkdirs();
                    try (InputStream in = zipFile.getInputStream(entry);
                         FileOutputStream out = new FileOutputStream(soFile)) {
                        byte[] buffer = new byte[4096];
                        int len;
                        while ((len = in.read(buffer)) != -1) {
                            out.write(buffer, 0, len);
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
        return soOutputDir;
    }

    // Analyze .so Files
    private static void analyzeSoFiles(String soDirPath) {
        File soDir = new File(soDirPath);
        File[] soFiles = soDir.listFiles((dir, name) -> name.endsWith(".so"));

        if (soFiles == null || soFiles.length == 0) {
            System.out.println("No .so files found.");
            return;
        }

        for (File soFile : soFiles) {
            System.out.println("Analyzing .so file: " + soFile.getName());
            analyzeEntropy(soFile);
            analyzeCrypticPatterns(soFile);
        }
    }

    // Cryptic Pattern Analysis (For both .so and Classes)
    private static void analyzeCrypticPatterns(File file) {
        try {
            byte[] data = Files.readAllBytes(file.toPath());
            String content = new String(data);

            // Advanced Cryptic Patterns: Rot13, Base32, Caesar Cipher, XOR, and Prime-based
            Pattern rot13Pattern = Pattern.compile("([a-zA-Z]{13}[a-zA-Z]*)");
            Pattern base32Pattern = Pattern.compile("([A-Z2-7]{8,})");
            Pattern caesarPattern = Pattern.compile("([a-zA-Z]{5,})");
            Pattern xorPattern = Pattern.compile("([a-fA-F0-9]{8,})");  // XOR encrypted patterns

            if (rot13Pattern.matcher(content).find()) {
                System.out.println("  [Cryptic] Rot13 encoded data found.");
            }
            if (base32Pattern.matcher(content).find()) {
                System.out.println("  [Cryptic] Base32 encoded data found.");
            }
            if (caesarPattern.matcher(content).find()) {
                System.out.println("  [Cryptic] Caesar cipher pattern detected.");
            }
            if (xorPattern.matcher(content).find()) {
                System.out.println("  [Cryptic] XOR encrypted data pattern found.");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Shannon Entropy
    private static void analyzeEntropy(File file) {
        try {
            byte[] data = Files.readAllBytes(file.toPath());
            double entropy = calculateShannonEntropy(data);

            System.out.printf("  [Entropy] %s: %.4f%n", file.getName(), entropy);
            if (entropy > 7.5) {
                System.out.println("  [Warning] Possible hidden data detected!");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static double calculateShannonEntropy(byte[] data) {
        int[] freq = new int[256];
        for (byte b : data) {
            freq[b & 0xFF]++;
        }
        double entropy = 0.0;
        for (int count : freq) {
            if (count > 0) {
                double p = (double) count / data.length;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }




    // Save analysis data as Fourier image
    private static void saveAnalysisDataAsFourierImage() {
        // Generate random data for demonstration (in real scenario, this will be your analysis data)
        List<Double> analysisData = generateAnalysisData();

        // Apply Fourier Transform
        FastFourierTransformer fft = new FastFourierTransformer(DftNormalization.STANDARD);
        Complex[] fftData = fft.transform(analysisData.stream().mapToDouble(Double::doubleValue).toArray(), TransformType.FORWARD);

        // Convert Fourier Data to Image
        BufferedImage image = generateFourierImage(fftData);

        // Save the image to file
        try {
            File outputfile = new File("/Users/macbook/IdeaProjects/Soot/src/fourier_image.png");
            ImageIO.write(image, "png", outputfile);
            System.out.println("Fourier Image saved to: " + outputfile.getAbsolutePath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Generate analysis data (for demonstration)
    private static List<Double> generateAnalysisData() {
        List<Double> data = new ArrayList<>();
        for (int i = 0; i < 256; i++) {
            data.add(Math.random() * 100);  // Example random data
        }
        return data;
    }

    // Generate Fourier Image from Fourier Transformed Data
    private static BufferedImage generateFourierImage(Complex[] fftData) {
        int width = 256;
        int height = 256;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);

        // Process Fourier Data to create an image
        for (int i = 0; i < width; i++) {
            for (int j = 0; j < height; j++) {
                int value = (int) (Math.abs(fftData[i % fftData.length].getReal()) * 255);
                if(value > 255){
                    value = value % 255;
                }
                image.setRGB(i, j, new Color(value, value, value).getRGB());
            }
        }

        return image;
    }

    // Obfuscation Detection
    private static void inspectForObfuscation(SootClass sootClass) {
        if (sootClass.getName().matches("[a-zA-Z0-9]{1,3}")) {
            System.out.println("  [Obfuscation] Suspicious class name detected: " + sootClass.getName());
        }

        for (SootField field : sootClass.getFields()) {
            if (field.getName().matches("[a-zA-Z0-9]{1,3}")) {
                System.out.println("  [Obfuscation] Suspicious field name detected: " + field.getName());
            }
        }
    }

    // Steganography Detection (for Class and Field Names)
    private static void inspectForSteganography(SootClass sootClass) {
        if (sootClass.getName().matches(".*stego.*")) {
            System.out.println("  [Steganography] Suspicious steganography pattern detected in class: " + sootClass.getName());
        }

        for (SootField field : sootClass.getFields()) {
            if (field.getName().matches(".*stego.*")) {
                System.out.println("  [Steganography] Suspicious steganography pattern detected in field: " + field.getName());
            }
        }
    }

    // Detecting JavaScript patterns
    private static void detectJavaScript(SootClass sootClass) {
        String className = sootClass.getName();
        if (className.contains("js") || className.contains("<script")) {
            System.out.println("  [JavaScript] Possible JavaScript code detected in class: " + className);
        }
    }

    // Detecting JNI (Java Native Interface) Bridges
    private static void detectJNI(SootClass sootClass) {
        if (sootClass.getName().contains("JNI")) {
            System.out.println("  [JNI] Native method usage detected in class: " + sootClass.getName());
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

    private static double calculateObfuscationRate(Chain<SootClass> classes) {
        int totalClasses = classes.size();
        int suspiciousClasses = 0;
        int reflectionCalls = 0;
        int encryptedStrings = 0;

        for (SootClass sootClass : classes) {
            if (sootClass.getName().matches("[a-zA-Z0-9]{1,3}")) {
                suspiciousClasses++;
            }

            for (SootMethod method : sootClass.getMethods()) {
                if (method.getSignature().contains("java.lang.reflect")) {
                    reflectionCalls++;
                }

                if (Pattern.compile("([a-fA-F0-9]{8,})").matcher(method.getSignature()).find()) {
                    encryptedStrings++;
                }
            }
        }

        return (double) (suspiciousClasses + encryptedStrings + reflectionCalls) / totalClasses * 100;
    }

    private static double calculateStegoRate(String apkPath, String soPath) throws IOException {
        int totalFiles = 0;
        int highEntropyFiles = 0;

        File[] files = new File(soPath).listFiles();
        if (files != null) {
            for (File file : files) {
                totalFiles++;
                double entropy = calculateShannonEntropy(file);
                if (entropy > 7.5) {
                    highEntropyFiles++;
                }
                detectGESDAnomalies(file);
                detectZScoreAnomalies(file);
                detectQuantileAnomalies(file);
                detectFluctuations(file);
                detectMannKendallTrend(file);
                detectThresholdAnomalies(file);
            }
        }

        return totalFiles > 0 ? ((double) highEntropyFiles / totalFiles) * 100 : 0;
    }

    private static double calculateShannonEntropy(File file) throws IOException {
        byte[] data = Files.readAllBytes(file.toPath());
        Map<Byte, Integer> frequencyMap = new HashMap<>();
        for (byte b : data) {
            frequencyMap.put(b, frequencyMap.getOrDefault(b, 0) + 1);
        }
        double entropy = 0.0;
        int totalBytes = data.length;
        for (int count : frequencyMap.values()) {
            double probability = (double) count / totalBytes;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        return entropy;
    }

    private static void detectGESDAnomalies(File file) throws IOException {
        List<Double> data = readFileAsNumbers(file);
        double mean = data.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double stdDev = Math.sqrt(data.stream().mapToDouble(num -> Math.pow(num - mean, 2)).sum() / data.size());
        for (double value : data) {
            if (Math.abs(value - mean) > 3 * stdDev) {
                System.out.println("GESD Anomaly detected: " + value);
            }
        }
    }

    private static void detectZScoreAnomalies(File file) throws IOException {
        List<Double> data = readFileAsNumbers(file);
        double mean = data.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double stdDev = Math.sqrt(data.stream().mapToDouble(num -> Math.pow(num - mean, 2)).sum() / data.size());
        for (double value : data) {
            double zScore = (value - mean) / stdDev;
            if (Math.abs(zScore) > 3) {
                System.out.println("Z-Score Anomaly detected: " + value);
            }
        }
    }

    private static void detectQuantileAnomalies(File file) throws IOException {
        List<Double> data = readFileAsNumbers(file);

        if (data.isEmpty()) {
            System.out.println("No data available for quantile anomaly detection.");
            return;
        }

        Collections.sort(data);
        int size = data.size();
        double q1 = data.get(size / 4);
        double q3 = data.get(3 * size / 4);
        double iqr = q3 - q1;
        double lowerBound = q1 - 1.5 * iqr;
        double upperBound = q3 + 1.5 * iqr;

        for (double value : data) {
            if (value < lowerBound || value > upperBound) {
                System.out.println("Quantile Anomaly detected: " + value);
            }
        }
    }


    private static void detectFluctuations(File file) throws IOException {
        List<Double> data = readFileAsNumbers(file);
        for (int i = 1; i < data.size(); i++) {
            double diff = Math.abs(data.get(i) - data.get(i - 1));
            if (diff > 2 * Math.sqrt(data.get(i))) {
                System.out.println("Fluctuation detected at index " + i + " with change " + diff);
            }
        }
    }

    private static void detectMannKendallTrend(File file) throws IOException {
        List<Double> data = readFileAsNumbers(file);
        int s = 0;
        for (int i = 0; i < data.size() - 1; i++) {
            for (int j = i + 1; j < data.size(); j++) {
                if (data.get(j) > data.get(i)) s++;
                else if (data.get(j) < data.get(i)) s--;
            }
        }
        System.out.println("Mann-Kendall Trend Score: " + s);
    }

    private static void detectThresholdAnomalies(File file) throws IOException {
        List<Double> data = readFileAsNumbers(file);
        double threshold = 100.0; // Example threshold
        for (double value : data) {
            if (value > threshold) {
                System.out.println("Threshold Anomaly detected: " + value);
            }
        }
    }

    private static List<Double> readFileAsNumbers(File file) throws IOException {
        List<Double> numbers = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    numbers.add(Double.parseDouble(line));
                } catch (NumberFormatException ignored) {}
            }
        }
        return numbers;
    }
}
