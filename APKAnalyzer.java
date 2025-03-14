import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import org.json.JSONArray;
import org.json.JSONObject;
import org.xml.sax.InputSource;

import javax.imageio.ImageIO;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class APKAnalyzer {
    // Path to apktool.jar (update this to your actual path)
    private static final String APKTOOL_PATH = "/Users/macbook/IdeaProjects/Soot/lib/apktool.jar";

    public static void main(String[] args) {
        String apkDirectoryPath = "/Users/macbook/IdeaProjects/Soot/src/Banking";
        String outputDirectoryPath = "/Users/macbook/IdeaProjects/Soot/src/banking_data";

        File apkDir = new File(apkDirectoryPath);
        if (!apkDir.isDirectory()) {
            System.out.println("Invalid directory: " + apkDirectoryPath);
            return;
        }

        File outputDir = new File(outputDirectoryPath);
        if (!outputDir.exists() && !outputDir.mkdirs()) {
            System.out.println("Failed to create output directory: " + outputDirectoryPath);
            return;
        }

        List<File> apks = getAPKFiles(apkDir);
        int apkCounter = 1;
        for (File apk : apks) {
            System.out.println("Processing: " + apk.getName());
            try {
                String apkName = apk.getName().replace(".apk", "");
                String decodedDir = apkDirectoryPath + "/" + apkName + "_decoded";
                String apkOutputDir = outputDir.getAbsolutePath() + "/" + apkName;
                File apkDirFile = new File(apkOutputDir);
                if (!apkDirFile.exists()) apkDirFile.mkdirs();

                String packageName = extractManifest(apk, decodedDir, apkDirFile);
                String packageOutputDir = apkOutputDir + "/" + packageName.replace(".", "/");
                File packageDir = new File(packageOutputDir);
                if (!packageDir.exists()) packageDir.mkdirs();

                generateClassGraph(apk.getAbsolutePath(), apkName, apkCounter, packageOutputDir);
                generateMethodCallGraph(apk.getAbsolutePath(), apkName, apkCounter, packageOutputDir);
                extractAST(apk.getAbsolutePath(), apkName, apkCounter, packageOutputDir);
                analyzeLayoutXML(apk.getAbsolutePath(), apkName, apkCounter, packageOutputDir);
                detectObfuscation(apk.getAbsolutePath(), apkName, apkCounter, packageOutputDir);
                detectSteganographyAndSaveAsJson(apk.getAbsolutePath(), apkName, apkCounter, packageOutputDir);
            } catch (Exception e) {
                System.err.println("Error processing " + apk.getName() + ": " + e.getMessage());
                e.printStackTrace();
            }
            apkCounter++;
        }
    }

    private static List<File> getAPKFiles(File dir) {
        List<File> apkFiles = new ArrayList<>();
        try {
            Files.walk(dir.toPath())
                    .filter(path -> path.toString().endsWith(".apk"))
                    .forEach(path -> apkFiles.add(path.toFile()));
        } catch (IOException e) {
            System.err.println("Error scanning directory: " + e.getMessage());
        }
        return apkFiles;
    }

    private static String extractManifest(File apk, String decodedDir, File outputDir) {
        String packageName = "unknown";
        File manifestFile = new File(decodedDir, "AndroidManifest.xml");

        if (!manifestFile.exists()) {
            try {
                decodeApkWithApktool(apk.getAbsolutePath(), decodedDir);
            } catch (Exception e) {
                System.err.println("Failed to decode APK with apktool: " + e.getMessage());
                return packageName;
            }
        }

        if (!manifestFile.exists()) {
            System.err.println("Decoded manifest still not found at: " + manifestFile.getAbsolutePath());
            return packageName;
        }

        try {
            File outputManifest = new File(outputDir, apk.getName() + "_AndroidManifest.xml");
            Files.copy(manifestFile.toPath(), outputManifest.toPath(), StandardCopyOption.REPLACE_EXISTING);
            packageName = parseManifest(outputManifest, apk.getName(), outputDir);
        } catch (IOException e) {
            System.err.println("Error copying manifest: " + e.getMessage());
        }
        return packageName;
    }

    private static void decodeApkWithApktool(String apkPath, String outputDir) throws IOException, InterruptedException {
        File apktoolFile = new File(APKTOOL_PATH);
        if (!apktoolFile.exists()) {
            throw new IOException("apktool.jar not found at: " + APKTOOL_PATH + ". Please download it and update the path.");
        }

        ProcessBuilder pb = new ProcessBuilder("java", "-jar", APKTOOL_PATH, "d", apkPath, "-f", "-o", outputDir);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println("apktool: " + line);
            }
        }

        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("apktool decoding failed with exit code: " + exitCode);
        }
    }

    private static String parseManifest(File manifestFile, String apkName, File outputDir) {
        String packageName = "unknown";
        try {
            DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
            DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
            try (InputStreamReader isr = new InputStreamReader(new FileInputStream(manifestFile), StandardCharsets.UTF_8)) {
                Document doc = dBuilder.parse(new InputSource(isr));
                doc.getDocumentElement().normalize();

                JSONObject jsonManifest = new JSONObject();
                packageName = doc.getDocumentElement().getAttribute("package");
                jsonManifest.put("package", packageName);

                JSONArray permissions = new JSONArray();
                NodeList permissionNodes = doc.getElementsByTagName("uses-permission");
                for (int i = 0; i < permissionNodes.getLength(); i++) {
                    Element permission = (Element) permissionNodes.item(i);
                    permissions.put(permission.getAttribute("android:name"));
                }
                jsonManifest.put("permissions", permissions);

                JSONArray receivers = new JSONArray();
                NodeList receiverNodes = doc.getElementsByTagName("receiver");
                for (int i = 0; i < receiverNodes.getLength(); i++) {
                    Element receiver = (Element) receiverNodes.item(i);
                    JSONObject receiverObj = new JSONObject();
                    receiverObj.put("name", receiver.getAttribute("android:name"));
                    if (receiver.hasAttribute("android:exported")) {
                        receiverObj.put("exported", receiver.getAttribute("android:exported"));
                    }
                    receivers.put(receiverObj);
                }
                jsonManifest.put("receivers", receivers);

                JSONArray services = new JSONArray();
                NodeList serviceNodes = doc.getElementsByTagName("service");
                for (int i = 0; i < serviceNodes.getLength(); i++) {
                    Element service = (Element) serviceNodes.item(i);
                    JSONObject serviceObj = new JSONObject();
                    serviceObj.put("name", service.getAttribute("android:name"));
                    if (service.hasAttribute("android:exported")) {
                        serviceObj.put("exported", service.getAttribute("android:exported"));
                    }
                    services.put(serviceObj);
                }
                jsonManifest.put("services", services);

                JSONArray activities = new JSONArray();
                NodeList activityNodes = doc.getElementsByTagName("activity");
                for (int i = 0; i < activityNodes.getLength(); i++) {
                    Element activity = (Element) activityNodes.item(i);
                    JSONObject activityObj = new JSONObject();
                    activityObj.put("name", activity.getAttribute("android:name"));
                    if (activity.hasAttribute("android:exported")) {
                        activityObj.put("exported", activity.getAttribute("android:exported"));
                    }
                    activities.put(activityObj);
                }
                jsonManifest.put("activities", activities);

                File jsonFile = new File(outputDir, apkName.replace(".apk", "") + "_manifest.json");
                try (FileWriter writer = new FileWriter(jsonFile, StandardCharsets.UTF_8)) {
                    writer.write(jsonManifest.toString(4));
                }
                System.out.println("Manifest data saved to: " + jsonFile.getAbsolutePath());
            }
        } catch (Exception e) {
            System.err.println("Error parsing manifest: " + e.getMessage());
            e.printStackTrace();
        }
        return packageName;
    }

    private static double analyzeEntropy(BufferedImage image) {
        int width = image.getWidth();
        int height = image.getHeight();
        int[] pixelValues = new int[width * height];

        for (int i = 0; i < width; i++) {
            for (int j = 0; j < height; j++) {
                pixelValues[i * height + j] = image.getRGB(i, j);
            }
        }

        double[] histogram = new double[256];
        for (int pixelValue : pixelValues) {
            int grayValue = (pixelValue >> 16) & 0xFF;
            histogram[grayValue]++;
        }

        double totalPixels = pixelValues.length;
        for (int i = 0; i < 256; i++) {
            histogram[i] /= totalPixels;
        }

        double entropy = 0.0;
        for (double prob : histogram) {
            if (prob > 0) {
                entropy -= prob * Math.log(prob) / Math.log(2);
            }
        }
        return entropy;
    }

    private static void extractApk(String apkPath, String extractDir) throws IOException {
        File dir = new File(extractDir);
        if (!dir.exists()) dir.mkdirs();

        try (ZipInputStream zis = new ZipInputStream(new BufferedInputStream(new FileInputStream(apkPath)))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                File newFile = new File(extractDir, entry.getName());
                if (entry.isDirectory()) {
                    newFile.mkdirs();
                } else {
                    newFile.getParentFile().mkdirs();
                    try (FileOutputStream fos = new FileOutputStream(newFile)) {
                        byte[] buffer = new byte[1024];
                        int len;
                        while ((len = zis.read(buffer)) > 0) {
                            fos.write(buffer, 0, len);
                        }
                    }
                }
            }
        }
    }

    private static String analyzeLsb(String imagePath) {
        try {
            BufferedImage image = ImageIO.read(new File(imagePath));
            int width = image.getWidth();
            int height = image.getHeight();

            int suspiciousCount = 0;
            for (int x = 0; x < width; x++) {
                for (int y = 0; y < height; y++) {
                    int pixel = image.getRGB(x, y);
                    int lsb = pixel & 1;
                    if (lsb == 1) suspiciousCount++;
                }
            }

            double ratio = (double) suspiciousCount / (width * height);
            return ratio > 0.5 ? "Possible LSB steganography detected" : "No significant LSB patterns";
        } catch (IOException e) {
            return "Error analyzing LSB: " + e.getMessage();
        }
    }

    private static void detectSteganographyAndSaveAsJson(String apkPath, String apkName, int apkCounter, String outputDir) {
        String extractDir = outputDir + "/extracted_" + apkCounter;
        try {
            extractApk(apkPath, extractDir);
            File extractedFolder = new File(extractDir);

            JSONObject resultJson = new JSONObject();
            JSONArray imagesArray = new JSONArray();

            File[] files = extractedFolder.listFiles();
            if (files != null) {
                for (File file : files) {
                    String fileName = file.getName().toLowerCase();
                    if (fileName.endsWith(".png") || fileName.endsWith(".jpg") || fileName.endsWith(".jpeg")) {
                        JSONObject imageResult = new JSONObject();
                        imageResult.put("image_name", fileName);

                        BufferedImage image = ImageIO.read(file);
                        if (image != null) {
                            String lsbResult = analyzeLsb(file.getAbsolutePath());
                            imageResult.put("LSB_steganography", lsbResult);

                            double entropy = analyzeEntropy(image);
                            imageResult.put("entropy", entropy);
                            imageResult.put("DCT_steganography", entropy > 7.0 ?
                                    "Possible high entropy detected" : "Normal entropy levels");

                            imagesArray.put(imageResult);
                        }
                    }
                }
            }

            resultJson.put("images", imagesArray);
            File jsonFile = new File(outputDir, apkName + "_steganography_analysis_" + apkCounter + ".json");
            try (FileWriter fileWriter = new FileWriter(jsonFile, StandardCharsets.UTF_8)) {
                fileWriter.write(resultJson.toString(4));
            }

            deleteDirectory(new File(extractDir));
            System.out.println("Steganography analysis saved to: " + jsonFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Error during steganography analysis: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void generateClassGraph(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
            setupSoot(apkPath);
            File outputFile = new File(outputDir, apkName + "_classgraph_" + apkCounter + ".dot");
            try (PrintWriter writer = new PrintWriter(outputFile, StandardCharsets.UTF_8)) {
                writer.println("digraph ClassGraph {");
                for (SootClass sc : Scene.v().getClasses()) {
                    for (SootClass parent : sc.getInterfaces()) {
                        writer.println("\"" + parent.getName() + "\" -> \"" + sc.getName() + "\";");
                    }
                    if (sc.hasSuperclass()) {
                        writer.println("\"" + sc.getSuperclass().getName() + "\" -> \"" + sc.getName() + "\";");
                    }
                }
                writer.println("}");
            }
            System.out.println("Class graph saved to: " + outputFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Failed to generate ClassGraph for " + apkName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void generateMethodCallGraph(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
            setupSoot(apkPath);
            CallGraph cg = Scene.v().getCallGraph();
            File outputFile = new File(outputDir, apkName + "_methodcallgraph_" + apkCounter + ".dot");
            try (PrintWriter writer = new PrintWriter(outputFile, StandardCharsets.UTF_8)) {
                writer.println("digraph MethodCallGraph {");
                for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
                    Edge edge = it.next();
                    writer.println("\"" + edge.getSrc() + "\" -> \"" + edge.getTgt() + "\";");
                }
                writer.println("}");
            }
            System.out.println("Method call graph saved to: " + outputFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Failed to generate MethodCallGraph for " + apkName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void analyzeLayoutXML(String apkPath, String apkName, int apkCounter, String outputDir) {
        String extractDir = outputDir + "/extracted_" + apkCounter;
        try {
            extractApk(apkPath, extractDir);
            String layoutPath = outputDir + "/" + apkName + "_layout_" + apkCounter + ".json";
            JSONObject resultJson = new JSONObject();
            JSONArray layoutsArray = new JSONArray();

            File layoutDir = new File(extractDir, "res/layout");
            if (!layoutDir.exists() || !layoutDir.isDirectory()) {
                System.out.println("No layout XML files found for: " + apkName);
                resultJson.put("layouts", layoutsArray);
                try (PrintWriter writer = new PrintWriter(layoutPath, StandardCharsets.UTF_8)) {
                    writer.write(resultJson.toString(4));
                }
                return;
            }

            List<File> layoutFiles = getXMLFiles(layoutDir);
            for (File file : layoutFiles) {
                try {
                    if (isBinaryXML(file)) {
                        System.out.println("Skipping binary XML: " + file.getName());
                        JSONObject layoutJson = new JSONObject();
                        layoutJson.put("layout_name", file.getName());
                        layoutJson.put("status", "Binary XML - requires decoding");
                        layoutsArray.put(layoutJson);
                        continue;
                    }

                    JSONObject layoutJson = analyzeXML(file);
                    if (layoutJson != null) {
                        layoutsArray.put(layoutJson);
                    }
                } catch (Exception e) {
                    System.err.println("Error processing " + file.getName() + ": " + e.getMessage());
                    JSONObject layoutJson = new JSONObject();
                    layoutJson.put("layout_name", file.getName());
                    layoutJson.put("error", e.getMessage());
                    layoutsArray.put(layoutJson);
                }
            }

            resultJson.put("layouts", layoutsArray);
            try (PrintWriter writer = new PrintWriter(layoutPath, StandardCharsets.UTF_8)) {
                writer.write(resultJson.toString(4));
            }

            deleteDirectory(new File(extractDir));
            System.out.println("Layout analysis saved: " + layoutPath);
        } catch (Exception e) {
            System.err.println("Error in layout analysis: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static List<File> getXMLFiles(File dir) {
        List<File> xmlFiles = new ArrayList<>();
        File[] files = dir.listFiles((d, name) -> name.endsWith(".xml"));
        if (files != null) {
            xmlFiles.addAll(Arrays.asList(files));
        }
        return xmlFiles;
    }

    private static JSONObject analyzeXML(File file) throws Exception {
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        try (InputStreamReader isr = new InputStreamReader(new FileInputStream(file), StandardCharsets.UTF_8)) {
            Document doc = dBuilder.parse(new InputSource(isr));
            doc.getDocumentElement().normalize();

            JSONObject layoutJson = new JSONObject();
            layoutJson.put("layout_name", file.getName());

            JSONArray elementsArray = new JSONArray();
            extractElements(doc.getDocumentElement(), elementsArray);

            layoutJson.put("elements", elementsArray);
            return layoutJson;
        }
    }

    private static void extractElements(Element element, JSONArray elementsArray) {
        JSONObject elementJson = new JSONObject();
        elementJson.put("type", element.getTagName());

        if (element.hasAttribute("android:id")) {
            elementJson.put("id", element.getAttribute("android:id"));
        } else {
            elementJson.put("id", "N/A");
        }

        if (element.hasAttribute("android:text")) {
            elementJson.put("text", element.getAttribute("android:text"));
        }

        if (element.hasAttribute("android:layout_width")) {
            elementJson.put("width", element.getAttribute("android:layout_width"));
        }

        if (element.hasAttribute("android:layout_height")) {
            elementJson.put("height", element.getAttribute("android:layout_height"));
        }

        elementsArray.put(elementJson);

        NodeList children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                extractElements((Element) node, elementsArray);
            }
        }
    }

    private static boolean isBinaryXML(File file) throws IOException {
        try (InputStream is = new FileInputStream(file)) {
            byte[] header = new byte[4];
            int bytesRead = is.read(header);
            if (bytesRead < 4) return true;
            return header[0] == 0x03 && header[1] == 0x00 && header[2] == 0x08 && header[3] == 0x00;
        }
    }

    private static void extractAST(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
            setupSoot(apkPath);

            JSONObject astJson = new JSONObject();
            JSONArray importsArray = new JSONArray();
            JSONArray classesArray = new JSONArray();

            Set<String> uniqueImports = new HashSet<>();
            Map<String, String> obfuscationMap = new HashMap<>();

            for (SootClass sc : Scene.v().getClasses()) {
                String originalClassName = sc.getName();
                String obfuscatedClassName = obfuscateName(originalClassName, obfuscationMap);

                JSONObject classJson = new JSONObject();
                classJson.put("name", obfuscatedClassName);
                classJson.put("superclass", sc.hasSuperclass() ?
                        obfuscateName(sc.getSuperclass().getName(), obfuscationMap) : "None");

                JSONArray interfacesArray = new JSONArray();
                for (SootClass iface : sc.getInterfaces()) {
                    String obfuscatedIface = obfuscateName(iface.getName(), obfuscationMap);
                    interfacesArray.put(obfuscatedIface);
                    uniqueImports.add(obfuscatedIface);
                }
                classJson.put("interfaces", interfacesArray);

                JSONArray fieldsArray = new JSONArray();
                for (SootField field : sc.getFields()) {
                    String obfuscatedFieldType = obfuscateName(field.getType().toString(), obfuscationMap);
                    fieldsArray.put(obfuscatedFieldType);
                    uniqueImports.add(obfuscatedFieldType);
                }
                classJson.put("fields", fieldsArray);

                JSONArray methodsArray = new JSONArray();
                for (SootMethod method : sc.getMethods()) {
                    JSONObject methodJson = new JSONObject();
                    String obfuscatedMethodName = obfuscateName(method.getName(), obfuscationMap);
                    methodJson.put("name", obfuscatedMethodName);

                    JSONArray parametersArray = new JSONArray();
                    for (Type param : method.getParameterTypes()) {
                        String obfuscatedParam = obfuscateName(param.toString(), obfuscationMap);
                        parametersArray.put(obfuscatedParam);
                        uniqueImports.add(obfuscatedParam);
                    }
                    methodJson.put("parameters", parametersArray);

                    String obfuscatedReturnType = obfuscateName(method.getReturnType().toString(), obfuscationMap);
                    methodJson.put("returnType", obfuscatedReturnType);
                    uniqueImports.add(obfuscatedReturnType);

                    methodsArray.put(methodJson);
                }
                classJson.put("methods", methodsArray);
                classesArray.put(classJson);
            }

            for (String imp : uniqueImports) {
                if (imp.contains(".")) {
                    importsArray.put(imp);
                }
            }

            astJson.put("apk", apkName);
            astJson.put("imports", importsArray);
            astJson.put("classes", classesArray);

            File outputFile = new File(outputDir, apkName + "_obfuscated_ast_" + apkCounter + ".json");
            try (PrintWriter writer = new PrintWriter(outputFile, StandardCharsets.UTF_8)) {
                writer.write(astJson.toString(4));
            }

            System.out.println("Obfuscated AST saved: " + outputFile.getAbsolutePath());

            // Uncomment to apply obfuscation back to Soot and regenerate code
            // applyObfuscationToSoot(obfuscationMap);

        } catch (Exception e) {
            System.err.println("Failed to generate obfuscated AST for " + apkName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String obfuscateName(String original, Map<String, String> obfuscationMap) {
        if (obfuscationMap.containsKey(original)) {
            return obfuscationMap.get(original);
        }
        if (original.startsWith("java.") || original.startsWith("android.") || original.startsWith("javax.")) {
            obfuscationMap.put(original, original);
            return original;
        }
        String obfuscated = "a" + UUID.randomUUID().toString().replaceAll("-", "").substring(0, 8);
        obfuscationMap.put(original, obfuscated);
        return obfuscated;
    }

    private static void applyObfuscationToSoot(Map<String, String> obfuscationMap) {
        for (SootClass sc : Scene.v().getClasses()) {
            String newName = obfuscationMap.get(sc.getName());
            if (newName != null && !newName.equals(sc.getName())) {
                sc.setName(newName);
            }
            for (SootMethod method : sc.getMethods()) {
                String newMethodName = obfuscationMap.get(method.getName());
                if (newMethodName != null && !newMethodName.equals(method.getName())) {
                    method.setName(newMethodName);
                }
            }
            for (SootField field : sc.getFields()) {
                String newFieldName = obfuscationMap.get(field.getName());
                if (newFieldName != null && !newFieldName.equals(field.getName())) {
                    field.setName(newFieldName);
                }
            }
        }
        Options.v().set_output_format(Options.output_format_dex);
        Options.v().set_output_dir("/path/to/obfuscated/output"); // Update this path
        PackManager.v().writeOutput();
    }

    private static void detectObfuscation(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
            setupSoot(apkPath);

            List<String> obfuscatedClasses = new ArrayList<>();
            List<String> obfuscatedMethods = new ArrayList<>();
            List<String> obfuscatedFields = new ArrayList<>();

            for (SootClass sc : Scene.v().getClasses()) {
                if (isObfuscatedName(sc.getName())) {
                    obfuscatedClasses.add(sc.getName());
                }
                for (SootMethod method : sc.getMethods()) {
                    if (isObfuscatedName(method.getName())) {
                        obfuscatedMethods.add(method.getSignature());
                    }
                }
                for (SootField field : sc.getFields()) {
                    if (isObfuscatedName(field.getName())) {
                        obfuscatedFields.add(field.getSignature());
                    }
                }
            }

            saveObfuscationResults(apkName, obfuscatedClasses, obfuscatedMethods, obfuscatedFields, outputDir, apkCounter);
        } catch (Exception e) {
            System.err.println("Error in obfuscation detection: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static boolean isObfuscatedName(String name) {
        String pattern = "^[a-zA-Z]{1,2}$|^[a-zA-Z0-9]{6,}$";
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(name);
        return m.matches() && !name.contains(".");
    }

    private static void saveObfuscationResults(String apkName, List<String> classes, List<String> methods,
                                               List<String> fields, String outputDir, int apkCounter) {
        JSONObject obfuscationJson = new JSONObject();
        obfuscationJson.put("apk", apkName);
        obfuscationJson.put("obfuscated_classes", new JSONArray(classes));
        obfuscationJson.put("obfuscated_methods", new JSONArray(methods));
        obfuscationJson.put("obfuscated_fields", new JSONArray(fields));

        File outputFile = new File(outputDir, apkName + "_obfuscation_" + apkCounter + ".json");
        try (PrintWriter writer = new PrintWriter(outputFile, StandardCharsets.UTF_8)) {
            writer.write(obfuscationJson.toString(4));
            System.out.println("Obfuscation results saved for " + apkName + ": " + outputFile.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error saving obfuscation results: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void deleteDirectory(File directory) {
        if (directory.exists()) {
            File[] files = directory.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        file.delete();
                    }
                }
            }
            directory.delete();
        }
    }

    private static void setupSoot(String apkPath) {
        G.reset();
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars("/Users/macbook/Library/Android/sdk/platforms/");
        Options.v().set_process_dir(List.of(apkPath));
        Options.v().set_force_android_jar("/Users/macbook/Library/Android/sdk/platforms/android-35/android.jar");
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().setPhaseOption("cg.spark", "on");
        Options.v().set_output_format(Options.output_format_none);
        Scene.v().loadNecessaryClasses();
        PackManager.v().runPacks();
    }
}