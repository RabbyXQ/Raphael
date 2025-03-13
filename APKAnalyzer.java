import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.json.JSONObject;
import org.json.JSONArray;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

public class APKAnalyzer {
    public static void main(String[] args) {
        String apkDirectoryPath = "./Banking";
        String outputDirectoryPath = "./banking_data";

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
                extractManifest(apk, outputDir);
                generateClassGraph(apk.getAbsolutePath(), apk.getName(), apkCounter, outputDir.getAbsolutePath());
                generateMethodCallGraph(apk.getAbsolutePath(), apk.getName(), apkCounter, outputDir.getAbsolutePath());
                extractAST(apk.getAbsolutePath(), apk.getName(), apkCounter, outputDir.getAbsolutePath());
                analyzeLayoutXML(apk.getAbsolutePath(), apk.getName(), apkCounter, outputDir.getAbsolutePath());
                detectObfuscation(apk.getAbsolutePath(), apk.getName(), apkCounter, outputDir.getAbsolutePath());
            } catch (Exception e) {
                System.err.println("Error processing " + apk.getName() + ": " + e.getMessage());
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

    private static void extractManifest(File apk, File outputDir) {
        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(apk.toPath()))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals("AndroidManifest.xml")) {
                    File manifestFile = new File(outputDir, apk.getName() + "_AndroidManifest.xml");
                    Files.copy(zis, manifestFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    parseManifest(manifestFile, apk.getName(), outputDir);
                    return;
                }
            }
        } catch (IOException e) {
            System.err.println("Error extracting manifest: " + e.getMessage());
        }
    }

    private static void parseManifest(File manifestFile, String apkName, File outputDir) {
        try {
            List<String> lines = Files.readAllLines(manifestFile.toPath());
            JSONObject jsonManifest = new JSONObject();
            JSONArray permissions = new JSONArray();

            for (String line : lines) {
                if (line.contains("permission")) {
                    permissions.put(line.trim());
                }
            }

            jsonManifest.put("permissions", permissions);

            File jsonFile = new File(outputDir, apkName + "_manifest.json");
            Files.write(jsonFile.toPath(), jsonManifest.toString(4).getBytes());
        } catch (IOException e) {
            System.err.println("Error parsing manifest: " + e.getMessage());
        }
    }

    private static void generateClassGraph(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
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

            File outputFile = new File(outputDir, apkName.replace(".apk", "") + "_classgraph_" + apkCounter + ".dot");
            try (PrintWriter writer = new PrintWriter(outputFile)) {
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
        } catch (Exception e) {
            System.err.println("Failed to generate ClassGraph for " + apkName + ": " + e.getMessage());
        }
    }

    private static void generateMethodCallGraph(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
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
            CallGraph cg = Scene.v().getCallGraph();

            File outputFile = new File(outputDir, apkName.replace(".apk", "") + "_methodcallgraph_" + apkCounter + ".dot");
            try (PrintWriter writer = new PrintWriter(outputFile)) {
                writer.println("digraph MethodCallGraph {");
                for (Iterator<Edge> it = cg.iterator(); it.hasNext(); ) {
                    Edge edge = it.next();
                    writer.println("\"" + edge.getSrc() + "\" -> \"" + edge.getTgt() + "\";");
                }
                writer.println("}");
            }
        } catch (Exception e) {
            System.err.println("Failed to generate MethodCallGraph for " + apkName + ": " + e.getMessage());
        }
    }


    private static void analyzeLayoutXML(String apkPath, String apkName, int apkCounter, String outputDir) {
        String layoutPath = outputDir + "/" + apkName.replace(".apk", "") + "_layout_" + apkCounter + ".json";
        JSONObject resultJson = new JSONObject();
        JSONArray layoutsArray = new JSONArray();

        File extractedDir = new File(outputDir, apkName.replace(".apk", ""));
        File layoutDir = new File(extractedDir, "res/layout");

        if (!layoutDir.exists() || !layoutDir.isDirectory()) {
            System.out.println("No layout XML files found for: " + apkName);
            return;
        }

        List<File> layoutFiles = getXMLFiles(layoutDir);
        for (File file : layoutFiles) {
            try {
                JSONObject layoutJson = analyzeXML(file);
                if (layoutJson != null) {
                    layoutsArray.put(layoutJson);
                }
            } catch (Exception e) {
                System.err.println("Error processing " + file.getName() + ": " + e.getMessage());
            }
        }

        resultJson.put("layouts", layoutsArray);

        // Save JSON output
        try (PrintWriter writer = new PrintWriter(layoutPath)) {
            writer.write(resultJson.toString(4));
        } catch (Exception e) {
            System.err.println("Error saving JSON: " + e.getMessage());
        }

        System.out.println("Layout analysis saved: " + layoutPath);
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
        Document doc = dBuilder.parse(file);
        doc.getDocumentElement().normalize();

        JSONObject layoutJson = new JSONObject();
        layoutJson.put("layout_name", file.getName());

        JSONArray elementsArray = new JSONArray();
        extractElements(doc.getDocumentElement(), elementsArray);

        layoutJson.put("elements", elementsArray);
        return layoutJson;
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


    private static void extractAST(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
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

            // JSON Object to store AST
            JSONObject astJson = new JSONObject();
            JSONArray importsArray = new JSONArray();
            JSONArray classesArray = new JSONArray();

            Set<String> uniqueImports = new HashSet<>();

            for (SootClass sc : Scene.v().getClasses()) {
                JSONObject classJson = new JSONObject();
                classJson.put("name", sc.getName());
                classJson.put("superclass", sc.hasSuperclass() ? sc.getSuperclass().getName() : "None");

                JSONArray interfacesArray = new JSONArray();
                for (SootClass iface : sc.getInterfaces()) {
                    interfacesArray.put(iface.getName());
                    uniqueImports.add(iface.getName());
                }
                classJson.put("interfaces", interfacesArray);

                JSONArray fieldsArray = new JSONArray();
                for (SootField field : sc.getFields()) {
                    fieldsArray.put(field.getType().toString());
                    uniqueImports.add(field.getType().toString());
                }
                classJson.put("fields", fieldsArray);

                JSONArray methodsArray = new JSONArray();
                for (SootMethod method : sc.getMethods()) {
                    JSONObject methodJson = new JSONObject();
                    methodJson.put("name", method.getName());

                    JSONArray parametersArray = new JSONArray();
                    for (Type param : method.getParameterTypes()) {
                        parametersArray.put(param.toString());
                        uniqueImports.add(param.toString());
                    }
                    methodJson.put("parameters", parametersArray);

                    methodJson.put("returnType", method.getReturnType().toString());
                    uniqueImports.add(method.getReturnType().toString());

                    methodsArray.put(methodJson);
                }
                classJson.put("methods", methodsArray);
                classesArray.put(classJson);
            }

            // Add inferred imports to JSON
            for (String imp : uniqueImports) {
                if (imp.contains(".")) { // Ignore primitive types
                    importsArray.put(imp);
                }
            }

            astJson.put("apk", apkName);
            astJson.put("imports", importsArray);
            astJson.put("classes", classesArray);

            // Write JSON output
            File outputFile = new File(outputDir, apkName.replace(".apk", "") + "_ast_" + apkCounter + ".json");
            try (PrintWriter writer = new PrintWriter(outputFile)) {
                writer.write(astJson.toString(4)); // Pretty-print JSON
            }

            System.out.println("AST saved: " + outputFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Failed to generate AST for " + apkName + ": " + e.getMessage());
        }
    }

    private static void detectObfuscation(String apkPath, String apkName, int apkCounter, String outputDir) {
        try {
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

            List<String> obfuscatedClasses = new ArrayList<>();
            List<String> obfuscatedMethods = new ArrayList<>();
            List<String> obfuscatedFields = new ArrayList<>();

            // Check class names for patterns indicating obfuscation
            for (SootClass sc : Scene.v().getClasses()) {
                if (isObfuscatedName(sc.getName())) {
                    obfuscatedClasses.add(sc.getName());
                }

                // Check methods within classes
                for (SootMethod method : sc.getMethods()) {
                    if (isObfuscatedName(method.getName())) {
                        obfuscatedMethods.add(method.getName());
                    }

                    // Check fields within classes
                    for (SootField field : sc.getFields()) {
                        if (isObfuscatedName(field.getName())) {
                            obfuscatedFields.add(field.getName());
                        }
                    }
                }
            }

            // Save or log the findings
            saveObfuscationResults(apkName, obfuscatedClasses, obfuscatedMethods, obfuscatedFields, outputDir);

        } catch (Exception e) {
            System.err.println("Error detecting obfuscation in APK " + apkName + ": " + e.getMessage());
        }
    }

    // Helper method to check if a name matches obfuscation patterns
    private static boolean isObfuscatedName(String name) {
        // Regex pattern for detecting obfuscated names (e.g., random string patterns)
        String pattern = "^[a-zA-Z0-9]{6,}$"; // Match names with random-looking alphanumeric characters
        Pattern p = Pattern.compile(pattern);
        Matcher m = p.matcher(name);
        return m.matches();
    }

    // Save obfuscation detection results to a file
    private static void saveObfuscationResults(String apkName, List<String> classes, List<String> methods, List<String> fields, String outputDir) {
        JSONObject obfuscationJson = new JSONObject();
        obfuscationJson.put("apk", apkName);
        obfuscationJson.put("obfuscated_classes", new JSONArray(classes));
        obfuscationJson.put("obfuscated_methods", new JSONArray(methods));
        obfuscationJson.put("obfuscated_fields", new JSONArray(fields));

        // Save the results to a JSON file
        File outputFile = new File(outputDir, apkName.replace(".apk", "") + "_obfuscation.json");
        try (PrintWriter writer = new PrintWriter(outputFile)) {
            writer.write(obfuscationJson.toString(4));
            System.out.println("Obfuscation results saved for " + apkName);
        } catch (IOException e) {
            System.err.println("Error saving obfuscation results: " + e.getMessage());
        }
    }
}
