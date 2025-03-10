import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.options.Options;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ClassGraphGenerator {

    public static void main(String[] args) {
        String apkDirectoryPath = "/Volumes/Shared/rabbyx/Riskware";
        String outputDirectoryPath = "./riskwares";

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
                generateClassGraph(apk.getAbsolutePath(), apk.getName(), apkCounter, outputDir.getAbsolutePath());
                generateMethodCallGraph(apk.getAbsolutePath(), apk.getName(), apkCounter, outputDir.getAbsolutePath());
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
            Files.walk(dir.toPath())
                    .filter(path -> path.toString().endsWith(".xapk"))
                    .forEach(path -> apkFiles.addAll(extractXAPK(path.toFile())));
        } catch (IOException e) {
            System.err.println("Error scanning directory: " + e.getMessage());
        }
        return apkFiles;
    }

    private static List<File> extractXAPK(File xapkFile) {
        List<File> extractedApks = new ArrayList<>();
        File tempDir = new File(xapkFile.getParent(), xapkFile.getName().replace(".xapk", "_extracted"));
        if (!tempDir.exists() && !tempDir.mkdirs()) {
            System.err.println("Failed to create extraction directory for " + xapkFile.getName());
            return extractedApks;
        }

        try (ZipInputStream zis = new ZipInputStream(Files.newInputStream(xapkFile.toPath()))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().endsWith(".apk")) {
                    File apkFile = new File(tempDir, entry.getName());
                    Files.copy(zis, apkFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
                    extractedApks.add(apkFile);
                }
            }
        } catch (IOException e) {
            System.err.println("Error extracting XAPK: " + e.getMessage());
        }
        return extractedApks;
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
}
