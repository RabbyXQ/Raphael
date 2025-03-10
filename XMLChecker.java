import org.w3c.dom.*;
import javax.xml.parsers.*;
import java.io.*;
import java.util.*;

public class XMLChecker {

    private static final String CSV_FILE_PATH = "output.csv"; // Path to save the CSV file
    private static CSVWriter csvWriter;

    /**
     * Scans all XML files in the given directory and analyzes their contents.
     *
     * @param resDir The Android project's `res` directory.
     */
    public static void scanXMLFiles(File resDir) {
        if (!resDir.exists() || !resDir.isDirectory()) {
            System.out.println("Invalid res directory: " + resDir.getAbsolutePath());
            return;
        }

        // Initialize the CSV writer
        try {
            csvWriter = new CSVWriter(new FileWriter(CSV_FILE_PATH));
            // Write the CSV header
            csvWriter.writeNext(new String[]{"File Name", "Element Type", "Attribute", "Value"});
        } catch (IOException e) {
            System.out.println("Error initializing CSV writer: " + e.getMessage());
            return;
        }

        System.out.println("Scanning XML files in: " + resDir.getAbsolutePath());
        scanDirectory(resDir);

        // Close the CSV writer after scanning
        try {
            csvWriter.close();
        } catch (IOException e) {
            System.out.println("Error closing CSV writer: " + e.getMessage());
        }
    }

    /**
     * Recursively scans directories for XML files and processes them.
     *
     * @param dir The directory to scan.
     */
    private static void scanDirectory(File dir) {
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File file : files) {
            if (file.isDirectory()) {
                scanDirectory(file); // Recursive scan for subdirectories
            } else if (file.getName().endsWith(".xml")) {
                analyzeXMLFile(file);
            }
        }
    }

    /**
     * Analyzes an XML file to extract relevant attributes and detect suspicious elements.
     *
     * @param xmlFile The XML file to analyze.
     */
    private static void analyzeXMLFile(File xmlFile) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(xmlFile);
            document.getDocumentElement().normalize();

            if (xmlFile.getParent().contains("layout")) {
                checkLayoutContext(xmlFile, document);
            } else if (xmlFile.getParent().contains("drawable") || xmlFile.getParent().contains("mipmap") || xmlFile.getParent().contains("xml")) {
                checkDrawableAndXmlFiles(xmlFile, document);
            }
        } catch (Exception e) {
            System.out.println("Error processing file: " + xmlFile.getName());
        }
    }

    /**
     * Extracts and prints the `tools:context` attribute from layout files and writes to CSV.
     *
     * @param xmlFile  The layout XML file.
     * @param document The parsed XML document.
     */
    private static void checkLayoutContext(File xmlFile, Document document) {
        Element rootElement = document.getDocumentElement();
        String context = rootElement.getAttribute("tools:context");

        if (!context.isEmpty()) {
            System.out.println("Found context in " + xmlFile.getName() + ": " + context);
            // Write to CSV
            csvWriter.writeNext(new String[]{xmlFile.getName(), "tools:context", "context", context});
        }
    }

    /**
     * Checks drawable, mipmap, and XML files for potentially suspicious elements and writes to CSV.
     *
     * @param xmlFile  The XML file to analyze.
     * @param document The parsed XML document.
     */
    private static void checkDrawableAndXmlFiles(File xmlFile, Document document) {
        NodeList nodes = document.getElementsByTagName("*"); // Get all elements
        for (int i = 0; i < nodes.getLength(); i++) {
            Element element = (Element) nodes.item(i);
            String tagName = element.getTagName();

            if (tagName.equalsIgnoreCase("bitmap") || tagName.equalsIgnoreCase("vector")) {
                System.out.println("Potentially suspicious image in " + xmlFile.getName() + ": " + tagName);
                // Write to CSV
                csvWriter.writeNext(new String[]{xmlFile.getName(), tagName, "suspicious", "image"});
            }
        }
    }

    public static void main(String[] args) {
        File resDir = new File("path/to/your/project/app/src/main/res"); // Change this path to your project
        scanXMLFiles(resDir);
    }
}

class CSVWriter {

    private final FileWriter fileWriter;
    private final BufferedWriter bufferedWriter;

    public CSVWriter(FileWriter fileWriter) throws IOException {
        this.fileWriter = fileWriter;
        this.bufferedWriter = new BufferedWriter(fileWriter);
    }

    public void writeNext(String[] data) {
        try {
            bufferedWriter.write(String.join(",", data));
            bufferedWriter.newLine();
        } catch (IOException e) {
            System.out.println("Error writing to CSV: " + e.getMessage());
        }
    }

    public void close() throws IOException {
        bufferedWriter.close();
        fileWriter.close();
    }
}
