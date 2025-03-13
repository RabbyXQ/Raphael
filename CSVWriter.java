import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

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