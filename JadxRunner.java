import java.io.*;

public class JadxRunner {

    public static void runJadx(String apkPath) throws IOException, InterruptedException {
        // Command to run JADX to decompile the APK
        String cmd = "jadx -d ./output_jadx " + apkPath;

        // Create a ProcessBuilder to execute the command
        ProcessBuilder processBuilder = new ProcessBuilder("/bin/bash", "-c", cmd);

        // Start the process
        Process process = processBuilder.start();

        // Capture and print the output from the command
        captureStream(process.getInputStream(), "OUTPUT");

        // Capture and print the error output from the command
        captureStream(process.getErrorStream(), "ERROR");

        // Wait for the process to complete and get the exit code
        int exitCode = process.waitFor();
        System.out.println("JADX command executed with exit code: " + exitCode);
    }

    private static void captureStream(InputStream stream, String streamType) throws IOException {
        BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
        String line;
        while ((line = reader.readLine()) != null) {
            System.out.println("[" + streamType + "] " + line);
        }
    }


}
