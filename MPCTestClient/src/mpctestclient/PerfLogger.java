package mpctestclient;


import mpc.Consts;
import mpc.PM;

import java.io.*;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Methods used for performance testing from the {@link MPCTestClient} class.
 */
//TODO
public class PerfLogger {
    static final String PERF_TRAP_CALL = "PM.check(PM.";
    static final String PERF_TRAP_CALL_END = ");";
    public static byte[] PERF_COMMAND = {Consts.CLA_MPC, Consts.INS_PERF_SETSTOP, 0, 0, 2, 0, 0};
    public final boolean MODIFY_SOURCE_FILES_BY_PERF = true;
    final FileOutputStream perfFile;
    public HashMap<Short, String> PERF_STOP_MAPPING = new HashMap<>();
    ArrayList<Map.Entry<String, Long>> perfResults = new ArrayList<>();


    public PerfLogger(FileOutputStream perfFile) {
        buildPerfMapping();
        this.perfFile = perfFile;
    }

    void saveLatexPerfLog(ArrayList<Map.Entry<String, Long>> results) {
        try {
            // Save performance results also as latex
            String logFileName = String.format("MPC_PERF_log_%d.tex", System.currentTimeMillis());
            FileOutputStream perfFile = new FileOutputStream(logFileName);
            String tableHeader = "\\begin{tabular}{|l|c|}\n"
                    + "\\hline\n"
                    + "\\textbf{Operation} & \\textbf{Time (ms)} \\\\\n"
                    + "\\hline\n"
                    + "\\hline\n";
            perfFile.write(tableHeader.getBytes());
            for (Map.Entry<String, Long> measurement : results) {
                String operation = measurement.getKey();
                operation = operation.replace("_", "\\_");
                perfFile.write(String.format("%s & %d \\\\ \\hline\n", operation, measurement.getValue()).getBytes());
            }
            String tableFooter = "\\hline\n\\end{tabular}";
            perfFile.write(tableFooter.getBytes());
            perfFile.close();
        } catch (IOException ex) {
            Logger.getLogger(MPCTestClient.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    void InsertPerfInfoIntoFile(String filePath, String cardName, String experimentID, String outputDir, HashMap<Short, Map.Entry<Short, Long>> perfResultsSubpartsRaw) throws IOException {
        try {
            BufferedReader br = new BufferedReader(new FileReader(filePath));
            String basePath = filePath.substring(0, filePath.lastIndexOf("\\"));
            String fileName = filePath.substring(filePath.lastIndexOf("\\"));

            String fileNamePerf = String.format("%s\\%s", outputDir, fileName);
            FileOutputStream fileOut = new FileOutputStream(fileNamePerf);
            String strLine;
            String resLine;
            // For every line of program try to find perfromance trap. If found and perf. is available, then insert comment into code
            while ((strLine = br.readLine()) != null) {

                if (strLine.contains(PERF_TRAP_CALL)) {
                    int trapStart = strLine.indexOf(PERF_TRAP_CALL);
                    int trapEnd = strLine.indexOf(PERF_TRAP_CALL_END);
                    // We have perf. trap, now check if we also corresponding measurement
                    String perfTrapName = strLine.substring(trapStart + PERF_TRAP_CALL.length(), trapEnd);
                    short perfID = getPerfStopFromName(perfTrapName);

                    if (perfResultsSubpartsRaw.containsKey(perfID)) {
                        // We have measurement for this trap, add into comment section
                        resLine = String.format("%s // %d ms (%s,%s) %s", strLine.substring(0, trapEnd + PERF_TRAP_CALL_END.length()), perfResultsSubpartsRaw.get(perfID).getValue(), cardName, experimentID, strLine.subSequence(trapEnd + PERF_TRAP_CALL_END.length(), strLine.length()));
                    } else {
                        resLine = strLine;
                    }
                } else {
                    resLine = strLine;
                }
                resLine += "\n";
                fileOut.write(resLine.getBytes());
            }

            fileOut.close();
        } catch (Exception e) {
            System.out.println(String.format("Failed to transform file %s ", filePath) + e);
        }
    }


    void InsertPerfInfoIntoFiles(String basePath, String cardName, String experimentID, HashMap<Short, Map.Entry<Short, Long>> perfResultsSubpartsRaw) throws IOException {
        File dir = new File(basePath);
        String[] filesArray = dir.list();
        if ((filesArray != null) && (dir.isDirectory() == true)) {
            // make subdir for results
            String outputDir = String.format("%s\\perf\\%s\\", basePath, experimentID);
            new File(outputDir).mkdirs();

            for (String fileName : filesArray) {
                File dir2 = new File(basePath + fileName);
                if (!dir2.isDirectory()) {
                    InsertPerfInfoIntoFile(String.format("%s\\%s", basePath, fileName), cardName, experimentID, outputDir, perfResultsSubpartsRaw);
                }
            }
        }
    }


    public void buildPerfMapping() {
        PERF_STOP_MAPPING.put(PM.PERF_START, "PERF_START");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_1, "TRAP_CRYPTOPS_ENCRYPT_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_2, "TRAP_CRYPTOPS_ENCRYPT_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_3, "TRAP_CRYPTOPS_ENCRYPT_3");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_4, "TRAP_CRYPTOPS_ENCRYPT_4");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_5, "TRAP_CRYPTOPS_ENCRYPT_5");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_6, "TRAP_CRYPTOPS_ENCRYPT_6");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_ENCRYPT_COMPLETE, "TRAP_CRYPTOPS_ENCRYPT_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_1, "TRAP_CRYPTOPS_DECRYPTSHARE_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_2, "TRAP_CRYPTOPS_DECRYPTSHARE_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE, "TRAP_CRYPTOPS_DECRYPTSHARE_COMPLETE");

        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_1, "TRAP_CRYPTOPS_SIGN_1");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_2, "TRAP_CRYPTOPS_SIGN_2");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_3, "TRAP_CRYPTOPS_SIGN_3");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_4, "TRAP_CRYPTOPS_SIGN_4");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_5, "TRAP_CRYPTOPS_SIGN_5");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_6, "TRAP_CRYPTOPS_SIGN_6");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_7, "TRAP_CRYPTOPS_SIGN_7");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_8, "TRAP_CRYPTOPS_SIGN_8");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_9, "TRAP_CRYPTOPS_SIGN_9");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_10, "TRAP_CRYPTOPS_SIGN_10");
        PERF_STOP_MAPPING.put(PM.TRAP_CRYPTOPS_SIGN_COMPLETE, "TRAP_CRYPTOPS_SIGN_COMPLETE");
    }


    public String getPerfStopName(short stopID) {
        if (PERF_STOP_MAPPING.containsKey(stopID)) {
            return PERF_STOP_MAPPING.get(stopID);
        } else {
            assert (false);
            return "PERF_UNDEFINED";
        }
    }

    public short getPerfStopFromName(String stopName) {
        for (Short stopID : PERF_STOP_MAPPING.keySet()) {
            if (PERF_STOP_MAPPING.get(stopID).equalsIgnoreCase(stopName)) {
                return stopID;
            }
        }
        assert (false);
        return PM.TRAP_UNDEFINED;
    }


    void SavePerformanceResults(HashMap<Short, Map.Entry<Short, Long>> perfResultsSubpartsRaw, String fileName) throws IOException {
        // Save performance traps into single file
        FileOutputStream perfLog = new FileOutputStream(fileName);
        String output = "perfID, previous perfID, time difference between perfID and previous perfID (ms)\n";
        perfLog.write(output.getBytes());
        for (Short perfID : perfResultsSubpartsRaw.keySet()) {
            output = String.format("%d, %d, %d\n", perfID, perfResultsSubpartsRaw.get(perfID).getKey(), perfResultsSubpartsRaw.get(perfID).getValue());
            perfLog.write(output.getBytes());
        }
        perfLog.close();
    }


    void writePerfLog(String operationName, Long time) throws IOException {
        perfResults.add(new AbstractMap.SimpleEntry<>(operationName, time));
        perfFile.write(String.format("%s,%d\n", operationName, time).getBytes());
        perfFile.flush();
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        perfFile.close();
        saveLatexPerfLog(perfResults);


    }
}
