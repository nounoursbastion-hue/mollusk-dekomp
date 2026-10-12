// Local Ghidra postscript: inferred pseudocode and observed listing, never original source.
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.zip.GZIPOutputStream;

public class MolluskNativeExport extends HeadlessScript {
    private String cell(Object value) { return String.valueOf(value).replace('\t',' ').replace('\n',' ').replace('\r',' '); }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path out = Paths.get(args[0]);
        int timeout = Integer.parseInt(args[1]), limit = Integer.parseInt(args[2]);
        long deadline = System.nanoTime() + Long.parseLong(args[3]) * 1000000000L;
        int total = currentProgram.getFunctionManager().getFunctionCount(), done = 0, ok = 0, failed = 0;
        long instructions = 0;
        try (BufferedWriter asm = new BufferedWriter(new OutputStreamWriter(new GZIPOutputStream(Files.newOutputStream(out.resolve("listing.asm.gz"))), StandardCharsets.UTF_8))) {
            InstructionIterator iter = currentProgram.getListing().getInstructions(true);
            while(iter.hasNext() && !monitor.isCancelled() && System.nanoTime() < deadline) {
                Instruction inst = iter.next();
                asm.write(inst.getAddress() + "\t" + inst.toString() + "\n"); instructions++;
            }
        }
        try (BufferedWriter symbols = Files.newBufferedWriter(out.resolve("symbols.tsv"))) {
            symbols.write("address\tname\ttype\tsource\n");
            SymbolIterator iter = currentProgram.getSymbolTable().getAllSymbols(true);
            while(iter.hasNext() && !monitor.isCancelled() && System.nanoTime() < deadline) {
                Symbol s = iter.next();
                symbols.write(s.getAddress()+"\t"+cell(s.getName(true))+"\t"+cell(s.getSymbolType())+"\t"+s.getSource()+"\n");
            }
        }
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        try (BufferedWriter index = Files.newBufferedWriter(out.resolve("functions.tsv"))) {
            index.write("address\tname\tsignature\tbody_bytes\tstatus\tpseudocode\tdiagnostic\n");
            FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
            while(iter.hasNext() && !monitor.isCancelled() && System.nanoTime() < deadline && (limit == 0 || done < limit)) {
                Function f = iter.next();
                String file = "", status = "failed", diagnostic = "";
                try {
                    DecompileResults result = decomp.decompileFunction(f, timeout, monitor);
                    if(result.decompileCompleted() && result.getDecompiledFunction() != null) {
                        file = "pseudocode/f_" + f.getEntryPoint().toString().replace(':','_') + ".c";
                        Files.writeString(out.resolve(file), "/* Inferred pseudocode, not original source. Processor-specific semantics require verification. */\n" + result.getDecompiledFunction().getC());
                        status = "inferred_unvalidated"; ok++;
                    } else { diagnostic = result.getErrorMessage(); failed++; }
                } catch(Exception ex) { diagnostic = ex.toString(); failed++; }
                index.write(f.getEntryPoint()+"\t"+cell(f.getName())+"\t"+cell(f.getSignature())+"\t"+f.getBody().getNumAddresses()+"\t"+status+"\t"+file+"\t"+cell(diagnostic)+"\n");
                done++;
                if(done % 250 == 0) { index.flush(); println("Mollusk: " + done + "/" + total + " recognized functions, " + ok + " inferred"); }
            }
        } finally { decomp.dispose(); }
        long errors = 0;
        try (BufferedWriter bookmarks = Files.newBufferedWriter(out.resolve("analysis-bookmarks.tsv"))) {
            bookmarks.write("address\ttype\tcategory\tdiagnostic\n");
            java.util.Iterator<Bookmark> iter = currentProgram.getBookmarkManager().getBookmarksIterator();
            while(iter.hasNext()) {
                Bookmark b = iter.next();
                bookmarks.write(b.getAddress()+"\t"+cell(b.getTypeString())+"\t"+cell(b.getCategory())+"\t"+cell(b.getComment())+"\n");
                if(b.getTypeString().equals("Error")) errors++;
            }
        }
        String json = "{\"recognized_functions\":"+total+",\"processed_functions\":"+done+",\"pseudocode_functions\":"+ok+",\"failed_functions\":"+failed+",\"listed_instructions\":"+instructions+",\"analysis_error_bookmarks\":"+errors+",\"analysis_timed_out\":"+analysisTimeoutOccurred()+",\"all_recognized_functions_processed\":"+(done==total)+",\"semantic_validation\":false}";
        Files.writeString(out.resolve("ghidra-summary.json"), json);
        println(json);
    }
}
