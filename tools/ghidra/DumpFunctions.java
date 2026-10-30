// DumpFunctions.java - callers, data strings, and decompilation for given functions.
//
// Headless usage (after the program has been imported/analyzed):
//   analyzeHeadless <project_dir> <project_name> -process Sky.exe -noanalysis \
//       -scriptPath tools/ghidra \
//       -postScript DumpFunctions.java <out_dir> <hex-address> [...]
//
// Addresses may be written with or without a 0x prefix. Writes
// <out_dir>/dump_functions_report.txt plus one decomp_0x<addr>.c per function.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;

public class DumpFunctions extends GhidraScript {

    private File outDir;
    private PrintWriter report;

    private String readCString(Address a) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 120; i++) {
                int b = currentProgram.getMemory().getByte(a.add(i)) & 0xff;
                if (b == 0) {
                    return sb.length() == 0 ? null : sb.toString();
                }
                if (b < 0x20 || b > 0x7e) {
                    return null;
                }
                sb.append((char) b);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private void dump(long addr) {
        Address a = toAddr(addr);
        Function f = getFunctionAt(a);
        if (f == null) {
            f = getFunctionContaining(a);
        }
        if (f == null) {
            report.printf("%n=== 0x%x: no function (not analyzed) ===%n", addr);
            return;
        }

        report.printf("%n=== 0x%x -> %s @0x%x size=%d ===%n", addr, f.getName(),
                f.getEntryPoint().getOffset(), f.getBody().getNumAddresses());

        ReferenceManager rm = currentProgram.getReferenceManager();
        List<String> callers = new ArrayList<>();
        for (Reference r : rm.getReferencesTo(f.getEntryPoint())) {
            if (!r.getReferenceType().isCall()) {
                continue;
            }
            Function cf = getFunctionContaining(r.getFromAddress());
            callers.add(String.format("0x%x(%s)", r.getFromAddress().getOffset(),
                    cf == null ? "?" : cf.getName()));
        }
        report.println("callers(" + callers.size() + "): " + callers);

        LinkedHashSet<String> strings = new LinkedHashSet<>();
        InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext()) {
            Instruction ins = it.next();
            for (Reference r : ins.getReferencesFrom()) {
                if (!r.getReferenceType().isData()) {
                    continue;
                }
                String s = readCString(r.getToAddress());
                if (s != null) {
                    strings.add(s);
                }
            }
        }
        report.println("unique data strings: " + strings.size());
        int n = 0;
        for (String s : strings) {
            report.println("  str: " + s);
            if (++n >= 40) {
                report.println("  ...");
                break;
            }
        }

        DecompInterface ifc = new DecompInterface();
        try {
            ifc.openProgram(currentProgram);
            DecompileResults res = ifc.decompileFunction(f, 180, monitor);
            if (res.decompileCompleted() && res.getDecompiledFunction() != null) {
                String c = res.getDecompiledFunction().getC();
                String name = String.format("decomp_0x%x.c", addr);
                try (PrintWriter w = new PrintWriter(new File(outDir, name))) {
                    w.print(c);
                }
                report.println("decompiled -> " + name + " (" + c.length() + " chars)");
                String[] lines = c.split("\n");
                for (int i = 0; i < Math.min(80, lines.length); i++) {
                    report.println(lines[i]);
                }
            } else {
                report.println("decompile failed: " + res.getErrorMessage());
            }
        } catch (Exception e) {
            report.println("decompile exception: " + e);
        } finally {
            ifc.dispose();
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: DumpFunctions.java <out_dir> <hex-address> [hex-address ...]");
            return;
        }
        outDir = new File(args[0]);
        if (!outDir.isDirectory() && !outDir.mkdirs()) {
            println("cannot create output dir: " + outDir);
            return;
        }

        try (PrintWriter w = new PrintWriter(
                new FileWriter(new File(outDir, "dump_functions_report.txt")))) {
            report = w;
            report.println("program: " + currentProgram.getName()
                    + "  imageBase: " + currentProgram.getImageBase());
            for (int i = 1; i < args.length; i++) {
                String s = args[i].toLowerCase().replace("0x", "");
                dump(Long.parseUnsignedLong(s, 16));
                report.flush();
            }
        }
        println("DumpFunctions done: " + new File(outDir, "dump_functions_report.txt"));
    }
}
