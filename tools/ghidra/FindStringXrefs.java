// FindStringXrefs.java - list where anchor strings occur and which functions reference them.
//
// Headless usage (after the program has been imported/analyzed):
//   analyzeHeadless <project_dir> <project_name> -process Sky.exe -noanalysis \
//       -scriptPath tools/ghidra \
//       -postScript FindStringXrefs.java <out_dir> "anchor string" ["another string" ...]
//
// Writes <out_dir>/find_string_xrefs_report.txt. Read-only toward the analyzed program.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class FindStringXrefs extends GhidraScript {

    private static class FnInfo {
        long entry;
        long size;
        final Set<String> strings = new LinkedHashSet<>();
        final List<Long> refs = new ArrayList<>();
    }

    private Address findInBlock(MemoryBlock block, byte[] needle, Address from) {
        try {
            return currentProgram.getMemory()
                    .findBytes(from, block.getEnd(), needle, null, true, monitor);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: FindStringXrefs.java <out_dir> <string> [string ...]");
            return;
        }
        File outDir = new File(args[0]);
        if (!outDir.isDirectory() && !outDir.mkdirs()) {
            println("cannot create output dir: " + outDir);
            return;
        }

        Memory mem = currentProgram.getMemory();
        ReferenceManager rm = currentProgram.getReferenceManager();
        Map<Long, FnInfo> byFn = new LinkedHashMap<>();

        try (PrintWriter out = new PrintWriter(
                new FileWriter(new File(outDir, "find_string_xrefs_report.txt")))) {
            out.println("program: " + currentProgram.getName()
                    + "  imageBase: " + currentProgram.getImageBase());

            for (int a = 1; a < args.length; a++) {
                String needle = args[a];
                byte[] nb = needle.getBytes("UTF-8");
                List<Address> occurrences = new ArrayList<>();
                for (MemoryBlock block : mem.getBlocks()) {
                    if (!block.isInitialized()) {
                        continue;
                    }
                    Address hit = findInBlock(block, nb, block.getStart());
                    while (hit != null) {
                        occurrences.add(hit);
                        hit = findInBlock(block, nb, hit.add(1));
                    }
                }

                out.printf("%n== %s: %d occurrence(s)%n", needle, occurrences.size());
                for (Address strAddr : occurrences) {
                    out.printf("   string @0x%x%n", strAddr.getOffset());
                    for (Reference r : rm.getReferencesTo(strAddr)) {
                        Address from = r.getFromAddress();
                        Function f = getFunctionContaining(from);
                        out.printf("     ref 0x%x type=%s fn=%s%n",
                                from.getOffset(), r.getReferenceType(),
                                f == null ? "?" : f.getName());
                        if (f != null) {
                            long entry = f.getEntryPoint().getOffset();
                            FnInfo fi = byFn.computeIfAbsent(entry, k -> new FnInfo());
                            fi.entry = entry;
                            fi.size = f.getBody().getNumAddresses();
                            fi.strings.add(needle);
                            fi.refs.add(from.getOffset());
                        }
                    }
                }
            }

            out.printf("%n%n=== functions referencing the strings (by count) ===%n");
            List<FnInfo> list = new ArrayList<>(byFn.values());
            list.sort((x, y) -> Integer.compare(y.strings.size(), x.strings.size()));
            for (FnInfo fi : list) {
                out.printf("fn 0x%x size=%d strings=%d: %s%n",
                        fi.entry, fi.size, fi.strings.size(), fi.strings);
                out.printf("    refs: %s%n", fi.refs);
            }

            if (list.isEmpty()) {
                out.println("(no function references found)");
            }
        }
        println("FindStringXrefs done: " + new File(outDir, "find_string_xrefs_report.txt"));
    }
}
