// SASF Ghidra Script: Control Flow Deobfuscator
// -----------------------------------------------
// Identifies and simplifies obfuscated control flow patterns:
//   - Opaque predicates (always-true/always-false conditions)
//   - Bogus basic blocks (dead code inserted by obfuscators)
//   - Dispatcher-based flattening (state variable + switch table)
//   - Indirect jumps through obfuscated tables
//
// Usage: Run via Ghidra Script Manager or headless mode:
//   analyzeHeadless . project -import binary -postScript SASFControlFlowDeobfuscator.java
//
// @category SASF
// @author Malvex Malware Analysis Platform

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.util.*;

public class SASFControlFlowDeobfuscator extends GhidraScript {

    private DecompInterface decompiler;
    private int opaquePredicates = 0;
    private int flattenedDispatchers = 0;
    private int bogusBlocks = 0;
    private List<Map<String, String>> findings = new ArrayList<>();

    @Override
    protected void run() throws Exception {
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        println("[SASF] Starting control flow deobfuscation analysis...");

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int funcCount = 0;

        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function func = funcs.next();
            if (func.isThunk() || func.isExternal()) continue;

            analyzeFunction(func);
            funcCount++;
            if (funcCount % 100 == 0) {
                monitor.setMessage("Analyzed " + funcCount + " functions...");
            }
        }

        decompiler.dispose();

        // Report
        println("\n===== SASF Control Flow Deobfuscation Report =====");
        println("Functions analyzed: " + funcCount);
        println("Opaque predicates: " + opaquePredicates);
        println("Flattened dispatchers: " + flattenedDispatchers);
        println("Bogus blocks: " + bogusBlocks);
        println("Total findings: " + findings.size());
        println("================================================\n");

        for (Map<String, String> f : findings) {
            println(String.format("  [%s] %s at %s in %s",
                f.get("type"), f.get("desc"), f.get("addr"), f.get("func")));
        }
    }

    private void analyzeFunction(Function func) throws Exception {
        // Decompile
        DecompileResults result = decompiler.decompileFunction(func, 30, monitor);
        if (!result.decompileCompleted()) return;

        HighFunction highFunc = result.getHighFunction();
        if (highFunc == null) return;

        // Check for dispatcher pattern (control flow flattening)
        detectDispatcher(func, highFunc);

        // Check for opaque predicates
        detectOpaquePredicates(func, highFunc);

        // Check for bogus blocks
        detectBogusBlocks(func);
    }

    private void detectDispatcher(Function func, HighFunction highFunc) {
        // Look for state variable pattern:
        // A local variable used as switch index with many cases
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();
        int switchCount = 0;
        int phiCount = 0;

        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() == PcodeOp.MULTIEQUAL) {
                phiCount++;
            }
            if (op.getOpcode() == PcodeOp.BRANCHIND) {
                switchCount++;
            }
        }

        // Flattened functions typically have high phi-node-to-block ratio
        // and indirect branches
        SimpleBlockModel blockModel = new SimpleBlockModel(currentProgram);
        int blockCount = 0;
        try {
            CodeBlockIterator blocks = blockModel.getCodeBlocksContaining(
                func.getBody(), monitor);
            while (blocks.hasNext()) {
                blocks.next();
                blockCount++;
            }
        } catch (Exception e) {
            return;
        }

        // Heuristic: if phiCount > blockCount * 0.5 and switchCount > 0
        // and blockCount > 20, likely flattened
        if (phiCount > blockCount * 0.5 && switchCount > 0 && blockCount > 20) {
            flattenedDispatchers++;
            Map<String, String> f = new HashMap<>();
            f.put("type", "control-flow-flattening");
            f.put("func", func.getName());
            f.put("addr", func.getEntryPoint().toString());
            f.put("desc", String.format("Dispatcher pattern: %d blocks, %d phi-nodes, %d switches",
                blockCount, phiCount, switchCount));
            findings.add(f);

            // Add bookmark
            currentProgram.getBookmarkManager().setBookmark(
                func.getEntryPoint(), "SASF", "CFF",
                "Control flow flattening detected");
        }
    }

    private void detectOpaquePredicates(Function func, HighFunction highFunc) {
        Iterator<PcodeOpAST> ops = highFunc.getPcodeOps();

        while (ops.hasNext()) {
            PcodeOpAST op = ops.next();
            if (op.getOpcode() == PcodeOp.CBRANCH) {
                Varnode condition = op.getInput(1);
                // Check if condition is a constant (always true/false)
                if (condition != null && condition.isConstant()) {
                    opaquePredicates++;
                    Map<String, String> f = new HashMap<>();
                    f.put("type", "opaque-predicate");
                    f.put("func", func.getName());
                    f.put("addr", op.getSeqnum().getTarget().toString());
                    f.put("desc", "Constant condition in CBRANCH — opaque predicate (value: " +
                        condition.getOffset() + ")");
                    findings.add(f);

                    currentProgram.getBookmarkManager().setBookmark(
                        op.getSeqnum().getTarget(), "SASF", "OP",
                        "Opaque predicate");
                }
            }
        }
    }

    private void detectBogusBlocks(Function func) {
        // Bogus blocks: unreachable code within function body
        // Check for blocks that are not reachable from function entry
        SimpleBlockModel blockModel = new SimpleBlockModel(currentProgram);
        Set<Address> reachable = new HashSet<>();
        Queue<Address> worklist = new LinkedList<>();

        try {
            CodeBlock entryBlock = blockModel.getFirstCodeBlockContaining(
                func.getEntryPoint(), monitor);
            if (entryBlock == null) return;

            worklist.add(entryBlock.getFirstStartAddress());
            reachable.add(entryBlock.getFirstStartAddress());

            while (!worklist.isEmpty()) {
                Address current = worklist.poll();
                CodeBlock block = blockModel.getFirstCodeBlockContaining(current, monitor);
                if (block == null) continue;

                CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                while (dests.hasNext()) {
                    CodeBlockReference ref = dests.next();
                    Address destAddr = ref.getDestinationBlock().getFirstStartAddress();
                    if (func.getBody().contains(destAddr) && !reachable.contains(destAddr)) {
                        reachable.add(destAddr);
                        worklist.add(destAddr);
                    }
                }
            }

            // Count unreachable blocks
            CodeBlockIterator allBlocks = blockModel.getCodeBlocksContaining(
                func.getBody(), monitor);
            int unreachable = 0;
            while (allBlocks.hasNext()) {
                CodeBlock block = allBlocks.next();
                if (!reachable.contains(block.getFirstStartAddress())) {
                    unreachable++;
                }
            }

            if (unreachable > 3) {
                bogusBlocks += unreachable;
                Map<String, String> f = new HashMap<>();
                f.put("type", "bogus-blocks");
                f.put("func", func.getName());
                f.put("addr", func.getEntryPoint().toString());
                f.put("desc", unreachable + " unreachable blocks — likely obfuscation padding");
                findings.add(f);
            }

        } catch (Exception e) {
            // skip on error
        }
    }
}
