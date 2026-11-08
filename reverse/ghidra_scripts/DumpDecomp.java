// DumpDecomp.java — headless-постскрипт: декомпилировать все функции в C-подобный текст.
// Запускается через analyzeHeadless:
//   analyzeHeadless <proj> <name> -import <bin> -postScript DumpDecomp.java \
//       -scriptPath <toolbox>\reverse\ghidra_scripts -deleteProject
//@category CTF

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DumpDecomp extends GhidraScript {

    @Override
    public void run() throws Exception {
        DecompInterface ifc = new DecompInterface();
        ifc.toggleCCode(true);
        ifc.toggleSyntaxTree(true);
        if (!ifc.openProgram(currentProgram)) {
            println("/* decompiler не открылся */");
            return;
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        int shown = 0;
        for (Function f : fm.getFunctions(true)) {
            if (monitor.isCancelled()) {
                break;
            }
            if (f.isThunk()) {
                continue;
            }
            DecompileResults res = ifc.decompileFunction(f, 45, monitor);
            if (res == null || !res.decompileCompleted()) {
                continue;
            }
            String code = res.getDecompiledFunction().getC();
            if (code == null || code.isBlank()) {
                continue;
            }
            println("/* ==== " + f.getName() + " @ " + f.getEntryPoint() + " ==== */");
            println(code);
            shown++;
        }
        println("/* функций декомпилировано: " + shown + " */");
    }
}
