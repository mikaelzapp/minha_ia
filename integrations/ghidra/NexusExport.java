// Bounded static export for NEXUS. Does not launch or attach to the input.
// @category NEXUS.Security
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import com.google.gson.Gson;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class NexusExport extends HeadlessScript {
    private static final int ITERATIONS = 100000;
    private final Map<String, Boolean> truncated = new LinkedHashMap<>();

    private static String clip(Object value, int size) {
        String text = value == null ? "" : String.valueOf(value);
        return text.length() > size ? text.substring(0, size) : text;
    }

    private static Map<String, Object> row(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) {
            result.put((String) values[index], values[index + 1]);
        }
        return result;
    }

    private static int bounded(String value, int max) {
        int number = Integer.parseInt(value);
        if (number < 1 || number > max) throw new IllegalArgumentException("Invalid export bound");
        return number;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 5 || currentProgram == null) throw new IllegalArgumentException("Expected output and four bounded options");
        Path output = Paths.get(args[0]).toAbsolutePath().normalize();
        int maxFunctions = bounded(args[1], 200);
        int maxStrings = bounded(args[2], 500);
        int maxReferences = bounded(args[3], 1000);
        if (!args[4].equals("true") && !args[4].equals("false")) throw new IllegalArgumentException("Invalid decompile option");
        boolean wantDecompile = Boolean.parseBoolean(args[4]);

        Map<String, Object> result = row(
            "schema", "nexus-ghidra-v1", "sha256", currentProgram.getExecutableSHA256(),
            "language_id", currentProgram.getLanguageID().toString(),
            "compiler_spec", currentProgram.getCompilerSpec().getCompilerSpecID().toString(),
            "executable_format", clip(currentProgram.getExecutableFormat(), 256),
            "image_base", currentProgram.getImageBase().toString(),
            "analysis_timed_out", analysisTimeoutOccurred());

        List<Map<String, Object>> functions = new ArrayList<>();
        List<Map<String, Object>> strings = new ArrayList<>();
        List<Map<String, Object>> imports = new ArrayList<>();
        List<Map<String, Object>> exports = new ArrayList<>();
        List<Map<String, Object>> references = new ArrayList<>();
        List<String> entries = new ArrayList<>();
        SymbolTable symbols = currentProgram.getSymbolTable();
        ghidra.program.model.address.AddressIterator entryIterator = symbols.getExternalEntryPointIterator();
        while (entryIterator.hasNext() && entries.size() < 100) {
            monitor.checkCancelled();
            entries.add(entryIterator.next().toString());
        }
        truncated.put("entry_points", entryIterator.hasNext());

        SymbolIterator externalSymbols = symbols.getExternalSymbols();
        int visited = 0;
        while (externalSymbols.hasNext() && imports.size() < 500 && visited++ < ITERATIONS) {
            monitor.checkCancelled();
            Symbol symbol = externalSymbols.next();
            imports.add(row("name", clip(symbol.getName(true), 256), "address", symbol.getAddress().toString(),
                            "kind", clip(symbol.getSymbolType(), 64), "source", "Ghidra symbol table"));
        }
        truncated.put("imports", externalSymbols.hasNext());
        SymbolIterator allSymbols = symbols.getAllSymbols(true);
        visited = 0;
        while (allSymbols.hasNext() && exports.size() < 500 && visited++ < ITERATIONS) {
            monitor.checkCancelled();
            Symbol symbol = allSymbols.next();
            if (symbol.isExternalEntryPoint()) {
                exports.add(row("name", clip(symbol.getName(true), 256), "address", symbol.getAddress().toString(),
                                "source", "Ghidra external entry-point symbol"));
            }
        }
        truncated.put("exports", allSymbols.hasNext());

        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        visited = 0;
        while (dataIterator.hasNext() && strings.size() < maxStrings && visited++ < ITERATIONS) {
            monitor.checkCancelled();
            Data data = dataIterator.next();
            if (data.hasStringValue()) {
                Object value = data.getValue();
                String text = value instanceof String ? (String) value : String.valueOf(value);
                strings.add(row("address", data.getAddress().toString(), "text", clip(text, 512),
                                "value_truncated", text.length() > 512, "source", "Ghidra defined string"));
            }
        }
        truncated.put("strings", dataIterator.hasNext());

        DecompInterface decompiler = null;
        boolean decompilerReady = false;
        String decompilerError = "";
        int decompiled = 0;
        if (wantDecompile) {
            try {
                decompiler = new DecompInterface();
                decompiler.toggleSyntaxTree(false);
                decompiler.toggleCCode(true);
                decompilerReady = decompiler.openProgram(currentProgram);
                if (!decompilerReady) decompilerError = clip(decompiler.getLastMessage(), 512);
            } catch (Exception error) {
                decompilerError = clip(error.getClass().getSimpleName() + ": " + error.getMessage(), 512);
            }
        }
        try {
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext() && functions.size() < maxFunctions) {
                monitor.checkCancelled();
                Function function = iterator.next();
                Map<String, Object> item = row("name", clip(function.getName(), 256),
                    "address", function.getEntryPoint().toString(), "signature", clip(function.getSignature(), 512),
                    "external", function.isExternal(), "thunk", function.isThunk(), "source", "Ghidra function manager");
                if (decompilerReady && !function.isExternal()) {
                    DecompileResults decompiledResult = decompiler.decompileFunction(function, 5, monitor);
                    if (decompiledResult.decompileCompleted() && decompiledResult.getDecompiledFunction() != null) {
                        String code = decompiledResult.getDecompiledFunction().getC();
                        item.put("pseudocode", clip(code, 4096));
                        item.put("pseudocode_truncated", code.length() > 4096);
                        item.put("pseudocode_source", "Ghidra native decompiler; static inference");
                        decompiled++;
                    } else {
                        item.put("decompile_error", clip(decompiledResult.getErrorMessage(), 512));
                    }
                }
                functions.add(item);
                // References originating in the selected functions only. No recursive graph expansion.
                InstructionIterator instructions = currentProgram.getListing().getInstructions(function.getBody(), true);
                int inspected = 0;
                while (instructions.hasNext() && references.size() < maxReferences && inspected++ < ITERATIONS) {
                    monitor.checkCancelled();
                    Instruction instruction = instructions.next();
                    for (Reference reference : instruction.getReferencesFrom()) {
                        if (references.size() >= maxReferences) break;
                        if (reference.getReferenceType().isCall()) {
                            Function destination = currentProgram.getFunctionManager().getFunctionAt(reference.getToAddress());
                            references.add(row("from_function", function.getEntryPoint().toString(),
                                "from", reference.getFromAddress().toString(), "to", reference.getToAddress().toString(),
                                "to_function", destination == null ? null : clip(destination.getName(), 256),
                                "kind", reference.getReferenceType().toString(), "source", "Ghidra static call reference"));
                        }
                    }
                }
                if (instructions.hasNext()) truncated.put("references", true);
            }
            truncated.put("functions", iterator.hasNext());
        } finally {
            if (decompiler != null) decompiler.dispose();
        }
        if (references.size() >= maxReferences) truncated.put("references", true);
        result.put("entry_points", entries);
        result.put("functions", functions);
        result.put("strings", strings);
        result.put("imports", imports);
        result.put("exports", exports);
        result.put("references", references);
        result.put("decompiler", row("requested", wantDecompile, "available", decompilerReady,
                                    "functions_decompiled", decompiled, "error", decompilerError,
                                    "seconds_per_function", 5));
        result.put("coverage", row("total_functions_detected", currentProgram.getFunctionManager().getFunctionCount(),
            "functions_exported", functions.size(), "strings_exported", strings.size(),
            "call_references_exported", references.size(), "truncated", truncated,
            "notice", "Function cap bounds export/decompilation; automatic whole-file analysis is bounded by timeout and memory. Indirect calls may be unknown."));
        // CREATE_NEW prevents replacing an unexpected existing export.
        try (Writer writer = Files.newBufferedWriter(output, StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW)) {
            new Gson().toJson(result, writer);
        }
        println("NEXUS_EXPORT_COMPLETE " + functions.size() + " functions");
    }
}
