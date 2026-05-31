


import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.script.GhidraScript;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.SegmentedAddress;

import ghidra.program.model.scalar.Scalar;

import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;

import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionTag;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

import ghidra.program.model.mem.Memory;

import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import ghidra.util.UniversalID;

public class ExportSources extends GhidraScript {

	private static final String MANUAL_ASM_TAG = "MANUAL_ASM";

	private static final String MODE_ALL = "all";
	private static final String MODE_C   = "c";
	private static final String MODE_ASM = "asm";

	private static final String[] LOADER_CATEGORY_PREFIXES = {
			"/DOS", "/PE", "/MZ", "/LE", "/LX", "/ELF", "/MachO", "/Windows"
	};

	private Program program;
	private ReferenceManager referenceManager;
	private SymbolTable symbolTable;
	private DecompInterface decompiler;
	private Pattern includePattern;
	private String basename;
	private String projectPrefix;
	private MemoryModel memoryModel;

	private static String decorateWatcall(String functionName) { return functionName + "_"; }

	private enum MemoryModel { SMALL, LARGE, FLAT }

	private final List<Function> cFunctions = new ArrayList<>();
	private final List<Function> asmFunctions = new ArrayList<>();
	private final List<Data> externData = new ArrayList<>();

	private final Map<String, String> inlineCandidateLiterals = new LinkedHashMap<>();
	private final Map<String, Data> inlineCandidateData = new LinkedHashMap<>();
	private final Set<String> actuallyInlined = new HashSet<>();

	@Override
	public void run() throws Exception {
		String[] arguments = getScriptArgs();
		if(arguments.length < 3) {
			printerr("usage: ExportSources <out_dir> <basename> <include_glob> [mode=all|c|asm]");
			return;
		}

		Path output = Paths.get(arguments[0]);
		basename = arguments[1];
		projectPrefix = basename + "_";
		includePattern = globToRegex(arguments[2]);
		String mode = arguments.length >= 4 ? arguments[3] : MODE_ALL;
		if(!MODE_ALL.equals(mode) && !MODE_C.equals(mode) && !MODE_ASM.equals(mode)) {
			printerr("unknown mode: " + mode + " (expected all|c|asm)");
			return;
		}

		boolean emitCAndHeader = MODE_ALL.equals(mode) || MODE_C.equals(mode);
		boolean emitAsm        = MODE_ALL.equals(mode) || MODE_ASM.equals(mode);

		Files.createDirectories(output);

		program = currentProgram;
		referenceManager = program.getReferenceManager();
		symbolTable = program.getSymbolTable();
		memoryModel = detectMemoryModel(program.getCompilerSpec().getCompilerSpecID().getIdAsString());

		decompiler = new DecompInterface();
		try {
			if(!decompiler.openProgram(program)) {
				printerr("decompiler failed to open program: " + decompiler.getLastMessage());
				return;
			}

			collect();

			String cSource = emitCAndHeader ? emitC() : null;
			String asmSource = emitAsm ? emitAsm() : null;
			String header = emitCAndHeader ? emitHeader() : null;

			if(emitCAndHeader) {
				atomicWrite(output.resolve(basename + ".h"), header);
				atomicWrite(output.resolve(basename + ".c"), cSource);
			}
			if(emitAsm) {
				atomicWrite(output.resolve(basename + ".asm"), asmSource);
			}

			StringBuilder summary = new StringBuilder("wrote ");
			if(emitCAndHeader) {
				summary.append(cFunctions.size()).append(" c funcs, ")
						.append(externData.size()).append(" externs, ")
						.append(actuallyInlined.size()).append(" inlined strings");
			}

			if(emitCAndHeader && emitAsm) summary.append(", ");
			if(emitAsm) summary.append(asmFunctions.size()).append(" asm funcs");

			println(summary.toString());
		}
		finally {
			decompiler.dispose();
		}
	}

	private void collect() {
		FunctionManager functionManager = program.getFunctionManager();
		List<Function> all = new ArrayList<>();
		for(Function function : functionManager.getFunctions(true)) all.add(function);
		all.sort(Comparator.comparing(Function::getEntryPoint));

		for(Function function : all) {
			if(function.isExternal() || function.isThunk()) continue;
			if(!includePattern.matcher(function.getName()).matches()) continue;

			boolean isManualAsm = false;
			for(FunctionTag tag : function.getTags()) {
				if(MANUAL_ASM_TAG.equals(tag.getName())) {
					isManualAsm = true;
					break;
				}
			}

			if(isManualAsm) asmFunctions.add(function);
			else cFunctions.add(function);
		}

		Listing listing = program.getListing();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		UniversalID localId = dataTypeManager.getUniversalID();

		for(Data data : listing.getDefinedData(true)) {
			DataType type = data.getDataType();
			SourceArchive archive = type.getSourceArchive();

			boolean userType = archive != null
					&& archive.getSourceArchiveID().equals(localId)
					&& !(type instanceof BuiltInDataType)
					&& !isLoaderCategory(type.getCategoryPath().getPath());

			Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());
			String preferredName = primary != null ? primary.getName() : null;
			boolean userLabel = false;

			for(Symbol symbol : symbolTable.getSymbols(data.getMinAddress())) {
				SourceType source = symbol.getSource();
				if(source == SourceType.USER_DEFINED || source == SourceType.IMPORTED) {
					userLabel = true;
					boolean primaryIsAuto = primary == null
							|| primary.getSource() == SourceType.DEFAULT
							|| primary.getSource() == SourceType.ANALYSIS;

					if(preferredName == null || primaryIsAuto) preferredName = symbol.getName();
					break;
				}
			}

			if(!userType && !userLabel) continue;
			if(preferredName == null) continue;

			boolean stringLike = isStringLike(data);
			if(stringLike) {
				String literal = stringLiteralFromData(data);
				if(literal != null) {
					inlineCandidateLiterals.put(preferredName, literal);
					inlineCandidateData.put(preferredName, data);
					continue;
				}
			}

			externData.add(data);
		}
	}

	private String emitHeader() {
		StringBuilder stringBuilder = new StringBuilder();
		String guard = basename.toUpperCase().replaceAll("[^A-Z0-9]", "_") + "_H";

		stringBuilder.append("#ifndef ").append(guard).append('\n');
		stringBuilder.append("#define ").append(guard).append("\n\n");
		stringBuilder.append("#include <stddef.h>\n");
		stringBuilder.append("#include <stdint.h>\n");
		stringBuilder.append("#include <stdio.h>\n");
		stringBuilder.append("#include <dos.h>\n");
		stringBuilder.append("#include <stdbool.h>\n\n");

		stringBuilder.append("typedef struct find_t find_t;\n\n");

		stringBuilder.append("typedef unsigned char  byte;\n");
		stringBuilder.append("typedef unsigned short word, ushort, uint;\n");
		stringBuilder.append("typedef unsigned long  dword, ulong;\n");
		stringBuilder.append("typedef void code;\n\n");

		appendUserTypes(stringBuilder);

		if(!externData.isEmpty()) {
			for(Data data : externData) {
				Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());
				String name = primary != null ? primary.getName() : ("DAT_" + data.getMinAddress());
				stringBuilder.append("extern ").append(renderExternDecl(data, name)).append(";\n");
			}
		}

		for(Map.Entry<String, Data> entry : inlineCandidateData.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;

			Data data = entry.getValue();
			stringBuilder.append("extern ").append(renderExternDecl(data, name)).append("; /* inline fallback */\n");
		}

		stringBuilder.append("\n#endif\n");

		return stringBuilder.toString();
	}

	private void appendUserTypes(StringBuilder stringBuilder) {
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		UniversalID localId = dataTypeManager.getUniversalID();

		List<DataType> userTypes = new ArrayList<>();

		Iterator<DataType> it = dataTypeManager.getAllDataTypes();
		while(it.hasNext()) {
			DataType type = it.next();
			if(type instanceof Pointer || type instanceof Array) continue;
			if(type instanceof BuiltInDataType) continue;

			SourceArchive archive = type.getSourceArchive();
			if(archive == null) continue;
			if(!archive.getSourceArchiveID().equals(localId)) continue;

			if(isLoaderCategory(type.getCategoryPath().getPath())) continue;

			userTypes.add(type);
		}

		userTypes.sort(Comparator.comparing(DataType::getPathName));

		if(userTypes.isEmpty()) return;

		for(DataType type : userTypes) {
			if(type instanceof TypeDef) {
				TypeDef typedef = (TypeDef) type;
				stringBuilder.append("typedef ").append(renderTypeForDecl(typedef.getDataType(), type.getName())).append(";\n\n");
			}
			else if(type instanceof Structure) {
				Structure s = (Structure) type;
				stringBuilder.append("typedef struct ").append(s.getName()).append(" {\n");

				for(DataTypeComponent typeComponent : s.getDefinedComponents()) {
					String fieldName = typeComponent.getFieldName() != null ? typeComponent.getFieldName() : ("field_" + typeComponent.getOffset());
					stringBuilder.append("\t").append(renderTypeForDecl(typeComponent.getDataType(), fieldName)).append(";");

					if(typeComponent.getComment() != null && !typeComponent.getComment().isEmpty()) {
						stringBuilder.append(" /* ").append(typeComponent.getComment()).append(" */");
					}

					stringBuilder.append('\n');
				}

				stringBuilder.append("} ").append(s.getName()).append(";\n\n");
			}
			else if(type instanceof Union) {
				Union union = (Union) type;
				stringBuilder.append("typedef union ").append(union.getName()).append(" {\n");

				for(DataTypeComponent typeComponent : union.getDefinedComponents()) {
					String fieldName = typeComponent.getFieldName() != null ? typeComponent.getFieldName() : ("field_" + typeComponent.getOrdinal());
					stringBuilder.append("\t").append(renderTypeForDecl(typeComponent.getDataType(), fieldName)).append(";\n");
				}

				stringBuilder.append("} ").append(union.getName()).append(";\n\n");
			}
			else if(type instanceof Enum) {
				Enum enumeration = (Enum) type;
				stringBuilder.append("typedef enum ").append(enumeration.getName()).append(" {\n");
				String[] names = enumeration.getNames();
				for(int i = 0; i < names.length; i++) {
					stringBuilder.append("\t").append(names[i]).append(" = ").append(enumeration.getValue(names[i]));
					if(i < names.length - 1) stringBuilder.append(',');
					stringBuilder.append('\n');
				}
				stringBuilder.append("} ").append(enumeration.getName()).append(";\n\n");
			}
		}
	}

	private String emitC() {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("#include \"").append(basename).append(".h\"\n\n");

		Map<String, Pattern> patternsBySymbol = new LinkedHashMap<>();
		for(String symbolName : inlineCandidateLiterals.keySet()) {
			patternsBySymbol.put(symbolName, Pattern.compile("\\b" + Pattern.quote(symbolName) + "\\b"));
		}

		List<String> bodies = new ArrayList<>(cFunctions.size());
		Map<String, Integer> occurrenceCount = new LinkedHashMap<>();
		for(String symbol : patternsBySymbol.keySet()) occurrenceCount.put(symbol, 0);

		for(Function function : cFunctions) {
			DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
			if(!results.decompileCompleted() || results.getDecompiledFunction() == null) {
				bodies.add(null);
				continue;
			}
			String body = results.getDecompiledFunction().getC();
			bodies.add(body);
			if(body == null) continue;

			for(Map.Entry<String, Pattern> entry : patternsBySymbol.entrySet()) {
				Matcher matcher = entry.getValue().matcher(body);
				int count = 0;
				while(matcher.find()) count++;
				if(count > 0) occurrenceCount.merge(entry.getKey(), count, Integer::sum);
			}
		}

		for(int i = 0; i < cFunctions.size(); i++) {
			Function function = cFunctions.get(i);
			String body = bodies.get(i);

			String platePre = program.getListing().getComment(CommentType.PLATE, function.getEntryPoint());
			if(platePre != null && !platePre.isEmpty()) {
				stringBuilder.append("/*\n");
				for(String line : platePre.split("\n")) stringBuilder.append(" * ").append(line).append('\n');
				stringBuilder.append(" */\n");
			}

			if(body == null) {
				stringBuilder.append("/* decompile failed for ").append(function.getName()).append(" */\n\n");
				continue;
			}

			for(Map.Entry<String, Pattern> entry : patternsBySymbol.entrySet()) {
				String symbolName = entry.getKey();
				if(occurrenceCount.getOrDefault(symbolName, 0) != 1) continue;
				Pattern pattern = entry.getValue();
				Matcher matcher = pattern.matcher(body);
				if(matcher.find()) {
					actuallyInlined.add(symbolName);
					matcher.reset();
					body = matcher.replaceAll(Matcher.quoteReplacement(inlineCandidateLiterals.get(symbolName)));
				}
			}

			body = normalizeDecompiledBody(body);

			stringBuilder.append(body);
			if(!body.endsWith("\n")) stringBuilder.append('\n');
			stringBuilder.append('\n');
		}

		appendGlobalDefinitions(stringBuilder);

		return stringBuilder.toString();
	}

	private void appendGlobalDefinitions(StringBuilder stringBuilder) {
		boolean anyEmitted = false;
		StringBuilder section = new StringBuilder();

		for(Data data : externData) {
			Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());

			String name = primary != null ? primary.getName() : ("DAT_" + data.getMinAddress());
			if(!name.startsWith(projectPrefix)) continue;

			section.append(renderDefinition(data, name)).append(";\n");
			anyEmitted = true;
		}

		for(Map.Entry<String, Data> entry : inlineCandidateData.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;
			if(!name.startsWith(projectPrefix)) continue;

			Data data = entry.getValue();
			String literal = inlineCandidateLiterals.get(name);
			int length = data.getLength();
			String dimension = length > 0 ? "[" + length + "]" : "[]";

			section.append("char ").append(name).append(dimension);

			if(literal != null) section.append(" = ").append(literal);

			section.append(";\n");
			anyEmitted = true;
		}

		if(anyEmitted) {
			stringBuilder.append("\n");
			stringBuilder.append(section);
			stringBuilder.append('\n');
		}
	}

	private static final Pattern _CSPEC_KEYWORD = Pattern.compile("\\b__(?:cdecl|stdcall|watcall)16(?:near|far)?\\b\\s*");
	private static final Pattern _PARTIAL_FIELD = Pattern.compile("([A-Za-z_][A-Za-z_0-9]*)\\._([0-9]+)_([0-9]+)_");

	private static String normalizeDecompiledBody(String body) {
		body = _CSPEC_KEYWORD.matcher(body).replaceAll("");

		Matcher matcher = _PARTIAL_FIELD.matcher(body);
		StringBuffer stringBuffer = new StringBuffer();
		while(matcher.find()) {
			String var = matcher.group(1);
			int offset = Integer.parseInt(matcher.group(2));
			int size  = Integer.parseInt(matcher.group(3));
			String castType;
			switch(size) {
				case 1: {
					castType = "byte";
					break;
				}

				case 2: {
					castType = "word";
					break;
				}

				case 4: {
					castType = "dword";
					break;
				}

				default: {
					castType = null;
					break;
				}
			}

			if(castType == null) {
				matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(matcher.group(0)));
			}
			else {
				String replacement = "(*(" + castType + " *)((char *)&" + var + " + " + offset + "))";
				matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(replacement));
			}
		}

		matcher.appendTail(stringBuffer);

		return stringBuffer.toString();
	}

	private String renderDefinition(Data data, String identifier) {
		DataType type = data.getDataType();
		if(isStringTypeName(type)) {
			int length = data.getLength();
			return length > 0
					? "char " + identifier + "[" + length + "]"
					: "char " + identifier + "[]";
		}

		return renderTypeForDecl(type, identifier);
	}

	private final Set<String> asmDefinedDecorated = new HashSet<>();

	private final Map<String, String> asmExterns = new LinkedHashMap<>();

	private String emitAsm() {
		StringBuilder stringBuilder = new StringBuilder();

		switch(memoryModel) {
			case FLAT: {
				stringBuilder.append("\t.386p\n\t.model flat\n\n");
				break;
			}

			case LARGE: {
				stringBuilder.append("\t.386\n\t.model large\n\n");
				break;
			}

			case SMALL:
			default: {
				stringBuilder.append("\t.386\n\t.model small\n\n");
				break;
			}
		}

		for(Function function : asmFunctions) asmDefinedDecorated.add(decorateWatcall(function.getName()));

		TreeMap<String, List<Function>> bySegment = new TreeMap<>();
		for(Function function : asmFunctions) {
			String seg = segmentKey(function.getEntryPoint());
			bySegment.computeIfAbsent(seg, k -> new ArrayList<>()).add(function);
		}

		StringBuilder bodyBuffer = new StringBuilder();
		for(Map.Entry<String, List<Function>> entry : bySegment.entrySet()) {
			String segName = entry.getKey();
			List<Function> functions = entry.getValue();
			functions.sort(Comparator.comparing(Function::getEntryPoint));

			if(memoryModel == MemoryModel.FLAT) {
				bodyBuffer.append("_TEXT SEGMENT PUBLIC 'CODE' USE32\n\n");
			}
			else {
				bodyBuffer.append(segName).append(" SEGMENT BYTE PUBLIC 'CODE' USE16\n");
				bodyBuffer.append("\tASSUME CS:").append(segName).append(", DS:DGROUP\n\n");
			}

			for(Function function : functions) {
				bodyBuffer.append("PUBLIC ").append(decorateWatcall(function.getName())).append('\n');
			}

			bodyBuffer.append('\n');

			for(Function function : functions) {
				emitAsmFunction(bodyBuffer, function);
				bodyBuffer.append('\n');
			}

			if(memoryModel == MemoryModel.FLAT) bodyBuffer.append("_TEXT ENDS\n\n");
			else bodyBuffer.append(segName).append(" ENDS\n\n");
		}

		if(!asmExterns.isEmpty()) {
			for(Map.Entry<String, String> e : asmExterns.entrySet()) {
				stringBuilder.append("EXTRN ").append(e.getKey()).append(":").append(e.getValue()).append('\n');
			}

			stringBuilder.append('\n');
		}

		stringBuilder.append(bodyBuffer);
		stringBuilder.append("\tEND\n");

		return stringBuilder.toString();
	}

	private void emitAsmFunction(StringBuilder stringBuilder, Function function) {
		String decoratedName = decorateWatcall(function.getName());
		String platePre = program.getListing().getComment(CommentType.PLATE, function.getEntryPoint());

		if(platePre != null && !platePre.isEmpty()) {
			for(String line : platePre.split("\n")) stringBuilder.append("; ").append(line).append('\n');
		}

		String procFlavor = memoryModel == MemoryModel.FLAT ? "NEAR" : "NEAR";
		stringBuilder.append(decoratedName).append(" PROC ").append(procFlavor).append('\n');

		AddressSetView body = function.getBody();
		Listing listing = program.getListing();
		InstructionIterator it = listing.getInstructions(body, true);
		while(it.hasNext()) {
			Instruction instruction = it.next();

			for(Symbol symbol : symbolTable.getSymbols(instruction.getAddress())) {
				if(symbol.getName().equals(function.getName())) continue;

				String symbolName = symbol.getName();
				if(symbolName.startsWith("LAB_") || symbolName.startsWith("SUB_") || symbol.getSource() == SourceType.USER_DEFINED) {
					stringBuilder.append(symbolName).append(":\n");
					break;
				}
			}

			String mnemonic = instruction.getMnemonicString().toUpperCase();
			int dot = mnemonic.indexOf('.');
			String prefix = null;
			if(dot > 0) {
				prefix = mnemonic.substring(dot + 1);
				mnemonic = mnemonic.substring(0, dot);
			}

			if(("JMPF".equals(mnemonic) || "CALLF".equals(mnemonic)) && isLiteralFarTarget(instruction)) {
				appendRawBytes(stringBuilder, instruction);

				String eolForRaw = listing.getComment(CommentType.EOL, instruction.getAddress());
				if(eolForRaw != null && !eolForRaw.isEmpty()) stringBuilder.append("\t; ").append(eolForRaw);

				stringBuilder.append("\t; ").append(mnemonic).append(' ').append(instruction.getDefaultOperandRepresentation(0));
				stringBuilder.append('\n');

				continue;
			}

			boolean implicitOperands = isStringOp(mnemonic);

			if(prefix != null) stringBuilder.append('\t').append(prefix).append(' ').append(mnemonic);
			else stringBuilder.append('\t').append(mnemonic);

			if(!implicitOperands) {
				int operands = instruction.getNumOperands();
				if(operands > 0) {
					stringBuilder.append(' ');
					for(int i = 0; i < operands; i++) {
						if(i > 0) stringBuilder.append(", ");
						stringBuilder.append(renderOperand(instruction, i, function));
					}
				}
			}

			String eol = listing.getComment(CommentType.EOL, instruction.getAddress());
			if(eol != null && !eol.isEmpty()) stringBuilder.append("\t; ").append(eol);

			stringBuilder.append('\n');
		}

		stringBuilder.append(decoratedName).append(" ENDP\n");
	}

	private String renderOperand(Instruction instruction, int operandIndex, Function inFunction) {
		String text = instruction.getDefaultOperandRepresentation(operandIndex);
		String mnemonic = instruction.getMnemonicString().toUpperCase();

		Reference[] references = instruction.getOperandReferences(operandIndex);
		for(Reference reference : references) {
			if(!reference.isPrimary()) continue;

			Address target = reference.getToAddress();
			if(target == null) continue;

			Symbol symbol = symbolTable.getPrimarySymbol(target);
			if(symbol == null) continue;

			RefType referenceType = reference.getReferenceType();

			String symbolName = symbol.getName();
			if(!isValidAsmIdentifier(symbolName)) continue;

			if(referenceType.isFlow() && !referenceType.isComputed()) {
				if(symbol.getSymbolType() == SymbolType.FUNCTION) {
					String decorated = decorateWatcall(symbolName);
					if(!asmDefinedDecorated.contains(decorated)) {
						asmExterns.putIfAbsent(decorated, "NEAR");
					}

					return decorated;
				}

				if(symbol.getSource() == SourceType.DEFAULT && !targetIsInEmittedAsm(target)) {
					return formatFarAddress(target);
				}

				return symbolName;
			}

			String renderedName = symbol.getSymbolType() == SymbolType.FUNCTION
					? decorateWatcall(symbolName)
					: symbolName;

			boolean isMemoryOperand = text.contains("[");
			if(referenceType.isData()) {
				boolean isDefinedHere = symbol.getSymbolType() == SymbolType.FUNCTION && asmDefinedDecorated.contains(renderedName);
				if(!isDefinedHere) {
					asmExterns.putIfAbsent(renderedName, inferDataExternType(symbol));
				}

				if(isMemoryOperand) {
					return substituteAddressInOperand(text, renderedName);
				}

				Scalar immediate = instruction.getScalar(operandIndex);
				if(immediate != null && target instanceof SegmentedAddress) {
					SegmentedAddress segTarget = (SegmentedAddress) target;

					long val = immediate.getUnsignedValue();
					if(val == segTarget.getSegment()) return "SEG " + renderedName;
					if(val == segTarget.getSegmentOffset()) return "OFFSET " + renderedName;
				}

				return "OFFSET " + renderedName;
			}
		}

		return masmifyOperand(text);
	}

	private static final Set<String> STRING_OPS = new HashSet<>(java.util.Arrays.asList(
			"LODSB", "LODSW", "LODSD",
			"STOSB", "STOSW", "STOSD",
			"MOVSB", "MOVSW", "MOVSD",
			"CMPSB", "CMPSW", "CMPSD",
			"SCASB", "SCASW", "SCASD",
			"INSB",  "INSW",  "INSD",
			"OUTSB", "OUTSW", "OUTSD"));

	private static boolean isStringOp(String mnemonic) { return STRING_OPS.contains(mnemonic); }

	private static boolean isValidAsmIdentifier(String name) {
		if(name == null || name.isEmpty()) return false;

		char ch = name.charAt(0);
		if(!Character.isLetter(ch) && ch != '_' && ch != '$' && ch != '@') return false;

		for(int i = 1; i < name.length(); i++) {
			char c = name.charAt(i);
			if(!Character.isLetterOrDigit(c) && c != '_' && c != '$' && c != '@') return false;
		}

		return true;
	}

	private boolean isLiteralFarTarget(Instruction instruction) {
		Reference[] references = instruction.getReferencesFrom();
		for(Reference reference : references) {
			Address address = reference.getToAddress();
			if(address == null) continue;

			Symbol symbol = symbolTable.getPrimarySymbol(address);
			if(symbol != null && symbol.getSource() != SourceType.DEFAULT) return false;
			if(symbol != null && targetIsInEmittedAsm(address)) return false;
		}

		return true;
	}

	private void appendRawBytes(StringBuilder stringBuilder, Instruction instruction) {
		try {
			byte[] bytes = instruction.getBytes();
			stringBuilder.append("\tDB ");

			for(int i = 0; i < bytes.length; i++) {
				if(i > 0) stringBuilder.append(", ");

				int byteValue = bytes[i] & 0xff;

				String prefix = (byteValue >= 0xA0) ? "0" : "";
				stringBuilder.append(prefix).append(String.format("%02X", byteValue)).append('h');
			}
		}
		catch(Exception e) {
			stringBuilder.append("\t; <bytes unavailable: ").append(e.getMessage()).append(">");
		}
	}

	private boolean targetIsInEmittedAsm(Address addr) {
		for(Function fn : asmFunctions) {
			if(fn.getBody().contains(addr)) return true;
		}

		return false;
	}

	private static String formatFarAddress(Address address) {
		if(address instanceof SegmentedAddress) {
			SegmentedAddress segmentedAddress = (SegmentedAddress) address;
			return String.format("0%04Xh:0%04Xh", segmentedAddress.getSegment(), segmentedAddress.getSegmentOffset());
		}

		return String.format("0%Xh", address.getOffset());
	}

	private boolean inFunctionOwnsSymbol(Function fn, Symbol sym) {
		Address functionEntry = fn.getEntryPoint();
		Address symbolAddress = sym.getAddress();

		return segmentKey(functionEntry).equals(segmentKey(symbolAddress));
	}

	private String inferDataExternType(Symbol sym) {
		Data data = program.getListing().getDataAt(sym.getAddress());
		if(data == null) return "BYTE";

		int length = data.getLength();
		switch(length) {
			case 1: return "BYTE";
			case 2: return "WORD";
			case 4: return "DWORD";
			default: return "BYTE";
		}
	}

	private static final Pattern OPERAND_NUMERIC = Pattern.compile("\\b(?:0x[0-9A-Fa-f]+|[0-9][0-9A-Fa-f]*h|[0-9]+)\\b");

	private String substituteAddressInOperand(String text, String symbolName) {
		String masmified = masmifyOperand(text);
		Matcher matcher = OPERAND_NUMERIC.matcher(masmified);

		if(matcher.find()) {
			return masmified.substring(0, matcher.start()) + symbolName + masmified.substring(matcher.end());
		}

		return masmified;
	}

	private static final Pattern HEX_LITERAL = Pattern.compile("\\b0x([0-9A-Fa-f]+)\\b");

	private String masmifyOperand(String operand) {
		String out = operand.replace("word ptr", "WORD PTR")
				.replace("byte ptr", "BYTE PTR")
				.replace("dword ptr", "DWORD PTR")
				.replace("qword ptr", "QWORD PTR");

		Matcher matcher = HEX_LITERAL.matcher(out);
		StringBuffer stringBuilder = new StringBuffer();

		while(matcher.find()) {
			String digits = matcher.group(1).toUpperCase();
			String prefix = Character.isLetter(digits.charAt(0)) ? "0" : "";
			matcher.appendReplacement(stringBuilder, prefix + digits + "h");
		}

		matcher.appendTail(stringBuilder);

		return stringBuilder.toString();
	}


	private String segmentKey(Address address) {
		String string = address.toString();

		int colon = string.indexOf(':');
		if(colon < 0) return "_TEXT";

		return "SEG_" + string.substring(0, colon);
	}

	private static MemoryModel detectMemoryModel(String cspecId) {
		if("watcom16far".equals(cspecId)) return MemoryModel.LARGE;
		if("watcom16".equals(cspecId)) return MemoryModel.SMALL;

		return MemoryModel.FLAT;
	}

	private boolean isStringLike(Data data) {
		DataType type = data.getDataType();

		if(type instanceof StringDataType) return true;
		if(type instanceof TerminatedStringDataType) return true;

		if(type instanceof Array) {
			DataType element = ((Array) type).getDataType();
			String elementName = element.getName();
			if(!"char".equals(elementName) && !"byte".equals(elementName) && !"undefined1".equals(elementName)) return false;

			int length = ((Array) type).getNumElements();
			Memory memory = program.getMemory();
			try {
				boolean sawPrintable = false;
				boolean sawTerminator = false;

				for(int i = 0; i < length; i++) {
					int byteValue = memory.getByte(data.getMinAddress().add(i)) & 0xff;
					if(byteValue == 0) {
						sawTerminator = true;
						break;
					}

					if(byteValue >= 0x20 && byteValue < 0x7f) sawPrintable = true;
					else if(byteValue == '\n' || byteValue == '\r' || byteValue == '\t') sawPrintable = true;
					else return false;
				}

				return sawPrintable && sawTerminator;
			}
			catch(Exception ignored) {
				return false;
			}
		}

		return false;
	}

	private String stringLiteralFromData(Data data) {
		Memory memory = program.getMemory();
		StringBuilder stringBuilder = new StringBuilder("\"");

		try {
			int length;

			DataType type = data.getDataType();
			if(type instanceof Array) length = ((Array) type).getNumElements();
			else length = data.getLength();

			for(int i = 0; i < length; i++) {
				int byteValue = memory.getByte(data.getMinAddress().add(i)) & 0xff;
				if(byteValue == 0) break;

				switch(byteValue) {
					case '\\': {
						stringBuilder.append("\\\\");
						break;
					}

					case '"': {
						stringBuilder.append("\\\"");
						break;
					}

					case '\n': {
						stringBuilder.append("\\n");
						break;
					}

					case '\r': {
						stringBuilder.append("\\r");
						break;
					}

					case '\t': {
						stringBuilder.append("\\t");
						break;
					}

					default: {
						if(byteValue >= 0x20 && byteValue < 0x7f) stringBuilder.append((char) byteValue);
						else stringBuilder.append(String.format("\\x%02x", byteValue));
					}
				}
			}
		}
		catch(Exception ignored) {
			return null;
		}

		stringBuilder.append("\"");

		return stringBuilder.toString();
	}

	private static boolean isLoaderCategory(String categoryPath) {
		for(String prefix : LOADER_CATEGORY_PREFIXES) {
			if(categoryPath.equals(prefix) || categoryPath.startsWith(prefix + "/")) return true;
		}

		return false;
	}

	private static Pattern globToRegex(String glob) {
		StringBuilder stringBuilder = new StringBuilder("^");

		for(int i = 0; i < glob.length(); i++) {
			char typeComponent = glob.charAt(i);
			switch(typeComponent) {
				case '*': {
					stringBuilder.append(".*");
					break;
				}

				case '?': {
					stringBuilder.append('.');
					break;
				}

				case '.':
				case '\\':
				case '(':
				case ')':
				case '[':
				case ']':
				case '{':
				case '}':
				case '^':
				case '$':
				case '|':
				case '+': {
					stringBuilder.append('\\').append(typeComponent);
					break;
				}

				default: {
					stringBuilder.append(typeComponent);
					break;
				}
			}
		}

		stringBuilder.append('$');
		return Pattern.compile(stringBuilder.toString());
	}

	private String renderExternDecl(Data data, String identifier) {
		DataType type = data.getDataType();
		if(isStringTypeName(type)) {
			int length = data.getLength();
			if(length > 0) return "char " + identifier + "[" + length + "]";
			return "char " + identifier + "[]";
		}

		return renderTypeForDecl(type, identifier);
	}

	private static boolean isStringTypeName(DataType type) {
		String name = type.getName();
		return "string".equals(name)
				|| "TerminatedCString".equals(name)
				|| "string-utf8".equals(name)
				|| "unicode".equals(name)
				|| "TerminatedUnicode".equals(name);
	}

	private String renderTypeForDecl(DataType type, String identifier) {
		StringBuilder arraySuffix = new StringBuilder();
		while(type instanceof Array) {
			Array array = (Array) type;
			int dimension = array.getNumElements();

			if(dimension > 0) arraySuffix.append('[').append(dimension).append(']');
			else arraySuffix.append("[]");
			type = array.getDataType();
		}

		StringBuilder pointerStars = new StringBuilder();
		while(type instanceof Pointer) {
			pointerStars.append('*');

			DataType pointee = ((Pointer) type).getDataType();
			if(pointee == null) break;

			type = pointee;
		}

		String baseName = mapTypeName(type);
		StringBuilder out = new StringBuilder(baseName);

		if(pointerStars.length() > 0) out.append(' ').append(pointerStars);
		out.append(' ').append(identifier).append(arraySuffix);

		return out.toString();
	}

	private static String mapTypeName(DataType type) {
		String name = type.getName();

		switch(name) {
			case "char": return "char";
			case "void": return "void";
			case "bool": return "_Bool";
			case "float": return "float";
			case "double": return "double";
		}

		if(type instanceof Structure) return "struct " + name;
		if(type instanceof Union) return "union " + name;
		if(type instanceof Enum) return "enum " + name;

		if(type instanceof BuiltInDataType) {
			boolean unsigned;
			switch(name) {
				case "byte":
				case "word":
				case "dword":
				case "qword":
				case "uchar":
				case "ushort":
				case "uint":
				case "ulong":
				case "ulonglong":
				case "undefined":
				case "undefined1":
				case "undefined2":
				case "undefined4":
				case "undefined6":
				case "undefined8": {
					unsigned = true;
					break;
				}

				case "sbyte":
				case "sword":
				case "sdword":
				case "sqword":
				case "schar":
				case "short":
				case "int":
				case "long":
				case "longlong": {
					unsigned = false;
					break;
				}

				default: {
					unsigned = name.startsWith("u");
					break;
				}
			}

			switch(type.getLength()) {
				case 1: return unsigned ? "unsigned char" : "int8_t";
				case 2: return unsigned ? "uint16_t" : "int16_t";
				case 4: return unsigned ? "uint32_t" : "int32_t";
				case 8: return unsigned ? "uint64_t" : "int64_t";
			}
		}

		return name;
	}

	private void atomicWrite(Path target, String content) throws IOException {
		Path tmp = target.resolveSibling(target.getFileName().toString() + ".tmp");
		Files.writeString(tmp, content, StandardCharsets.UTF_8);
		Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
	}
}
