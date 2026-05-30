


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

import ghidra.util.UniversalID;

public class ExportSources extends GhidraScript {

	private static final String MANUAL_ASM_TAG = "MANUAL_ASM";

	private static final String[] LOADER_CATEGORY_PREFIXES = {
			"/DOS", "/PE", "/MZ", "/LE", "/LX", "/ELF", "/MachO", "/Windows"
	};

	private Program program;
	private ReferenceManager referenceManager;
	private SymbolTable symbolTable;
	private DecompInterface decompiler;
	private Pattern includePattern;
	private String basename;
	private MemoryModel memoryModel;

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
			printerr("usage: ExportSources <out_dir> <basename> <include_glob>");
			return;
		}

		Path output = Paths.get(arguments[0]);
		basename = arguments[1];
		includePattern = globToRegex(arguments[2]);

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

			String cSource = emitC();
			String asmSource = emitAsm();
			String header = emitHeader();

			atomicWrite(output.resolve(basename + ".h"), header);
			atomicWrite(output.resolve(basename + ".c"), cSource);
			atomicWrite(output.resolve(basename + ".asm"), asmSource);

			println(
					"wrote " +
					cFunctions.size() + " c funcs, " +
					asmFunctions.size() + " asm funcs, " +
					externData.size() + " externs, " +
					actuallyInlined.size() + " inlined strings");
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
		stringBuilder.append("#include <stddef.h>\n#include <stdint.h>\n\n");

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
				stringBuilder.append("struct ").append(s.getName()).append(" {\n");

				for(DataTypeComponent typeComponent : s.getDefinedComponents()) {
					String fieldName = typeComponent.getFieldName() != null ? typeComponent.getFieldName() : ("field_" + typeComponent.getOffset());
					stringBuilder.append("\t").append(renderTypeForDecl(typeComponent.getDataType(), fieldName)).append(";");

					if(typeComponent.getComment() != null && !typeComponent.getComment().isEmpty()) {
						stringBuilder.append(" /* ").append(typeComponent.getComment()).append(" */");
					}

					stringBuilder.append('\n');
				}

				if(!s.isPackingEnabled()) stringBuilder.append("} __attribute__((packed));\n\n");
				else stringBuilder.append("};\n\n");
			}
			else if(type instanceof Union) {
				Union union = (Union) type;
				stringBuilder.append("union ").append(union.getName()).append(" {\n");

				for(DataTypeComponent typeComponent : union.getDefinedComponents()) {
					String fieldName = typeComponent.getFieldName() != null ? typeComponent.getFieldName() : ("field_" + typeComponent.getOrdinal());
					stringBuilder.append("\t").append(renderTypeForDecl(typeComponent.getDataType(), fieldName)).append(";\n");
				}

				stringBuilder.append("};\n\n");
			}
			else if(type instanceof Enum) {
				Enum enumeration = (Enum) type;
				stringBuilder.append("enum ").append(enumeration.getName()).append(" {\n");
				String[] names = enumeration.getNames();
				for(int i = 0; i < names.length; i++) {
					stringBuilder.append("\t").append(names[i]).append(" = ").append(enumeration.getValue(names[i]));
					if(i < names.length - 1) stringBuilder.append(',');
					stringBuilder.append('\n');
				}
				stringBuilder.append("};\n\n");
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

			stringBuilder.append(body);
			if(!body.endsWith("\n")) stringBuilder.append('\n');
			stringBuilder.append('\n');
		}

		return stringBuilder.toString();
	}

	private String emitAsm() {
		StringBuilder stringBuilder = new StringBuilder();

		switch(memoryModel) {
			case FLAT: {
				stringBuilder.append("\t.386\n\t.model flat\n\n");
				break;
			}

			case LARGE: {
				stringBuilder.append("\t.8086\n\t.model large\n\n");
				break;
			}

			case SMALL:
			default: {
				stringBuilder.append("\t.8086\n\t.model small\n\n");
				break;
			}
		}

		TreeMap<String, List<Function>> bySegment = new TreeMap<>();
		for(Function function : asmFunctions) {
			String seg = segmentKey(function.getEntryPoint());
			bySegment.computeIfAbsent(seg, k -> new ArrayList<>()).add(function);
		}

		for(Map.Entry<String, List<Function>> entry : bySegment.entrySet()) {
			String segName = entry.getKey();
			List<Function> functions = entry.getValue();
			functions.sort(Comparator.comparing(Function::getEntryPoint));

			if(memoryModel == MemoryModel.FLAT) {
				stringBuilder.append("_TEXT SEGMENT PUBLIC 'CODE' USE32\n\n");
			}
			else {
				stringBuilder.append(segName).append(" SEGMENT BYTE PUBLIC 'CODE' USE16\n");
				stringBuilder.append("\tASSUME CS:").append(segName).append(", DS:DGROUP\n\n");
			}

			for(Function function : functions) {
				emitAsmFunction(stringBuilder, function);
				stringBuilder.append('\n');
			}

			if(memoryModel == MemoryModel.FLAT) stringBuilder.append("_TEXT ENDS\n\n");
			else stringBuilder.append(segName).append(" ENDS\n\n");
		}

		stringBuilder.append("\tEND\n");

		return stringBuilder.toString();
	}

	private void emitAsmFunction(StringBuilder stringBuilder, Function function) {
		String name = function.getName();
		String platePre = program.getListing().getComment(CommentType.PLATE, function.getEntryPoint());

		if(platePre != null && !platePre.isEmpty()) {
			for(String line : platePre.split("\n")) stringBuilder.append("; ").append(line).append('\n');
		}

		String procedureTag = memoryModel == MemoryModel.FLAT ? "NEAR" : "NEAR";
		stringBuilder.append(name).append(" PROC ").append(procedureTag).append('\n');

		AddressSetView body = function.getBody();
		Listing listing = program.getListing();
		InstructionIterator it = listing.getInstructions(body, true);
		while(it.hasNext()) {
			Instruction instruction = it.next();

			for(Symbol symbol : symbolTable.getSymbols(instruction.getAddress())) {
				if(symbol.getName().equals(name)) continue;

				String symbolName = symbol.getName();
				if(symbolName.startsWith("LAB_") || symbolName.startsWith("SUB_") || symbol.getSource() == SourceType.USER_DEFINED) {
					stringBuilder.append(symbolName).append(":\n");
					break;
				}
			}

			stringBuilder.append('\t').append(instruction.getMnemonicString().toUpperCase());

			int operands = instruction.getNumOperands();
			if(operands > 0) {
				stringBuilder.append(' ');
				for(int i = 0; i < operands; i++) {
					if(i > 0) stringBuilder.append(", ");
					stringBuilder.append(masmifyOperand(instruction.getDefaultOperandRepresentation(i)));
				}
			}

			String eol = listing.getComment(CommentType.EOL, instruction.getAddress());
			if(eol != null && !eol.isEmpty()) stringBuilder.append("\t; ").append(eol);

			stringBuilder.append('\n');
		}

		stringBuilder.append(name).append(" ENDP\n");
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
			arraySuffix.append('[').append(array.getNumElements()).append(']');
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
