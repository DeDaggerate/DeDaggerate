// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

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
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;

import ghidra.program.model.mem.Memory;

import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import ghidra.util.UniversalID;

import watcomdos.WatcomDecompileNormalizer;

public class ExportSources extends GhidraScript {

	private static final String MANUAL_ASM_TAG = "MANUAL_ASM";

	private static final String MODE_ALL = "all";
	private static final String MODE_C = "c";
	private static final String MODE_ASM = "asm";

	private static final String[] LOADER_CATEGORY_PREFIXES = {
			"/DOS", "/PE", "/MZ", "/LE", "/LX", "/ELF", "/MachO", "/Windows"
	};

	private Program program;
	private SymbolTable symbolTable;
	private DecompInterface decompiler;
	private Pattern includePattern;
	private String basename;
	private String projectPrefix;
	private MemoryModel memoryModel;

	private static String decorateWatcall(String functionName) { return functionName + "_"; }
	private static String decorateCVariable(String variableName) { return "_" + variableName; }

	private enum MemoryModel { SMALL, LARGE, FLAT }

	private final List<Function> cFunctions = new ArrayList<>();
	private final List<Function> asmFunctions = new ArrayList<>();
	private final List<Data> externData = new ArrayList<>();

	private final Map<String, String> inlineCandidateLiterals = new LinkedHashMap<>();
	private final Map<String, Data> inlineCandidateData = new LinkedHashMap<>();
	private final Map<String, LooseString> looseStrings = new LinkedHashMap<>();
	private final Set<String> actuallyInlined = new HashSet<>();
	private final TreeMap<Integer, DgroupSymbol> dgroupSymbols = new TreeMap<>();
	private final Map<String, DgroupSymbol> dgroupSymbolsByName = new LinkedHashMap<>();

	private final Set<Integer> codeSegments = new HashSet<>();

	private static final class LooseString {
		final Address address;
		final int length;
		LooseString(Address address, int length) {
			this.address = address;
			this.length = length;
		}
	}

	private static final class DgroupSymbol {
		final String name;
		final int offset;
		final int size;
		DgroupSymbol(String name, int offset, int size) {
			this.name = name;
			this.offset = offset;
			this.size = size;
		}
	}

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
		boolean emitAsm = MODE_ALL.equals(mode) || MODE_ASM.equals(mode);

		Files.createDirectories(output);

		program = currentProgram;
		symbolTable = program.getSymbolTable();
		memoryModel = detectMemoryModel(program.getCompilerSpec().getCompilerSpecID().getIdAsString());

		decompiler = new DecompInterface();
		try {
			if(!decompiler.openProgram(program)) {
				printerr("decompiler failed to open program: " + decompiler.getLastMessage());
				return;
			}

			collect();

			Map<String, String> cFiles = emitCAndHeader ? emitAllC() : null;
			Map<String, String> asmFiles = emitAsm ? emitAllAsm() : null;
			String header = emitCAndHeader ? emitHeader() : null;

			if(emitCAndHeader) {
				atomicWrite(output.resolve(basename + ".h"), header);
				for(Map.Entry<String, String> entry : cFiles.entrySet()) {
					atomicWrite(output.resolve(entry.getKey()), entry.getValue());
				}
			}
			if(emitAsm) {
				for(Map.Entry<String, String> entry : asmFiles.entrySet()) {
					atomicWrite(output.resolve(entry.getKey()), entry.getValue());
				}
			}

			if(emitCAndHeader && emitAsm) {
				atomicWrite(output.resolve("sources.mk"), emitSourcesMk(cFiles, asmFiles));
			}

			StringBuilder summary = new StringBuilder("wrote ");
			if(emitCAndHeader) {
				summary.append(cFunctions.size()).append(" c funcs (")
						.append(cFiles.size()).append(" files), ")
						.append(externData.size()).append(" externs, ")
						.append(actuallyInlined.size()).append(" inlined strings");
			}

			if(emitCAndHeader && emitAsm) summary.append(", ");
			if(emitAsm) summary.append(asmFunctions.size()).append(" asm funcs (")
					.append(asmFiles.size()).append(" files)");

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

			Address entry = function.getEntryPoint();
			if(entry instanceof SegmentedAddress) {
				codeSegments.add(((SegmentedAddress)entry).getSegment());
			}
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

		collectLooseStringSymbols();
		buildDgroupSymbolMap();
	}

	private void buildDgroupSymbolMap() {
		for(Data data : externData) {
			Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());
			String name = primary != null ? primary.getName() : null;
			if(name == null || !name.startsWith(projectPrefix)) continue;
			if(isInCodeSegment(data.getMinAddress())) continue;
			int offset = segmentOffset(data.getMinAddress());
			addDgroupSymbol(new DgroupSymbol(name, offset, data.getLength()));
		}
		for(Map.Entry<String, Data> entry : inlineCandidateData.entrySet()) {
			String name = entry.getKey();
			if(!name.startsWith(projectPrefix)) continue;
			Data data = entry.getValue();
			if(isInCodeSegment(data.getMinAddress())) continue;
			int offset = segmentOffset(data.getMinAddress());
			addDgroupSymbol(new DgroupSymbol(name, offset, data.getLength()));
		}

		SymbolIterator it = symbolTable.getAllSymbols(false);
		while(it.hasNext()) {
			Symbol symbol = it.next();
			if(symbol.getSymbolType() == SymbolType.FUNCTION) continue;
			if(symbol.isExternal()) continue;

			Address address = symbol.getAddress();
			if(address == null || !address.isMemoryAddress()) continue;

			SourceType source = symbol.getSource();
			if(source != SourceType.USER_DEFINED && source != SourceType.IMPORTED) continue;

			String name = symbol.getName();
			if(!name.startsWith(projectPrefix)) continue;
			if(isInCodeSegment(address)) continue;

			int offset = segmentOffset(address);
			if(dgroupSymbols.containsKey(offset)) continue;
			addDgroupSymbol(new DgroupSymbol(name, offset, 1));
		}
	}

	private void addDgroupSymbol(DgroupSymbol symbol) {
		dgroupSymbols.put(symbol.offset, symbol);
		dgroupSymbolsByName.put(symbol.name, symbol);
	}

	private static int segmentOffset(Address address) {
		if(address instanceof SegmentedAddress) {
			return ((SegmentedAddress)address).getSegmentOffset();
		}
		return (int)(address.getOffset() & 0xffff);
	}

	private boolean isInCodeSegment(Address address) {
		if(!(address instanceof SegmentedAddress)) return false;
		return codeSegments.contains(((SegmentedAddress)address).getSegment());
	}

	private String resolveDgroupOffset(int offset) {
		DgroupSymbol exact = dgroupSymbols.get(offset);
		if(exact != null) return exact.name;

		Map.Entry<Integer, DgroupSymbol> ceiling = dgroupSymbols.ceilingEntry(offset);
		if(ceiling != null) {
			int distance = ceiling.getKey() - offset;
			if(distance > 0 && distance <= 32) {
				return "(" + ceiling.getValue().name + " - " + distance + ")";
			}
		}

		return null;
	}

	private void collectLooseStringSymbols() {
		Set<Address> covered = new HashSet<>();
		for(Data data : externData) covered.add(data.getMinAddress());
		for(Data data : inlineCandidateData.values()) covered.add(data.getMinAddress());

		SymbolIterator it = symbolTable.getAllSymbols(false);
		while(it.hasNext()) {
			Symbol symbol = it.next();
			if(symbol.getSymbolType() == SymbolType.FUNCTION) continue;
			if(symbol.isExternal()) continue;

			Address address = symbol.getAddress();
			if(address == null || !address.isMemoryAddress()) continue;

			String name = symbol.getName();
			if(!name.startsWith(projectPrefix)) continue;

			SourceType source = symbol.getSource();
			if(source != SourceType.USER_DEFINED && source != SourceType.IMPORTED) continue;

			if(covered.contains(address)) continue;
			if(inlineCandidateLiterals.containsKey(name)) continue;

			String literal = readLooseStringLiteral(address, 256);
			if(literal == null) continue;

			int length = measureLooseStringLength(address, 256);
			if(length <= 0) continue;

			inlineCandidateLiterals.put(name, literal);
			looseStrings.put(name, new LooseString(address, length));
		}
	}

	private String readLooseStringLiteral(Address address, int maxLength) {
		Memory memory = program.getMemory();
		StringBuilder stringBuilder = new StringBuilder("\"");
		boolean sawPrintable = false;
		boolean sawTerminator = false;

		try {
			for(int i = 0; i < maxLength; i++) {
				int byteValue = memory.getByte(address.add(i)) & 0xff;
				if(byteValue == 0) {
					sawTerminator = true;
					break;
				}

				boolean printable = (byteValue >= 0x20 && byteValue < 0x7f)
						|| byteValue == '\n' || byteValue == '\r' || byteValue == '\t';
				if(!printable) return null;
				sawPrintable = true;

				switch(byteValue) {
					case '\\': stringBuilder.append("\\\\"); break;
					case '"':  stringBuilder.append("\\\""); break;
					case '\n': stringBuilder.append("\\n");  break;
					case '\r': stringBuilder.append("\\r");  break;
					case '\t': stringBuilder.append("\\t");  break;
					default:   stringBuilder.append((char) byteValue);
				}
			}
		}
		catch(Exception ignored) {
			return null;
		}

		if(!sawPrintable || !sawTerminator) return null;

		stringBuilder.append("\"");
		return stringBuilder.toString();
	}

	private int measureLooseStringLength(Address address, int maxLength) {
		Memory memory = program.getMemory();
		try {
			for(int i = 0; i < maxLength; i++) {
				if((memory.getByte(address.add(i)) & 0xff) == 0) return i + 1;
			}
		}
		catch(Exception ignored) { }
		return 0;
	}

	private String emitSourcesMk(Map<String, String> cFiles, Map<String, String> asmFiles) {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("# Generated by ExportSources -- do not edit.\n\n");

		appendSourcesMkList(stringBuilder, "CSRC", cFiles, null);
		appendSourcesMkList(stringBuilder, "ASMSRC", asmFiles, null);
		appendSourcesMkList(stringBuilder, "COBJ", cFiles, ".obj");
		appendSourcesMkList(stringBuilder, "AOBJ", asmFiles, ".obj");
		stringBuilder.append("OBJ = $(COBJ) $(AOBJ)\n");

		return stringBuilder.toString();
	}

	private static void appendSourcesMkList(StringBuilder stringBuilder, String macroName, Map<String, String> files, String replaceExtension) {
		stringBuilder.append(macroName).append(" =");
		if(files == null || files.isEmpty()) {
			stringBuilder.append('\n');
			return;
		}

		List<String> names = new ArrayList<>(files.keySet());
		names.sort(Comparator.naturalOrder());

		Iterator<String> iterator = names.iterator();
		while(iterator.hasNext()) {
			String name = iterator.next();
			if(replaceExtension != null) {
				int dot = name.lastIndexOf('.');
				if(dot >= 0) name = name.substring(0, dot) + replaceExtension;
			}
			stringBuilder.append(' ').append(name);
			if(iterator.hasNext()) stringBuilder.append(" &");
			stringBuilder.append('\n');
			if(iterator.hasNext()) stringBuilder.append("\t");
		}
	}

	private String emitHeader() {
		StringBuilder stringBuilder = new StringBuilder();
		String guard = basename.toUpperCase().replaceAll("[^A-Z0-9]", "_") + "_H";

		stringBuilder.append("#ifndef ").append(guard).append('\n');
		stringBuilder.append("#define ").append(guard).append("\n\n");

		stringBuilder.append("#include <ctype.h>\n\n");
		stringBuilder.append("#include <stddef.h>\n");
		stringBuilder.append("#include <stdint.h>\n");
		stringBuilder.append("#include <stdio.h>\n");
		stringBuilder.append("#include <stdbool.h>\n");
		stringBuilder.append("#include <stdlib.h>\n");
		stringBuilder.append("#include <string.h>\n\n");

		stringBuilder.append("#include <direct.h>\n");
		stringBuilder.append("#include <dos.h>\n");
		stringBuilder.append("#include <io.h>\n");
		stringBuilder.append("#include <process.h>\n");
		stringBuilder.append("#include <conio.h>\n\n");

		stringBuilder.append("typedef struct find_t find_t;\n\n");

		stringBuilder.append("typedef unsigned char byte;\n");
		stringBuilder.append("typedef unsigned short word, ushort, uint;\n");
		stringBuilder.append("typedef unsigned long dword, ulong;\n");
		stringBuilder.append("typedef void code;\n\n");

		stringBuilder.append("#define " + projectPrefix + "main main\n");
		stringBuilder.append("#define __stack_probe(n)\n\n");

		appendUserTypes(stringBuilder);

		if(!externData.isEmpty()) {
			for(Data data : externData) {
				Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());
				String name = primary != null ? primary.getName() : ("DAT_" + data.getMinAddress());
				if(!name.startsWith(projectPrefix)) continue;
				if(isInCodeSegment(data.getMinAddress())) continue;
				stringBuilder.append("extern ").append(renderExternDecl(data, name)).append(";\n");
			}
		}

		for(Map.Entry<String, Data> entry : inlineCandidateData.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;
			if(!name.startsWith(projectPrefix)) continue;

			Data data = entry.getValue();
			if(isInCodeSegment(data.getMinAddress())) continue;
			stringBuilder.append("extern ").append(renderExternDecl(data, name)).append(";\n");
		}

		for(Map.Entry<String, LooseString> entry : looseStrings.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;
			if(!name.startsWith(projectPrefix)) continue;

			LooseString loose = entry.getValue();
			if(isInCodeSegment(loose.address)) continue;

			String dimension = loose.length > 0 ? "[" + loose.length + "]" : "[]";
			stringBuilder.append("extern char ").append(name).append(dimension).append(";\n");
		}

		if(!cFunctions.isEmpty()) {
			stringBuilder.append('\n');
			for(Function function : cFunctions) {
				String name = function.getName();
				if(!name.startsWith(projectPrefix)) continue;
				stringBuilder.append(renderFunctionDecl(function)).append(";\n");
			}
		}

		if(!asmFunctions.isEmpty()) {
			stringBuilder.append('\n');
			for(Function function : asmFunctions) {
				String name = function.getName();
				if(!name.startsWith(projectPrefix)) continue;
				stringBuilder.append("extern ").append(renderFunctionDecl(function)).append(";\n");
			}
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

		if(userTypes.isEmpty()) return;
		userTypes.sort(Comparator.comparing(DataType::getPathName));

		for(DataType type : userTypes) {
			if(type instanceof TypeDef) {
				TypeDef typedef = (TypeDef) type;
				stringBuilder.append("typedef ").append(renderTypeForDecl(typedef.getDataType(), type.getName())).append(";\n\n");
			}
			else if(type instanceof Structure) {
				Structure s = (Structure) type;
				stringBuilder.append("typedef struct ").append(s.getName()).append(" {\n");
				for(DataTypeComponent c : s.getDefinedComponents()) {
					String fieldName = c.getFieldName() != null ? c.getFieldName() : ("field_" + c.getOffset());
					stringBuilder.append("\t").append(renderTypeForDecl(c.getDataType(), fieldName)).append(";");
					if(c.getComment() != null && !c.getComment().isEmpty()) {
						stringBuilder.append(" /* ").append(c.getComment()).append(" */");
					}
					stringBuilder.append('\n');
				}
				stringBuilder.append("} ").append(s.getName()).append(";\n\n");
			}
			else if(type instanceof Union) {
				Union union = (Union) type;
				stringBuilder.append("typedef union ").append(union.getName()).append(" {\n");
				for(DataTypeComponent c : union.getDefinedComponents()) {
					String fieldName = c.getFieldName() != null ? c.getFieldName() : ("field_" + c.getOrdinal());
					stringBuilder.append("\t").append(renderTypeForDecl(c.getDataType(), fieldName)).append(";\n");
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

	private Map<String, String> emitAllC() {
		Map<String, String> files = new LinkedHashMap<>();

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

			StringBuilder fileBuilder = new StringBuilder();
			fileBuilder.append("#include \"").append(basename).append(".h\"\n\n");

			String platePre = program.getListing().getComment(CommentType.PLATE, function.getEntryPoint());
			if(platePre != null && !platePre.isEmpty()) {
				fileBuilder.append("/*\n");
				for(String line : platePre.split("\n")) fileBuilder.append(" * ").append(line).append('\n');
				fileBuilder.append(" */\n");
			}

			if(body == null) {
				fileBuilder.append("/* decompile failed for ").append(function.getName()).append(" */\n");
			}
			else {
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

				fileBuilder.append(body);
				if(!body.endsWith("\n")) fileBuilder.append('\n');
			}

			files.put(function.getName() + ".c", fileBuilder.toString());
		}

		StringBuilder globalsBuilder = new StringBuilder();
		globalsBuilder.append("#include \"").append(basename).append(".h\"\n");
		appendGlobalDefinitions(globalsBuilder);
		files.put(basename + ".c", globalsBuilder.toString());

		return files;
	}

	private void appendGlobalDefinitions(StringBuilder stringBuilder) {
		boolean anyEmitted = false;
		StringBuilder section = new StringBuilder();

		for(Data data : externData) {
			Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());

			String name = primary != null ? primary.getName() : ("DAT_" + data.getMinAddress());
			if(!name.startsWith(projectPrefix)) continue;
			if(isInCodeSegment(data.getMinAddress())) continue;

			section.append(renderDefinition(data, name)).append(";\n");
			anyEmitted = true;
		}

		for(Map.Entry<String, Data> entry : inlineCandidateData.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;
			if(!name.startsWith(projectPrefix)) continue;

			Data data = entry.getValue();
			if(isInCodeSegment(data.getMinAddress())) continue;

			String literal = inlineCandidateLiterals.get(name);
			int length = data.getLength();
			String dimension = length > 0 ? "[" + length + "]" : "[]";

			section.append("char ").append(name).append(dimension);

			if(literal != null) section.append(" = ").append(literal);

			section.append(";\n");
			anyEmitted = true;
		}

		for(Map.Entry<String, LooseString> entry : looseStrings.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;
			if(!name.startsWith(projectPrefix)) continue;

			LooseString loose = entry.getValue();
			if(isInCodeSegment(loose.address)) continue;

			String literal = inlineCandidateLiterals.get(name);
			String dimension = loose.length > 0 ? "[" + loose.length + "]" : "[]";

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

	private static final Pattern _PTRARITH_HEX = Pattern.compile(
			"\\+ 0x([0-9a-fA-F]+)(?=\\))");

	private static final Pattern _PTR_PAST_SCALAR = Pattern.compile(
			"(?:\\(\\(([^()]+)\\)|\\()&(\\w+)\\)\\[([^\\]]+)\\]");

	private static final Set<String> _ONE_BYTE_CAST_TYPES = new HashSet<>(java.util.Arrays.asList(
			"undefined", "undefined1", "byte", "char", "unsigned char"));

	private String normalizeDecompiledBody(String body) {
		body = WatcomDecompileNormalizer.stripCspecKeywords(body);
		body = WatcomDecompileNormalizer.expandPartialFields(body);
		body = WatcomDecompileNormalizer.collapseLongWriteSplit(body);
		body = WatcomDecompileNormalizer.collapseLongReadConcat22(body);
		body = resolveAddressConstants(body);
		body = resolvePtrPastScalar(body);
		body = collapseDerefBufferAdd(body);
		body = WatcomDecompileNormalizer.rewriteGreedyHexEscapes(body);
		body = WatcomDecompileNormalizer.stripUnusedUnaff(body);
		return body;
	}

	private String resolveAddressConstants(String body) {
		Matcher matcher = _PTRARITH_HEX.matcher(body);
		StringBuffer stringBuffer = new StringBuffer();
		while(matcher.find()) {
			int value;
			try { value = Integer.parseInt(matcher.group(1), 16); }
			catch(NumberFormatException e) {
				matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(matcher.group(0)));
				continue;
			}

			String resolved = resolveDgroupOffset(value);
			if(resolved != null) {
				matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement("+ " + resolved));
			}
			else {
				matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(matcher.group(0)));
			}
		}
		matcher.appendTail(stringBuffer);
		return stringBuffer.toString();
	}

	private String collapseDerefBufferAdd(String body) {
		StringBuilder out = new StringBuilder();
		int cursor = 0;
		while(cursor < body.length()) {
			int castStart = body.indexOf("*(", cursor);
			if(castStart < 0) {
				out.append(body, cursor, body.length());
				return out.toString();
			}

			int rewrittenEnd = tryRewriteDerefBufferAdd(body, castStart, out, cursor);
			if(rewrittenEnd > 0) {
				cursor = rewrittenEnd;
			}
			else {
				out.append(body, cursor, castStart + 1);
				cursor = castStart + 1;
			}
		}
		return out.toString();
	}

	private int tryRewriteDerefBufferAdd(String body, int castStart, StringBuilder out, int cursor) {
		int castClose = body.indexOf(')', castStart + 2);
		if(castClose < 0) return -1;

		String castContent = body.substring(castStart + 2, castClose);
		String trimmedCastContent = castContent.trim();
		if(!trimmedCastContent.endsWith("*")) return -1;
		String castType = trimmedCastContent.substring(0, trimmedCastContent.length() - 1).trim();
		if(!_ONE_BYTE_CAST_TYPES.contains(castType)) return -1;

		if(castClose + 1 >= body.length() || body.charAt(castClose + 1) != '(') return -1;
		int innerOpen = castClose + 1;
		int innerClose = findMatchingParen(body, innerOpen);
		if(innerClose < 0) return -1;

		String inner = body.substring(innerOpen + 1, innerClose);
		String[] sides = splitTopLevelPlus(inner);
		if(sides == null) return -1;

		BufferRef bufferRef = parseBufferRef(sides[0]);
		String indexExpr;
		if(bufferRef != null) {
			indexExpr = sides[1].trim();
		}
		else {
			bufferRef = parseBufferRef(sides[1]);
			if(bufferRef == null) return -1;
			indexExpr = sides[0].trim();
		}

		indexExpr = stripRedundantWrappingParens(indexExpr);

		String tail;
		if(bufferRef.adjustment > 0) tail = "[" + indexExpr + " - " + bufferRef.adjustment + "]";
		else tail = "[" + indexExpr + "]";

		out.append(body, cursor, castStart);
		out.append(bufferRef.name);
		out.append(tail);
		return innerClose + 1;
	}

	private static int findMatchingParen(String s, int openIndex) {
		int depth = 1;
		for(int i = openIndex + 1; i < s.length(); i++) {
			char c = s.charAt(i);
			if(c == '(') depth++;
			else if(c == ')') {
				depth--;
				if(depth == 0) return i;
			}
		}
		return -1;
	}

	private static String[] splitTopLevelPlus(String s) {
		int depth = 0;
		for(int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if(c == '(') depth++;
			else if(c == ')') depth--;
			else if(c == '+' && depth == 0
					&& i > 0 && i + 1 < s.length()
					&& s.charAt(i - 1) == ' ' && s.charAt(i + 1) == ' ') {
				return new String[] { s.substring(0, i - 1), s.substring(i + 2) };
			}
		}
		return null;
	}

	private static String stripRedundantWrappingParens(String s) {
		String trimmed = s.trim();
		if(!trimmed.startsWith("(") || !trimmed.endsWith(")")) return trimmed;
		int depth = 0;
		for(int i = 0; i < trimmed.length(); i++) {
			char c = trimmed.charAt(i);
			if(c == '(') depth++;
			else if(c == ')') {
				depth--;
				if(depth == 0 && i < trimmed.length() - 1) return trimmed;
			}
		}
		return trimmed.substring(1, trimmed.length() - 1).trim();
	}

	private static final Pattern _IDENTIFIER = Pattern.compile("\\w+");

	private static final class BufferRef {
		final String name;
		final int adjustment;
		BufferRef(String name, int adjustment) { this.name = name; this.adjustment = adjustment; }
	}

	private BufferRef parseBufferRef(String s) {
		String trimmed = s.trim();
		if(trimmed.startsWith("(") && trimmed.endsWith(")")) {
			String inside = trimmed.substring(1, trimmed.length() - 1).trim();
			int minusIndex = inside.indexOf(" - ");
			if(minusIndex > 0) {
				String name = inside.substring(0, minusIndex).trim();
				String numString = inside.substring(minusIndex + 3).trim();
				if(_IDENTIFIER.matcher(name).matches()) {
					try {
						int adjustment = Integer.parseInt(numString);
						DgroupSymbol sym = dgroupSymbolsByName.get(name);
						if(sym != null && sym.size > 4) return new BufferRef(name, adjustment);
					}
					catch(NumberFormatException ignored) {}
				}
			}
		}
		else if(_IDENTIFIER.matcher(trimmed).matches()) {
			DgroupSymbol sym = dgroupSymbolsByName.get(trimmed);
			if(sym != null && sym.size > 4) return new BufferRef(trimmed, 0);
		}
		return null;
	}

	private String resolvePtrPastScalar(String body) {
		Matcher matcher = _PTR_PAST_SCALAR.matcher(body);
		StringBuffer stringBuffer = new StringBuffer();
		while(matcher.find()) {
			String castInside = matcher.group(1);
			String symbolName = matcher.group(2);
			String indexExpr = matcher.group(3);

			DgroupSymbol sym = dgroupSymbolsByName.get(symbolName);
			if(sym == null || sym.size <= 0 || sym.size > 4) {
				matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(matcher.group(0)));
				continue;
			}

			DgroupSymbol next = dgroupSymbols.get(sym.offset + sym.size);
			if(next == null || next.size <= 1) {
				matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(matcher.group(0)));
				continue;
			}

			if(castInside != null) {
				String castType = castInside.trim().replaceAll("\\s*\\*$", "").trim();
				if(!_ONE_BYTE_CAST_TYPES.contains(castType)) {
					matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(matcher.group(0)));
					continue;
				}
			}

			String replacement = next.name + "[" + indexExpr + " - " + sym.size + "]";
			matcher.appendReplacement(stringBuffer, Matcher.quoteReplacement(replacement));
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

	private String currentAsmFunctionDecorated;

	private final Map<String, String> asmExterns = new LinkedHashMap<>();

	private Map<String, String> emitAllAsm() {
		Map<String, String> files = new LinkedHashMap<>();

		for(Function function : asmFunctions) {
			currentAsmFunctionDecorated = decorateWatcall(function.getName());
			asmExterns.clear();

			StringBuilder bodyBuffer = new StringBuilder();
			String segName = segmentKey(function.getEntryPoint());

			if(memoryModel == MemoryModel.FLAT) {
				bodyBuffer.append("_TEXT SEGMENT PUBLIC 'CODE' USE32\n\n");
			}
			else {
				bodyBuffer.append(segName).append(" SEGMENT BYTE PUBLIC 'CODE' USE16\n");
				bodyBuffer.append("\tASSUME CS:").append(segName).append(", DS:").append(segName).append("\n\n");
			}

			bodyBuffer.append("PUBLIC ").append(decorateWatcall(function.getName())).append("\n\n");

			emitAsmFunction(bodyBuffer, function);
			bodyBuffer.append('\n');

			if(memoryModel == MemoryModel.FLAT) bodyBuffer.append("_TEXT ENDS\n\n");
			else bodyBuffer.append(segName).append(" ENDS\n\n");

			StringBuilder fileBuilder = new StringBuilder();
			switch(memoryModel) {
				case FLAT: {
					fileBuilder.append("\t.386p\n\t.model flat\n\n");
					break;
				}

				case LARGE: {
					fileBuilder.append("\t.386\n\t.model large\n\n");
					break;
				}

				case SMALL:
				default: {
					fileBuilder.append("\t.386\n\t.model small\n\n");
					break;
				}
			}

			if(!asmExterns.isEmpty()) {
				for(Map.Entry<String, String> e : asmExterns.entrySet()) {
					fileBuilder.append("EXTRN ").append(e.getKey()).append(":").append(e.getValue()).append('\n');
				}

				fileBuilder.append('\n');
			}

			fileBuilder.append(bodyBuffer);
			fileBuilder.append("\tEND\n");

			files.put(function.getName() + ".asm", fileBuilder.toString());
		}

		String projectAsm = emitProjectAsm();
		if(projectAsm != null) files.put(basename + "_data.asm", projectAsm);

		return files;
	}

	private static final class AsmDatum {
		final String name;
		final Address address;
		final int length;
		final String literal;
		AsmDatum(String name, Address address, int length, String literal) {
			this.name = name;
			this.address = address;
			this.length = length;
			this.literal = literal;
		}
	}

	private String emitProjectAsm() {
		Map<String, List<AsmDatum>> bySegment = new LinkedHashMap<>();

		for(Data data : externData) {
			Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());
			String name = primary != null ? primary.getName() : null;
			if(name == null || !name.startsWith(projectPrefix)) continue;
			Address address = data.getMinAddress();
			if(!isInCodeSegment(address)) continue;
			addAsmDatum(bySegment, new AsmDatum(name, address, data.getLength(), null));
		}

		for(Map.Entry<String, Data> entry : inlineCandidateData.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;
			if(!name.startsWith(projectPrefix)) continue;
			Data data = entry.getValue();
			Address address = data.getMinAddress();
			if(!isInCodeSegment(address)) continue;
			addAsmDatum(bySegment, new AsmDatum(name, address, data.getLength(), inlineCandidateLiterals.get(name)));
		}

		for(Map.Entry<String, LooseString> entry : looseStrings.entrySet()) {
			String name = entry.getKey();
			if(actuallyInlined.contains(name)) continue;
			if(!name.startsWith(projectPrefix)) continue;
			LooseString loose = entry.getValue();
			if(!isInCodeSegment(loose.address)) continue;
			addAsmDatum(bySegment, new AsmDatum(name, loose.address, loose.length, inlineCandidateLiterals.get(name)));
		}

		if(bySegment.isEmpty()) return null;

		for(List<AsmDatum> items : bySegment.values()) items.sort(Comparator.comparing(d -> d.address));

		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("\t.386\n\t.model small\n\n");

		for(Map.Entry<String, List<AsmDatum>> entry : bySegment.entrySet()) {
			String segName = entry.getKey();
			stringBuilder.append(segName).append(" SEGMENT BYTE PUBLIC 'CODE' USE16\n\n");
			for(AsmDatum datum : entry.getValue()) appendAsmDatum(stringBuilder, datum);
			stringBuilder.append('\n').append(segName).append(" ENDS\n\n");
		}

		stringBuilder.append("\tEND\n");
		return stringBuilder.toString();
	}

	private void addAsmDatum(Map<String, List<AsmDatum>> bySegment, AsmDatum datum) {
		bySegment.computeIfAbsent(segmentKey(datum.address), k -> new ArrayList<>()).add(datum);
	}

	private void appendAsmDatum(StringBuilder stringBuilder, AsmDatum datum) {
		String decorated = decorateCVariable(datum.name);
		stringBuilder.append("PUBLIC ").append(decorated).append('\n');
		stringBuilder.append(decorated).append('\t').append(renderAsmDataDirective(datum)).append('\n');
	}

	private String renderAsmDataDirective(AsmDatum datum) {
		if(datum.literal != null) return "DB " + datum.literal + ",0";

		byte[] bytes = new byte[datum.length];
		try {
			program.getMemory().getBytes(datum.address, bytes);
		}
		catch(Exception ignored) {
			return zeroInitDirective(datum.length);
		}

		boolean allZero = true;
		for(byte b : bytes) {
			if(b != 0) {
				allZero = false;
				break;
			}
		}
		if(allZero) return zeroInitDirective(datum.length);

		if(datum.length == 2) {
			int value = (bytes[0] & 0xff) | ((bytes[1] & 0xff) << 8);
			return String.format("DW 0%04xh", value);
		}
		if(datum.length == 4) {
			long value = (bytes[0] & 0xffL) | ((bytes[1] & 0xffL) << 8) | ((bytes[2] & 0xffL) << 16) | ((bytes[3] & 0xffL) << 24);
			return String.format("DD 0%08xh", value);
		}

		StringBuilder bytesBuilder = new StringBuilder();
		int perLine = 16;
		for(int i = 0; i < bytes.length; i++) {
			if(i % perLine == 0) {
				if(i > 0) bytesBuilder.append('\n');
				bytesBuilder.append("DB ");
			}
			else {
				bytesBuilder.append(',');
			}
			bytesBuilder.append(String.format("0%02xh", bytes[i] & 0xff));
		}
		return bytesBuilder.toString();
	}

	private static String zeroInitDirective(int length) {
		if(length == 1) return "DB 0";
		if(length == 2) return "DW 0";
		if(length == 4) return "DD 0";
		return "DB " + length + " DUP (0)";
	}

	private void emitAsmFunction(StringBuilder stringBuilder, Function function) {
		String decoratedName = decorateWatcall(function.getName());
		String platePre = program.getListing().getComment(CommentType.PLATE, function.getEntryPoint());

		if(platePre != null && !platePre.isEmpty()) {
			for(String line : platePre.split("\n")) stringBuilder.append("; ").append(line).append('\n');
		}

		stringBuilder.append(decoratedName).append(" PROC NEAR\n");

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
						stringBuilder.append(renderOperand(instruction, i));
					}
				}
			}

			String eol = listing.getComment(CommentType.EOL, instruction.getAddress());
			if(eol != null && !eol.isEmpty()) stringBuilder.append("\t; ").append(eol);

			stringBuilder.append('\n');
		}

		stringBuilder.append(decoratedName).append(" ENDP\n");
	}

	private String renderOperand(Instruction instruction, int operandIndex) {
		String text = instruction.getDefaultOperandRepresentation(operandIndex);

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
					if(!decorated.equals(currentAsmFunctionDecorated)) {
						asmExterns.putIfAbsent(decorated, "NEAR");
					}

					return decorated;
				}

				if(symbol.getSource() == SourceType.DEFAULT && !targetIsInEmittedAsm(target)) {
					return formatFarAddress(target);
				}

				return symbolName;
			}

			String renderedName;
			if(symbol.getSymbolType() == SymbolType.FUNCTION) {
				renderedName = decorateWatcall(symbolName);
			}
			else if(symbolName.startsWith(projectPrefix)) {
				renderedName = decorateCVariable(symbolName);
			}
			else {
				renderedName = symbolName;
			}

			boolean isMemoryOperand = text.contains("[");
			if(referenceType.isData()) {
				boolean isDefinedHere = symbol.getSymbolType() == SymbolType.FUNCTION && renderedName.equals(currentAsmFunctionDecorated);
				if(!isDefinedHere) {
					String externType = symbol.getSymbolType() == SymbolType.FUNCTION
							? "NEAR"
							: inferDataExternType(symbol);
					asmExterns.putIfAbsent(renderedName, externType);
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
			"INSB", "INSW", "INSD",
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
						else stringBuilder.append(String.format("\\%03o", byteValue));
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
			char c = glob.charAt(i);
			if(c == '*') stringBuilder.append(".*");
			else if(c == '?') stringBuilder.append('.');
			else stringBuilder.append(Pattern.quote(String.valueOf(c)));
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

	private String renderFunctionDecl(Function function) {
		StringBuilder out = new StringBuilder();
		out.append(renderTypeForDecl(function.getReturnType(), "").trim());
		out.append(' ').append(function.getName()).append('(');

		Parameter[] params = function.getParameters();
		if(params.length == 0) out.append("void");
		else {
			for(int i = 0; i < params.length; i++) {
				if(i > 0) out.append(", ");
				String paramName = params[i].getName();
				if(paramName == null || paramName.isEmpty()) paramName = "param_" + (i + 1);
				out.append(renderTypeForDecl(params[i].getDataType(), paramName));
			}
		}

		out.append(')');
		return out.toString();
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

		if(name.equals("bool")) return "_Bool";
		if(PRIMITIVE_TYPE_PASSTHROUGH.contains(name)) return name;

		if(type instanceof Structure) return "struct " + name;
		if(type instanceof Union) return "union " + name;
		if(type instanceof Enum) return "enum " + name;

		if(type instanceof BuiltInDataType) {
			boolean unsigned;
			if(UNSIGNED_BUILTIN_NAMES.contains(name)) unsigned = true;
			else if(SIGNED_BUILTIN_NAMES.contains(name)) unsigned = false;
			else unsigned = name.startsWith("u");

			switch(type.getLength()) {
				case 1: return unsigned ? "unsigned char" : "signed char";
				case 2: return unsigned ? "unsigned int" : "int";
				case 4: return unsigned ? "unsigned long" : "long";
				case 8: return unsigned ? "uint64_t" : "int64_t";
			}
		}

		return name;
	}

	private static final Set<String> PRIMITIVE_TYPE_PASSTHROUGH = new HashSet<>(java.util.Arrays.asList(
			"char", "void", "float", "double"));

	private static final Set<String> UNSIGNED_BUILTIN_NAMES = new HashSet<>(java.util.Arrays.asList(
			"byte", "word", "dword", "qword", "uchar", "ushort", "uint", "ulong", "ulonglong",
			"undefined", "undefined1", "undefined2", "undefined4", "undefined6", "undefined8"));

	private static final Set<String> SIGNED_BUILTIN_NAMES = new HashSet<>(java.util.Arrays.asList(
			"sbyte", "sword", "sdword", "sqword", "schar", "short", "int", "long", "longlong"));

	private void atomicWrite(Path target, String content) throws IOException {
		Path tmp = target.resolveSibling(target.getFileName().toString() + ".tmp");
		Files.writeString(tmp, content, StandardCharsets.UTF_8);
		Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
	}
}
