// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;

import ghidra.app.script.GhidraScript;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;

import ghidra.util.UniversalID;

public class ExportAnnotations extends GhidraScript {
	private static final CommentType[] COMMENT_TYPES = {
			CommentType.PLATE,
			CommentType.PRE,
			CommentType.POST,
			CommentType.EOL,
			CommentType.REPEATABLE,
	};

	private static final String[] COMMENT_NAMES = {
			"plate",
			"pre",
			"post",
			"eol",
			"repeatable"
	};

	private static final String FID_PLATE_PREFIX = "Library Function -";

	private static final String[] LOADER_CATEGORY_PREFIXES = {
			"/DOS",
			"/PE",
			"/MZ",
			"/LE",
			"/LX",
			"/ELF",
			"/MachO",
			"/Windows"
	};

	@Override
	public void run() throws Exception {
		String[] arguments = getScriptArgs();
		if(arguments.length < 1) {
			printerr("usage: ExportAnnotations <out.json>");
			return;
		}

		Path outPath = Paths.get(arguments[0]);

		Program program = currentProgram;

		JsonObject root = new JsonObject();
		root.addProperty("schema_version", 1);
		root.addProperty("binary", program.getName());
		root.addProperty("language", program.getLanguageID().getIdAsString());
		root.addProperty("cspec", program.getCompilerSpec().getCompilerSpecID().getIdAsString());

		String sha = program.getExecutableSHA256();
		if(sha != null) root.addProperty("image_sha256", sha);

		root.add("data_types", exportDataTypes(program));
		root.add("functions", exportFunctions(program));
		root.add("symbols", exportSymbols(program));
		root.add("data", exportDefinedData(program));
		root.add("comments", exportComments(program));

		Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
		Files.writeString(outPath, gson.toJson(root) + "\n");
		println("wrote " + outPath);
	}

	private JsonArray exportDataTypes(Program program) {
		JsonArray array = new JsonArray();
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

		for(DataType type : userTypes) {
			JsonObject object = new JsonObject();
			object.addProperty("path", type.getPathName());

			if(type instanceof Structure) {
				object.addProperty("kind", "struct");

				Structure structure = (Structure) type;
				object.addProperty("size", structure.isZeroLength() ? 0 : structure.getLength());
				object.addProperty("packed", structure.isPackingEnabled());

				JsonArray fields = new JsonArray();
				for(DataTypeComponent component : structure.getDefinedComponents()) {
					JsonObject field = new JsonObject();

					field.addProperty("offset", component.getOffset());
					if(component.getFieldName() != null) field.addProperty("name", component.getFieldName());

					field.addProperty("type", component.getDataType().getPathName());
					if(component.getComment() != null) field.addProperty("comment", component.getComment());

					fields.add(field);
				}
				object.add("fields", fields);
			}
			else if(type instanceof Union) {
				object.addProperty("kind", "union");

				Union union = (Union) type;
				JsonArray fields = new JsonArray();
				for(DataTypeComponent component : union.getDefinedComponents()) {
					JsonObject field = new JsonObject();

					if(component.getFieldName() != null) field.addProperty("name", component.getFieldName());

					field.addProperty("type", component.getDataType().getPathName());
					if(component.getComment() != null) field.addProperty("comment", component.getComment());

					fields.add(field);
				}

				object.add("fields", fields);
			}
			else if(type instanceof Enum) {
				object.addProperty("kind", "enum");

				Enum enumeration = (Enum) type;
				object.addProperty("size", enumeration.getLength());

				JsonArray values = new JsonArray();
				for(String name : enumeration.getNames()) {
					JsonObject value = new JsonObject();
					value.addProperty("name", name);
					value.addProperty("value", enumeration.getValue(name));
					values.add(value);
				}

				object.add("values", values);
			}
			else if(type instanceof TypeDef) {
				object.addProperty("kind", "typedef");
				object.addProperty("base", ((TypeDef) type).getDataType().getPathName());
			}
			else continue;

			array.add(object);
		}

		return array;
	}

	private JsonArray exportFunctions(Program program) {
		JsonArray array = new JsonArray();
		FunctionManager functionManager = program.getFunctionManager();

		List<Function> functions = new ArrayList<>();
		for(Function field : functionManager.getFunctions(true)) functions.add(field);

		functions.sort(Comparator.comparing(Function::getEntryPoint));

		for(Function field : functions) {
			boolean nameUser = field.getSymbol().getSource() == SourceType.USER_DEFINED;
			boolean signatureUser = field.getSignatureSource() == SourceType.USER_DEFINED;
			if(!nameUser && !signatureUser) continue;

			JsonObject object = new JsonObject();
			object.addProperty("address", field.getEntryPoint().toString());

			if(nameUser) object.addProperty("name", field.getName());
			if(signatureUser) {
				object.addProperty("calling_convention", field.getCallingConventionName());
				object.addProperty("return_type", field.getReturnType().getPathName());

				JsonArray parameters = new JsonArray();
				for(Parameter parameter : field.getParameters()) {
					JsonObject parameterObject = new JsonObject();
					parameterObject.addProperty("name", parameter.getName());
					parameterObject.addProperty("type", parameter.getDataType().getPathName());
					parameters.add(parameterObject);
				}

				object.add("parameters", parameters);
			}

			array.add(object);
		}

		return array;
	}

	private JsonArray exportSymbols(Program program) {
		JsonArray array = new JsonArray();
		SymbolTable symbolTable = program.getSymbolTable();
		List<Symbol> symbols = new ArrayList<>();

		SymbolIterator it = symbolTable.getAllSymbols(false);
		while(it.hasNext()) {
			Symbol structure = it.next();

			if(structure.getSource() != SourceType.USER_DEFINED) continue;
			if(structure.getSymbolType() == SymbolType.FUNCTION) continue;
			if(structure.isExternal()) continue;
			if(structure.getAddress() == null || !structure.getAddress().isMemoryAddress()) continue;

			symbols.add(structure);
		}

		symbols.sort(Comparator.comparing(Symbol::getAddress));

		for(Symbol structure : symbols) {
			JsonObject object = new JsonObject();
			object.addProperty("address", structure.getAddress().toString());
			object.addProperty("name", structure.getName());

			String namespace = structure.getParentNamespace().getName(true);
			if(!"Global".equals(namespace)) object.addProperty("namespace", namespace);

			array.add(object);
		}

		return array;
	}

	private JsonArray exportDefinedData(Program program) {
		JsonArray array = new JsonArray();
		Listing listing = program.getListing();
		DataTypeManager dataTypeManager = program.getDataTypeManager();
		UniversalID localId = dataTypeManager.getUniversalID();
		SymbolTable symbolTable = program.getSymbolTable();

		for(Data data : listing.getDefinedData(true)) {
			DataType type = data.getDataType();
			SourceArchive archive = type.getSourceArchive();

			boolean userType = archive != null
					&& archive.getSourceArchiveID().equals(localId)
					&& !(type instanceof BuiltInDataType)
					&& !isLoaderCategory(type.getCategoryPath().getPath());

			Symbol primary = symbolTable.getPrimarySymbol(data.getMinAddress());

			boolean userLabel = primary != null && primary.getSource() == SourceType.USER_DEFINED;
			if(!userType && !userLabel) continue;

			JsonObject object = new JsonObject();
			object.addProperty("address", data.getMinAddress().toString());
			object.addProperty("type", type.getPathName());

			array.add(object);
		}

		return array;
	}

	private static boolean isLoaderCategory(String categoryPath) {
		for(String prefix : LOADER_CATEGORY_PREFIXES) {
			if(categoryPath.equals(prefix) || categoryPath.startsWith(prefix + "/")) return true;
		}

		return false;
	}

	private JsonArray exportComments(Program program) {
		JsonArray array = new JsonArray();
		Listing listing = program.getListing();

		for(int i = 0; i < COMMENT_TYPES.length; i++) {
			CommentType type = COMMENT_TYPES[i];
			String typeName = COMMENT_NAMES[i];
			AddressIterator it = listing.getCommentAddressIterator(
					type,
					program.getMemory(),
					true);

			while(it.hasNext()) {
				Address address = it.next();

				String comment = listing.getComment(type, address);
				if(comment == null) continue;

				if(type == CommentType.PLATE && comment.startsWith(FID_PLATE_PREFIX)) continue;

				JsonObject object = new JsonObject();
				object.addProperty("address", address.toString());
				object.addProperty("kind", typeName);
				object.addProperty("text", comment);

				array.add(object);
			}
		}

		return array;
	}
}
