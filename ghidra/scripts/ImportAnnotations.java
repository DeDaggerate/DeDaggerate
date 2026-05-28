// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Emily "TTG" Banerjee <prs.ttg+dedagger@pm.me>

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;

public class ImportAnnotations extends GhidraScript {
	private Program program;
	private DataTypeManager dataTypeManager;
	private DataTypeParser typeParser;

	private static final Map<String, CommentType> COMMENT_KINDS = Map.of(
			"plate", CommentType.PLATE,
			"pre", CommentType.PRE,
			"post", CommentType.POST,
			"eol", CommentType.EOL,
			"repeatable", CommentType.REPEATABLE);

	@Override
	public void run() throws Exception {
		String[] arguments = getScriptArgs();
		if(arguments.length < 1) {
			printerr("usage: ImportAnnotations <in.json>");
			return;
		}

		Path inPath = Paths.get(arguments[0]);
		if(!Files.isRegularFile(inPath)) {
			println("no annotations to apply at " + inPath);
			return;
		}

		program = currentProgram;
		dataTypeManager = program.getDataTypeManager();
		typeParser = new DataTypeParser(dataTypeManager, dataTypeManager, null, AllowedDataTypes.ALL);

		JsonObject root = JsonParser.parseString(Files.readString(inPath)).getAsJsonObject();

		if(root.has("image_sha256")) {
			String expected = root.get("image_sha256").getAsString();
			String actual = program.getExecutableSHA256();

			if(actual != null && !expected.equals(actual)) {
				printerr("WARN: image SHA256 mismatch — annotations may not align");
				printerr("\texpected " + expected);
				printerr("\tactual " + actual);
			}
		}

		int types = importDataTypes(root.getAsJsonArray("data_types"));
		int data = importDefinedData(root.getAsJsonArray("data"));
		int functions = importFunctions(root.getAsJsonArray("functions"));
		int symbols = importSymbols(root.getAsJsonArray("symbols"));
		int comments = importComments(root.getAsJsonArray("comments"));

		println(
				"applied: types = " +
				types +
				", data=" +
				data +
				", functions=" +
				functions +
				", symbols=" +
				symbols +
				", comments=" +
				comments);
	}

	private int importDataTypes(JsonArray array) throws Exception {
		if(array == null) return 0;

		Map<String, JsonObject> definitions = new LinkedHashMap<>();
		for(JsonElement element : array) {
			JsonObject object = element.getAsJsonObject();
			definitions.put(object.get("path").getAsString(), object);
		}

		for(Map.Entry<String, JsonObject> entry : definitions.entrySet()) {
			JsonObject object = entry.getValue();

			String path = entry.getKey();
			if(dataTypeManager.getDataType(path) != null) continue;

			CategoryPath categoryPath = new CategoryPath(parentPath(path));
			String name = leaf(path);
			DataType stub = null;

			String kind = object.get("kind").getAsString();
			switch(kind) {
				case "struct": {
					int size = object.has("size") ? object.get("size").getAsInt() : 0;
					stub = new StructureDataType(categoryPath, name, size, dataTypeManager);
					break;
				}

				case "union": {
					stub = new UnionDataType(categoryPath, name, dataTypeManager);
					break;
				}

				case "enum": {
					stub = new EnumDataType(categoryPath, name, object.get("size").getAsInt(), dataTypeManager);
					break;
				}

				case "typedef": continue;
			}

			if(stub != null) dataTypeManager.addDataType(stub, DataTypeConflictHandler.REPLACE_HANDLER);
		}

		int count = 0;
		for(Map.Entry<String, JsonObject> entry : definitions.entrySet()) {
			JsonObject object = entry.getValue();

			String path = entry.getKey();
			String kind = object.get("kind").getAsString();

			try {
				switch(kind) {
					case "struct": {
						populateStruct(path, object);
						break;
					}

					case "union": {
						populateUnion(path, object);
						break;
					}

					case "enum": {
						populateEnum(path, object);
						break;
					}

					case "typedef": {
						createTypedef(path, object);
						break;
					}
				}
				count++;
			}
			catch(Exception exception) {
				printerr("data type " + path + ": " + exception.getMessage());
			}
		}
		return count;
	}

	private void populateStruct(String path, JsonObject object) throws Exception {
		Structure structure = (Structure) dataTypeManager.getDataType(path);
		if(structure == null) return;

		structure.deleteAll();

		int size = object.has("size") ? object.get("size").getAsInt() : 0;
		if(size > 0) structure.growStructure(size);

		for(JsonElement fieldElement : object.getAsJsonArray("fields")) {
			JsonObject field = fieldElement.getAsJsonObject();
			int offset = field.get("offset").getAsInt();

			String fieldName = field.has("name") ? field.get("name").getAsString() : null;
			DataType fieldType = resolveType(field.get("type").getAsString());
			String comment = field.has("comment") ? field.get("comment").getAsString() : null;

			structure.replaceAtOffset(offset, fieldType, fieldType.getLength(), fieldName, comment);
		}
	}

	private void populateUnion(String path, JsonObject object) throws Exception {
		Union union = (Union) dataTypeManager.getDataType(path);
		if(union == null) return;

		while(union.getNumComponents() > 0) union.delete(0);

		for(JsonElement fieldElement : object.getAsJsonArray("fields")) {
			JsonObject field = fieldElement.getAsJsonObject();
			String fieldName = field.has("name") ? field.get("name").getAsString() : null;
			DataType fieldType = resolveType(field.get("type").getAsString());
			String comment = field.has("comment") ? field.get("comment").getAsString() : null;

			union.add(fieldType, fieldName, comment);
		}
	}

	private void populateEnum(String path, JsonObject object) {
		Enum enum = (Enum) dataTypeManager.getDataType(path);
		if(enum == null) return;

		for(String name : enum.getNames()) enum.remove(name);

		for(JsonElement valueElement : object.getAsJsonArray("values")) {
			JsonObject value = valueElement.getAsJsonObject();
			enum.add(value.get("name").getAsString(), value.get("value").getAsLong());
		}
	}

	private void createTypedef(String path, JsonObject object) throws Exception {
		if(dataTypeManager.getDataType(path) != null) return;

		CategoryPath categoryPath = new CategoryPath(parentPath(path));
		String name = leaf(path);
		DataType base = resolveType(object.get("base").getAsString());
		TypedefDataType typedefType = new TypedefDataType(categoryPath, name, base, dataTypeManager);

		dataTypeManager.addDataType(typedefType, DataTypeConflictHandler.REPLACE_HANDLER);
	}

	private int importFunctions(JsonArray array) throws Exception {
		if(array == null) return 0;

		FunctionManager functionManager = program.getFunctionManager();

		int count = 0;
		for(JsonElement element : array) {
			JsonObject object = element.getAsJsonObject();
			Address address = address(object.get("address").getAsString());

			Function field = functionManager.getFunctionAt(address);
			if(field == null) {
				printerr("no function at " + address + ", skipping");
				continue;
			}

			try {
				if(object.has("name")) {
					field.setName(object.get("name").getAsString(), SourceType.USER_DEFINED);
				}

				if(object.has("parameters")) {
					String cc = object.has("calling_convention") ?
							object.get("calling_convention").getAsString() :
							null;

					DataType returnType = resolveType(object.get("return_type").getAsString());

					List<Parameter> params = new ArrayList<>();
					for(JsonElement parameterElement : object.getAsJsonArray("parameters")) {
						JsonObject parameter = parameterElement.getAsJsonObject();
						DataType parameterType = resolveType(parameter.get("type").getAsString());
						params.add(new ParameterImpl(parameter.get("name").getAsString(), parameterType, program));
					}

					field.updateFunction(
							cc,
							new ReturnParameterImpl(returnType, program),
							params,
							FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
							true,
							SourceType.USER_DEFINED);
				}

				count++;
			}
			catch(Exception exception) {
				printerr("function " + address + ": " + exception.getMessage());
			}
		}

		return count;
	}

	private int importSymbols(JsonArray array) throws Exception {
		if(array == null) return 0;

		SymbolTable symbolTable = program.getSymbolTable();
		int count = 0;

		for(JsonElement element : array) {
			JsonObject object = element.getAsJsonObject();
			Address address = address(object.get("address").getAsString());
			String name = object.get("name").getAsString();

			try {
				boolean exists = false;

				for(Symbol structure : symbolTable.getSymbols(address)) {
					if(structure.getName().equals(name)) { exists = true; break; }
				}

				if(!exists) {
					symbolTable.createLabel(address, name, SourceType.USER_DEFINED);
					count++;
				}
			}
			catch(Exception exception) {
				printerr("symbol " + name + "@" + address + ": " + exception.getMessage());
			}
		}

		return count;
	}

	private int importDefinedData(JsonArray array) throws Exception {
		if(array == null) return 0;

		Listing listing = program.getListing();
		int count = 0;

		for(JsonElement element : array) {
			JsonObject object = element.getAsJsonObject();
			Address address = address(object.get("address").getAsString());

			try {
				DataType dataType = resolveType(object.get("type").getAsString());

				int length = dataType.getLength();
				if(length > 0) listing.clearCodeUnits(address, address.add(length - 1), false);
				else listing.clearCodeUnits(address, address, false);

				listing.createData(address, dataType);
				count++;
			}
			catch(Exception exception) {
				printerr("data @" + address + ": " + exception.getMessage());
			}
		}

		return count;
	}

	private int importComments(JsonArray array) {
		if(array == null) return 0;

		Listing listing = program.getListing();
		int count = 0;

		for(JsonElement element : array) {
			JsonObject object = element.getAsJsonObject();
			Address address = address(object.get("address").getAsString());

			CommentType type = COMMENT_KINDS.get(object.get("kind").getAsString());
			if(type == null) continue;

			listing.setComment(address, type, object.get("text").getAsString());
			count++;
		}

		return count;
	}

	private Address address(String structure) {
		return program.getAddressFactory().getAddress(structure);
	}

	private DataType resolveType(String spec) throws Exception {
		DataType existing = dataTypeManager.getDataType(spec);
		if(existing != null) return existing;

		return typeParser.parse(spec);
	}

	private static String parentPath(String path) {
		int idx = path.lastIndexOf('/');
		return idx <= 0 ? "/" : path.substring(0, idx);
	}

	private static String leaf(String path) {
		int idx = path.lastIndexOf('/');
		return idx < 0 ? path : path.substring(idx + 1);
	}
}
