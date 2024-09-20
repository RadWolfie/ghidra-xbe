/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package xbeloader;

import java.util.List;
import java.util.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.File;
import java.io.FileNotFoundException;

import generic.jar.ResourceFile;
import ghidra.GhidraApplicationLayout;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.Platform;
import ghidra.framework.OperatingSystem;
import ghidra.framework.options.Options;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableFilter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;
import ghidra.program.model.address.*;
import ghidra.util.exception.*;


/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class XbeXbSymbolDatabaseAnalyzer extends AbstractAnalyzer {
	
	private static final String xbsdb_tool_exec = "XbSymbolDatabaseTool";
	private static final String xbsdb_tool_exec_wins = "XbSymbolDatabaseTool.exe";

	private static final String OPTION_NAME_SET_SYMBOL = "Allow  Set Symbol Name"; // Intentional extra space to force order of list.
	private static final String OPTION_NAME_DEMANGLE_SYMBOL = "Allow Demangle Symbol Name";
	private static final String OPTION_NAME_EXTEND_INFORMATION = "Allow Extend Information (includes fixup for param storage and calling convention)";
	private static final String OPTION_NAME_PARAM_VARS_RENAME = "EXTEND: Allow Rename Param Variables";

	private static final boolean OPTION_DEFAULT_ALLOW_SET_SYMBOL_NAME = true;
	private static final boolean OPTION_DEFAULT_ALLOW_DEMANGLE_NAME = false;
	private static final boolean OPTION_DEFAULT_ALLOW_EXTEND_INFORMATION = true;

	private boolean allowSetSymbolName = OPTION_DEFAULT_ALLOW_SET_SYMBOL_NAME;
	private boolean allowDemangleName = OPTION_DEFAULT_ALLOW_DEMANGLE_NAME;
	private boolean allowExtendInformation = OPTION_DEFAULT_ALLOW_EXTEND_INFORMATION;
	private boolean allowParameterStorageFixup = OPTION_DEFAULT_ALLOW_EXTEND_INFORMATION;
	private boolean allowParameterRename = !OPTION_DEFAULT_ALLOW_EXTEND_INFORMATION;

	public XbeXbSymbolDatabaseAnalyzer() {
		super("Xbox Symbol Database Analyzer", "Scan XBE for known library functions", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DISASSEMBLY.before());
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return program.getExecutableFormat().equals(XbeLoader.XBE_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getExecutableFormat().equals(XbeLoader.XBE_NAME);
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// NOTE: Ghidra does not keep the options listing in order.
		options.registerOption(OPTION_NAME_SET_SYMBOL, allowSetSymbolName, null, "Allow set symbol name, otherwise perform fixups if needed. (Demangle symbol will be excluded.)");
		options.registerOption(OPTION_NAME_DEMANGLE_SYMBOL, allowDemangleName, null, "Demangle symbol name into generic symbol name.");
		options.registerOption(OPTION_NAME_EXTEND_INFORMATION, allowExtendInformation, null, "Use extended information supplied by reverse-engineered information output.");
		options.registerOption(OPTION_NAME_PARAM_VARS_RENAME, allowParameterRename, null, "Allow rename parameters by XbSymbolDatabase supplied information.");
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		allowSetSymbolName = options.getBoolean(OPTION_NAME_SET_SYMBOL, OPTION_DEFAULT_ALLOW_SET_SYMBOL_NAME);
		allowDemangleName = options.getBoolean(OPTION_NAME_DEMANGLE_SYMBOL, OPTION_DEFAULT_ALLOW_DEMANGLE_NAME);
		allowExtendInformation = options.getBoolean(OPTION_NAME_EXTEND_INFORMATION, OPTION_DEFAULT_ALLOW_EXTEND_INFORMATION);
		allowParameterRename = options.getBoolean(OPTION_NAME_PARAM_VARS_RENAME, OPTION_DEFAULT_ALLOW_EXTEND_INFORMATION);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		String toolExec;
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			toolExec = xbsdb_tool_exec_wins;
		} else {
			toolExec = xbsdb_tool_exec;
		}

		String toolPath;
		try {
			toolPath = Application.getOSFile(toolExec).getAbsolutePath();
		} catch (FileNotFoundException e) {
			log.appendMsg("Failed to find " + toolExec + ": " + e.getMessage());
			return false;
		}
		String xbePath = program.getExecutablePath();
		// HACK: Somehow GUI broke this yet headlessAnalyzer didn't...
		// Ensure path does not erroneously begin with `/` before drive letter cause by Ghidra's end.
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.WINDOWS) {
			if (xbePath.charAt(0) == '/' && xbePath.charAt(1) != '/') {
				xbePath = xbePath.substring(1).replace("/", "\\");
			}
		}

		List<String> cmd = new ArrayList<>();
		cmd.add(toolPath);
		cmd.add(xbePath);
		if (allowDemangleName) {
			cmd.add("-d");
		}
		if (allowExtendInformation) {
			cmd.add("-e");
		}

		try {
			Process exec = new ProcessBuilder().command(cmd).start();
			BufferedReader output = new BufferedReader(new InputStreamReader(exec.getInputStream()));

			String line;
			while ((line = output.readLine()) != null) {
				String[] params = line.split("=");
				boolean isFunction = false;
				Address address = api.toAddr(Long.decode(params[1].strip()));
				String fullName = params[0].strip();
				int libNameLength = fullName.indexOf("__");
				String libName = fullName.substring(0, libNameLength);
				String symbolType, symbolName, callType = null;
				// Check if the extend information option is enabled, then process additional information supplied by xbsdb.
				if (allowExtendInformation) {
					int libTypeLength = fullName.indexOf("__", libNameLength + 2);
					symbolType = fullName.substring(libNameLength + 2, libTypeLength);
					// Check if symbol type is a function.
					if (symbolType.equals("FUN")) {
						isFunction = true;
						int callTypeLength = fullName.indexOf("__", libTypeLength + 2);
						callType = fullName.substring(libTypeLength + 2, callTypeLength);
						symbolName = fullName.substring(callTypeLength + 2, fullName.lastIndexOf("("));
					}
					// Otherwise, consider it as a variable.
					else {
						symbolName = fullName.substring(libNameLength + 2);
					}
				}
				// Otherwise, get the symbol name.
				else {
					symbolName = fullName.substring(libNameLength + 2);
				}

				if (isFunction) {
					processSymbolFunction(program, api, log, address, symbolName, getNamespace(program, libName), callType, fullName);
				}
				else if (allowSetSymbolName) {
					// NOTE: symbolName cannot be null to create label for variables. So, we must check if allowSetSymbolName is true first.
					program.getSymbolTable().createLabel(address, symbolName, getNamespace(program, libName), SourceType.ANALYSIS);
				}
			}

			exec.waitFor();
		} catch (Throwable e) {
			int st_i = 0;
			for (StackTraceElement stackTrace : e.getStackTrace()) {
				log.appendMsg("stack[" + st_i + "]     : " + stackTrace.toString());
				st_i++;
			}
			log.appendMsg("message      : " + e.getMessage());
			log.appendMsg("--------------");
			return false;
		}

		return true;
	}

	private void processSymbolFunction(Program program, FlatProgramAPI api, MessageLog log, Address address, String symbolName, Namespace libName, String callType, String fullName) {
		String ghidraSymbol = "N/A";
		String ghidraSymbolPrototype = "N/A";
		Function func = api.getFunctionAt​(address);
		Parameter ghidraParams[] = new Parameter[0];
		try {
			// Check if Ghidra had the function created or not.
			if (func == null) {
				func = api.createFunction(address, (allowSetSymbolName ? symbolName : null));
			}
			else {
				// Generate symbol mockup with parameters in case of exception occurs for readability.
				ghidraSymbol = func.getCallingConventionName() + " " + func.getName() + "(";
				ghidraParams = func.getParameters(VariableFilter.PARAMETER_FILTER);
				int ghidraParamsCount = func.getParameterCount();
				int ghidraParamsAutoCount = func.getAutoParameterCount();
				ghidraSymbolPrototype = func.getPrototypeString(true, true);
				String paramSymbols = new String();
				for (Variable param : ghidraParams) {
					VariableStorage paramStorage = param.getVariableStorage();
					if (!paramSymbols.isEmpty()) {
						paramSymbols += ",";
					}
					paramSymbols += paramStorage + " " + param.getName();
				}
				ghidraSymbol += paramSymbols + "); parameter count: " + ghidraParamsCount + ", auto parameter count: " + ghidraParamsAutoCount;
				// Check if user has request to set symbol name and update if both names are not the same.
				if (allowSetSymbolName && !func.getName().equals(symbolName)) {
					func.setName(symbolName, SourceType.ANALYSIS);
				}
			}
			Namespace ghidraLibName = func.getParentNamespace();
			if (ghidraLibName == null || ghidraLibName.getID() != libName.getID()) {
				func.setParentNamespace(libName);
			}
			boolean doUpdateParams = false;
			if (allowExtendInformation) {
				String[] xbsdbParams = fullName.substring(fullName.indexOf("(") + 1, fullName.indexOf(")")).split(",");
				if (xbsdbParams[0].isEmpty()) {
					return;
				}

				Parameter updateParams[] = new Parameter[xbsdbParams.length];
				int paramOffset = 0;
				int pushOffset = 4; // Always default to 4.
				for (String param : xbsdbParams) {
					String storageName[] = param.strip().split(" ");
					Parameter ghidraParam;
					DataType paramType;
					VariableStorage paramStorage;
					String paramName;
					boolean doUpdateParam = false;
					// Check if Ghidra's parameters are within bound.
					if (paramOffset < ghidraParams.length) {
						ghidraParam = ghidraParams[paramOffset];
						paramName = ghidraParam.getName();
						paramType = ghidraParam.getDataType();
						paramStorage = ghidraParam.getVariableStorage();
					}
					// Otherwise use default value for missing parameter.
					else {
						ghidraParam = null;
						paramName = null;
						paramType = Undefined.getUndefinedDataType(4);
						paramStorage = VariableStorage.UNASSIGNED_STORAGE;
					}
					// Check if user has request to verify and perform parameter storage fixup.
					if (allowParameterStorageFixup) {
						VariableStorage storageUpdate;
						DataType typeUpdate;
						// Create push variable to verify supplied input from Ghidra.
						if (storageName[0].startsWith("psh")) {
							String multiPush = storageName[0].substring(3);
							int size = 4;
							// Check multi-push from "psh#" input, then multiply it with the size of 4.
							if (!multiPush.isEmpty()) {
								size *= Integer.parseInt(multiPush);
							}
							storageUpdate = new VariableStorage(program, pushOffset, size);
							typeUpdate = Undefined.getUndefinedDataType(size);
							pushOffset += size;
						}
						// Create register variable to verify supplied input from Ghidra.
						else {
							Register register = getStorageType(program, storageName[0].toUpperCase());
							storageUpdate = new VariableStorage(program, register);
							typeUpdate = Undefined.getUndefinedDataType(register.getMinimumByteSize());
						}
						// Fix variable storage if it is not the same.
						if (storageUpdate.compareTo(paramStorage) != 0) {
							paramStorage = storageUpdate;
							doUpdateParam = true;
						}
						// Fix the data type if it is not the same.
						if (Undefined.isUndefined(paramType) && typeUpdate.getLength() != paramType.getLength()) {
							paramType = typeUpdate;
							doUpdateParam = true;
						}
						// Create a new parameter to replace the existing one or add a parameter to the list.
						if (doUpdateParam) {
							ghidraParam = new ParameterImpl(paramName, paramType, paramStorage, program, SourceType.DEFAULT);
							doUpdateParams = true;
						}
					}
					// Check if user has request to set parameter name and update if both names are not the same.
					if (allowParameterRename && 1 < storageName.length) {// once parameters listing is fixed again, enable -> && ghidraParam != null) {
						if (!storageName[1].equals(ghidraParam.getName())) {
							ghidraParam.setName(storageName[1], SourceType.ANALYSIS);
							doUpdateParams = true;
						}
					}
					updateParams[paramOffset] = ghidraParam;
					paramOffset++;
				}
				// If any above changes occur, override Ghidra's input with our own correction.
				if (doUpdateParams) {
					ghidraParams = updateParams;
				}
			}
			// Update the parameters on request.
			if (doUpdateParams) {
				GenericCallingConvention ghidraCallType = GenericCallingConvention.getGenericCallingConvention(callType);
				func.setCallingConvention(ghidraCallType.toString());
				FunctionUpdateType ghidraStorageType;
				if (ghidraCallType == GenericCallingConvention.unknown) {
					ghidraStorageType = FunctionUpdateType.CUSTOM_STORAGE;
				}
				else {
					ghidraStorageType = FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;
				}
				func.replaceParameters(ghidraStorageType, true, SourceType.ANALYSIS, ghidraParams);
				// Anything else need to be put in here? i.e. decompile again, etc
			}
		} catch (Throwable e) {
			log.appendMsg("xbsdb symbol : " + fullName);
			log.appendMsg("ghidra symbol: " + ghidraSymbol);
			log.appendMsg("ghidra proto : " + ghidraSymbolPrototype);
			int st_i = 0;
			for (StackTraceElement stackTrace : e.getStackTrace()) {
				log.appendMsg("stack[" + st_i + "]     : " + stackTrace.toString());
				st_i++;
			}
			log.appendMsg("message      : " + e.getMessage());
			log.appendMsg("--------------");
		}
	}

	private Register getStorageType(Program program, String storageName) {
		return program.getProgramContext().getRegister(storageName);
	}

	private Namespace getNamespace(Program program, String namespace) {
		Namespace space = program.getSymbolTable().getNamespace(namespace, null);
		if (space != null) {
			return space;
		}
		try {
			return program.getSymbolTable().createNameSpace(null, namespace, SourceType.IMPORTED);
		}
		catch (Exception e) {
			return null;
		}
	}
}
