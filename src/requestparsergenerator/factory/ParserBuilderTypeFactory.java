package requestparsergenerator.factory;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Properties;

import org.multistepcsrfpoc.model.request.RequestModel;
import org.python.core.PyFile;
import org.python.core.PyList;
import org.python.core.PyObject;
import org.python.core.PyString;
import org.python.util.PythonInterpreter;

import requestparsergenerator.api.ParserBuilderType;

public class ParserBuilderTypeFactory {
	public static boolean jythonModulePathSet = true;
	public static final String fileUploadFolder = "file_uploads";

	public static ParserBuilderType createParserBuilderType(ArrayList<RequestModel> requests) {
		Properties newProps = null;

		if (!jythonModulePathSet) {
			Properties oldProps = System.getProperties();
			newProps = setPythonModulePath(System.getProperties());
			PythonInterpreter.initialize(oldProps, newProps, null);
			jythonModulePathSet = true;
		}

		File currentClassFile = new File(ParserBuilderTypeFactory.class.getProtectionDomain().getCodeSource().getLocation().getPath());
		String burpTempFolder = currentClassFile.getAbsoluteFile().getParent()+java.io.File.separator+ParserBuilderTypeFactory.fileUploadFolder;
		System.out.println("Temp folder path: "+burpTempFolder);

		PythonInterpreter pyInterpreter = new PythonInterpreter();
		pyInterpreter.exec("from parserbuilder.request_parser_builder import ParserBuilder");
		PyObject parserBuilderClassObj = pyInterpreter.get("ParserBuilder");
		pyInterpreter.close();
		ArrayList<PyFile> requestStreamList = new ArrayList<PyFile>();
		ArrayList<String> protocolList = new ArrayList<String>();
		for (RequestModel request: requests) {
			ByteArrayInputStream requestStream = new ByteArrayInputStream(request.getRequest());
			requestStreamList.add(new PyFile(requestStream));
			protocolList.add(request.getProtocol());
		}
		PyObject parserBuilderPyObj = parserBuilderClassObj.__call__(new PyString(burpTempFolder), new PyList(requestStreamList), new PyList(protocolList));
		return (ParserBuilderType)parserBuilderPyObj.__tojava__(ParserBuilderType.class);
	}

	/**
	 * Method that adds the current
	 * */
	private static Properties setPythonModulePath(Properties props) {
		System.out.println("Working dir "+System.getProperty("user.dir"));
		String currentClassPath = ParserBuilderTypeFactory.class.getProtectionDomain().getCodeSource().getLocation().getPath();//+".zip";
		System.out.println("Current class path "+currentClassPath);

		String pythonPathProp = System.getProperty("python.path");
		String new_value;
		if (pythonPathProp == null)
			new_value  = currentClassPath;
		else
			new_value = pythonPathProp +java.io.File.pathSeparator + currentClassPath;

		System.out.println("New python module path value "+new_value);
		props.setProperty("python.path",new_value);
		return props;
	}
}
