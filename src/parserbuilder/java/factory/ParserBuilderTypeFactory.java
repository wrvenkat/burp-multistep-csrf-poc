package parserbuilder.java.factory;

import java.io.File;
import java.util.ArrayList;

import org.multistepcsrfpoc.model.request.RequestModel;
import org.python.core.PyByteArray;
import org.python.core.PyList;
import org.python.core.PyObject;
import org.python.core.PyString;
import org.python.util.PythonInterpreter;

import parserbuilder.java.api.ParserBuilderType;

public class ParserBuilderTypeFactory {
	public static final String fileUploadFolder = "file_uploads";

	public static ParserBuilderType createParserBuilderType(ArrayList<RequestModel> requests) {

		//get Burp temp folder
		File currentClassFile = new File(ParserBuilderTypeFactory.class.getProtectionDomain().getCodeSource().getLocation().getPath());
		String burpTempFolder = currentClassFile.getAbsoluteFile().getParent()+java.io.File.separator+ParserBuilderTypeFactory.fileUploadFolder;
		//System.out.println("Temp folder path: "+burpTempFolder);

		PythonInterpreter pyInterpreter = new PythonInterpreter();
		pyInterpreter.exec("from parserbuilder.python.request_parser_builder import ParserBuilder");
		PyObject parserBuilderClassObj = pyInterpreter.get("ParserBuilder");
		pyInterpreter.close();
		ArrayList<PyByteArray> requestStreamList = new ArrayList<PyByteArray>();
		ArrayList<String> protocolList = new ArrayList<String>();
		for (RequestModel request: requests) {
			requestStreamList.add(new PyByteArray(request.getRequest()));
			protocolList.add(request.getProtocol());
		}
		PyObject parserBuilderPyObj = parserBuilderClassObj.__call__(new PyString(burpTempFolder), new PyList(requestStreamList), new PyList(protocolList));
		return (ParserBuilderType)parserBuilderPyObj.__tojava__(ParserBuilderType.class);
	}
}
