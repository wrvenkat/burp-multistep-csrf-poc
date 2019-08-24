package requestparsergenerator.factory;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;

import org.multistepcsrfpoc.model.request.RequestModel;
import org.python.core.PyFile;
import org.python.core.PyList;
import org.python.core.PyObject;
import org.python.util.PythonInterpreter;

import requestparsergenerator.api.ParserBuilderType;

public class ParserBuilderTypeFactory {
	public static ParserBuilderType createParserBuilderType(ArrayList<RequestModel> requests) {
		PythonInterpreter pyInterpreter = new PythonInterpreter();
		pyInterpreter.exec("from parser.request_parser_builder import ParserBuilder");
		PyObject parserBuilderClassObj = pyInterpreter.get("ParserBuilder");
		pyInterpreter.close();
		ArrayList<PyFile> requestStreamList = new ArrayList<PyFile>();
		for (RequestModel request: requests) {
			ByteArrayInputStream requestStream = new ByteArrayInputStream(request.getRequest());
			requestStreamList.add(new PyFile(requestStream));
		}
		PyObject parserBuilderPyObj = parserBuilderClassObj.__call__(new PyList(requestStreamList));
		return (ParserBuilderType)parserBuilderPyObj.__tojava__(ParserBuilderType.class);
	}
}
