package requestparsergenerator.proxy;

import java.util.ArrayList;

import org.multistepcsrfpoc.model.request.RequestModel;
import org.python.core.PyException;

import requestparsergenerator.api.ParserBuilderType;
import requestparsergenerator.factory.ParserBuilderTypeFactory;

public class ParserBuilderProxy implements ParserBuilderType{
	ParserBuilderType parserBuilder = null;

	public ParserBuilderProxy(ArrayList<RequestModel> requests) {
		this.parserBuilder = ParserBuilderTypeFactory.createParserBuilderType(requests);
	}

	@Override
	public String generate(int generationType, int targetType, boolean autoSubmit) throws PyException {
		return this.parserBuilder.generate(generationType, targetType, autoSubmit);
	}
}
