package requestparsergenerator.api;

import org.python.core.PyException;

public interface ParserBuilderType {
	public String generate(int generationType, int targetType, boolean autoSubmit) throws PyException;
}
