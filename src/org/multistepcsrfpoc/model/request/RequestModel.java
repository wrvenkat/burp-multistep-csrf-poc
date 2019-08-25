package org.multistepcsrfpoc.model.request;

import java.net.URL;

import javax.swing.undo.UndoManager;

public class RequestModel {
	private String httpMethod;
	private URL url;
	private final String protocol;
	private byte[] request;
	private final UndoManager undoManager;


	public RequestModel(String httpMethod, URL url, String protocol, byte[] request) {
		this.httpMethod = httpMethod;
		this.url = url;
		this.protocol = protocol;
		this.request = request;
		this.undoManager = new UndoManager();
	}
	public URL getUrl() {
		return url;
	}
	public byte[] getRequest() {
		return request;
	}
	public void setHttpMethod(String httpMethod) {
		this.httpMethod = httpMethod;
	}
	public void setUrl(URL url) {
		this.url = url;
	}
	public void setRequest(byte[] request) {
		this.request = request;
	}
	public String getProtocol() {
		return protocol;
	}
	public String getHttpMethod() {
		return httpMethod;
	}
	public UndoManager getUndoManager() {
		return undoManager;
	}

}