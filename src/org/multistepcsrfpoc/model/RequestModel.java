package org.multistepcsrfpoc.model;

import java.net.URL;

public class RequestModel {
	private String httpMethod;	
	private URL url;
	private byte[] request;	
	
	public RequestModel(String httpMethod, URL url, byte[] request) {
		this.httpMethod = httpMethod;
		this.url = url;
		this.request = request;
	}
	
	public String getHttpMethod() {
		return httpMethod;
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
}