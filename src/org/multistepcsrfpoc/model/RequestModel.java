package org.multistepcsrfpoc.model;

public class RequestModel {
	private String httpMethod;	
	private String url;
	private String request;
	
	public RequestModel(String httpMethod, String url, String request) {
		this.httpMethod = httpMethod;
		this.url = url;
		this.request = request;
	}
	
	public String getHttpMethod() {
		return httpMethod;
	}
	public String getUrl() {
		return url;
	}
	public String getRequest() {
		return request;
	}	
	public void setHttpMethod(String httpMethod) {
		this.httpMethod = httpMethod;
	}
	public void setUrl(String url) {
		this.url = url;
	}
	public void setRequest(String request) {
		this.request = request;
	}
}