package org.multistepcsrfpoc.test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;

import org.multistepcsrfpoc.main.MultiStepCSRFPOC;
import org.multistepcsrfpoc.model.request.RequestModel;

public class MultiStepCSRFPOCTest {
	private static final String TEST_URL = "https://demo.testfire.net/test/";
	public static void main(String args[]) throws MalformedURLException {
		String title = "CSRF POC Test 1";
		MultiStepCSRFPOCTestClient client = new MultiStepCSRFPOCTestClient();
		ArrayList<RequestModel> requestList = new ArrayList<RequestModel>();
		int reqNum = 5;
		for (int i=0; i< reqNum; i++)
			requestList.add(new RequestModel("GET", new URL(TEST_URL+(i+1)),"https", ("REQ"+(i+1)).getBytes()));
		new MultiStepCSRFPOC(title, requestList, client);
	}
}