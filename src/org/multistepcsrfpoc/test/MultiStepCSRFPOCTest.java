package org.multistepcsrfpoc.test;

import java.util.ArrayList;

import org.multistepcsrfpoc.main.MultiStepCSRFPOC;
import org.multistepcsrfpoc.model.RequestModel;

public class MultiStepCSRFPOCTest {
	public static void main(String args[]) {
		String title = "CSRF POC Test 1";
		MultiStepCSRFPOCTestClient client = new MultiStepCSRFPOCTestClient();
		ArrayList<RequestModel> requestList = new ArrayList<RequestModel>();
		int reqNum = 5;
		for (int i=0; i< reqNum; i++)
			requestList.add(new RequestModel("GET", "URL"+(i+1), "REQ"+(i+1)));
		new MultiStepCSRFPOC(title, requestList, client);
		//System.out.println("UI Started!");
	}
}