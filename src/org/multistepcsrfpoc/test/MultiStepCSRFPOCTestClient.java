package org.multistepcsrfpoc.test;

import java.util.ArrayList;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClient;
import org.multistepcsrfpoc.model.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.RequestModel;

public class MultiStepCSRFPOCTestClient implements MultiStepCSRFPOCClient {

	@Override
	public void regenerateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests) {
		System.out.println("Regenerate Button Clicked!");		
	}

	@Override
	public void copyHTMLClicked(String csrfPOCText) {
		System.out.println("Copy HTML button clicked!");
	}
}
