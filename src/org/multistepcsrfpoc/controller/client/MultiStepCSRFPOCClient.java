package org.multistepcsrfpoc.controller.client;

import java.util.ArrayList;

import org.multistepcsrfpoc.model.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.RequestModel;
/*
 * Clients implement this interface so that the listed events are called.
 * */
public interface MultiStepCSRFPOCClient {			
	
	/*Called when Regenerate button is called*/
	public void regenerateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests);
	
	/*Copy HTML clicked*/
	public void copyHTMLClicked(String csrfPOCText);
}