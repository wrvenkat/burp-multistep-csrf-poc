package org.multistepcsrfpoc.controller.client;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;
import org.multistepcsrfpoc.main.MultiStepCSRFPOC;
import org.multistepcsrfpoc.model.config.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.request.RequestModel;
/*
 * Clients implement this interface so that the listed events are called.
 * */
public interface MultiStepCSRFPOCClientInterface {
	HashMap<String, MultiStepCSRFPOC> activePOCs = null;

	/*Called when Regenerate button is clicked*/
	/*Expects a String which is the new CSRF POC*/
	public String generateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests);

	/*Copy HTML clicked*/
	public void copyHTMLClicked(String csrfPOCText);

	/*CSRF POC Window closed*/
	public void csrfPOCWindowClosed(String title);

	/*Returns a list of active CSRF POC windows' title.*/
	public Set<String> getActivePOCs();

	/*Creates a new MultiStepCSRFPOC client*/
	public void createCSRFPOCWindow(ArrayList<RequestModel> requests);

	public void setController(MultiStepCSRFPOCController controller);

	/*Adds to existing POC window*/
	public void addToPOC(String title, ArrayList<RequestModel> requests);
}