package org.multistepcsrfpoc.controller.client;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClientInterface;
import org.multistepcsrfpoc.main.MultiStepCSRFPOC;
import org.multistepcsrfpoc.model.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.RequestModel;

import request_parser.http.request$py;

public class MultiStepCSRFPOCClient implements MultiStepCSRFPOCClientInterface {
	private int activePOCCount;
	private HashMap<String, MultiStepCSRFPOC> activePOCs;
	private static MultiStepCSRFPOCClient client;
	
	public static final String TITLE_STRING = "Enhanced CSRF POC ";
	
	public MultiStepCSRFPOCClient() {
		this.activePOCs = new HashMap<String, MultiStepCSRFPOC>();
	}

	/*Returns the instance of itself*/
	public static MultiStepCSRFPOCClientInterface getClient() {
		if (client == null) {
			client = new MultiStepCSRFPOCClient();
			client.activePOCCount = 0;
		}		
		return client;
	}
	
	@Override
	public String regenerateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests) {
		System.out.println("Regenerate Button Clicked!");
		System.out.println("\n"+
							"CSRF POC Config is "+"\n"+
							"Allow Scripts: "+csrfPOCConfig.isAllowScripts()+"\n"+
							"Use new tab: "+csrfPOCConfig.isUseNewTab()+"\n"+
							"Use Iframe: "+csrfPOCConfig.isUseIframe()+"\n"+							
							"Use XHR: "+csrfPOCConfig.isUseXhr()+"\n"+
							"Use Form: "+csrfPOCConfig.isUseForm()+"\n"+
							"Auto Submit: "+csrfPOCConfig.isAutoSubmit()							
						  );
		try {
			//call the request_parser on all the requests
			ArrayList<request$py> parserRequests = new ArrayList<request$py>();
	
			//call the request_builder on all the requests
			return "<NEW CSRF POC>";
		}
	}

	@Override
	public void copyHTMLClicked(String csrfPOCText) {
		System.out.println("Copy HTML button clicked. Returned text is "+csrfPOCText);
		if (csrfPOCText != null && csrfPOCText.length() > 0) {
			Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			clipboard.setContents(new StringSelection(csrfPOCText), null);
		}
	}

	@Override
	public Set<String> getActivePOCs() {
		
		for (String key: this.activePOCs.keySet())
			System.out.println("Key: "+key+" value: "+this.activePOCs.get(key).toString());
		
		return this.activePOCs.keySet();
	}

	@Override
	public void createCSRFPOCWindow(ArrayList<RequestModel> requests) {
		System.out.println("Generate new Multi-Step CSRF POC clicked!");
		
		//create title and spawn the UI
		String title = TITLE_STRING+(this.activePOCCount+1);
		MultiStepCSRFPOC newPOC = new MultiStepCSRFPOC(title, requests, this);
		
		//add to list of active POC
		this.activePOCs.put(title, newPOC);
		
		//increase count
		this.activePOCCount++;		
	}
	
	@Override
	public void csrfPOCWindowClosed(String title) {
		this.activePOCs.remove(title);
	}

	@Override
	public void addToPOC(String title, ArrayList<RequestModel> requests) {
		// TODO Auto-generated method stub
		System.out.println("TODO!");
	}	
}