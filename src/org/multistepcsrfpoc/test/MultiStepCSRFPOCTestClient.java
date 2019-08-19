package org.multistepcsrfpoc.test;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;
import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClientInterface;
import org.multistepcsrfpoc.main.MultiStepCSRFPOC;
import org.multistepcsrfpoc.model.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.RequestModel;

public class MultiStepCSRFPOCTestClient implements MultiStepCSRFPOCClientInterface {
	private HashMap<String, MultiStepCSRFPOC> activePOCs;
	private MultiStepCSRFPOCController controller;
	
	public MultiStepCSRFPOCTestClient() {
		this.activePOCs = new HashMap<String, MultiStepCSRFPOC>();
	}
	
	@Override
	public String regenerateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests) {		
		String configMsg =  "CSRF POC Config is "+"\n"+							
							"Use new tab: "+csrfPOCConfig.isUseNewTab()+"\n"+
							"Use Iframe: "+csrfPOCConfig.isUseIframe()+"\n"+							
							"Use XHR: "+csrfPOCConfig.isUseXhr()+"\n"+
							"Use Form: "+csrfPOCConfig.isUseForm()+"\n"+
							"Use jQuery: "+csrfPOCConfig.isUseJQuery()+"\n"+
							"Auto Submit: "+csrfPOCConfig.isAutoSubmit();
		
		//call the request_parser on all the requests

		//call the request_builder on all the requests
		
		this.controller.updateMsgs(configMsg);		
		return "<NEW CSRF POC>";
	}

	@Override
	public void copyHTMLClicked(String csrfPOCText) {
		if (csrfPOCText != null && csrfPOCText.length() > 0) {
			Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			clipboard.setContents(new StringSelection(csrfPOCText), null);
		}
		this.controller.updateMsgs("Copied someting to clipboard!\n");
	}

	@Override
	public Set<String> getActivePOCs() {
		// TODO implement returning active POCs
		return this.activePOCs.keySet();
	}

	@Override
	public void csrfPOCWindowClosed(String title) {
		this.activePOCs.remove(title);
		System.out.println("CSRF POC window closed!");
	}

	@Override
	public void createCSRFPOCWindow(ArrayList<RequestModel> requests) {
		System.out.println("Generate new Multi-Step CSRF POC clicked!");
	}
	
	@Override
	public void addToPOC(String title, ArrayList<RequestModel> requests) {
		System.out.println("addToPOC clicked!");
	}

	public void setController(MultiStepCSRFPOCController controller) {
		this.controller = controller;
	}
}