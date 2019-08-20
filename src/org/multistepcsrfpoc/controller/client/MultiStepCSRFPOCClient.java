package org.multistepcsrfpoc.controller.client;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;
import org.multistepcsrfpoc.main.MultiStepCSRFPOC;
import org.multistepcsrfpoc.model.config.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.request.RequestModel;

public class MultiStepCSRFPOCClient implements MultiStepCSRFPOCClientInterface {
	private int activePOCCount;
	private final HashMap<String, MultiStepCSRFPOC> activePOCs;
	private static MultiStepCSRFPOCClient client;
	private MultiStepCSRFPOCController controller;

	public static final String TITLE_STRING = "Enhanced CSRF POC ";

	public MultiStepCSRFPOCClient() {
		this.activePOCs = new HashMap<String, MultiStepCSRFPOC>();
		this.controller = null;
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
	public void setController(MultiStepCSRFPOCController controller) {
		this.controller = controller;
	}

	@Override
	public String regenerateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests) {
		System.out.println("Regenerate Button Clicked!");
		System.out.println("\n"+
							"CSRF POC Config is "+"\n"+
							"Use new tab: "+csrfPOCConfig.isUseNewTab()+"\n"+
							"Use Iframe: "+csrfPOCConfig.isUseIframe()+"\n"+
							"Use XHR: "+csrfPOCConfig.isUseXhr()+"\n"+
							"Use Form: "+csrfPOCConfig.isUseForm()+"\n"+
							"Use jQuery: "+csrfPOCConfig.isUseJQuery()+"\n"+
							"Auto Submit: "+csrfPOCConfig.isAutoSubmit()
						  );
		try {
			//call the request_parser on all the requests

			//call the request_builder on all the requests
		}
		catch (Exception e) {
			e.printStackTrace();
			this.controller.updateMsgs(e.toString());
			return "";
		}
		return "<NEW CSRF POC>";
	}

	@Override
	public void copyHTMLClicked(String csrfPOCText) {
		if (csrfPOCText != null && csrfPOCText.length() > 0) {
			Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
			clipboard.setContents(new StringSelection(csrfPOCText), null);
		}
	}

	@Override
	public Set<String> getActivePOCs() {

		/*for (String key: this.activePOCs.keySet())
			System.out.println("Key: "+key+" value: "+this.activePOCs.get(key).toString());*/

		return this.activePOCs.keySet();
	}

	@Override
	public void createCSRFPOCWindow(ArrayList<RequestModel> requests) {
		//System.out.println("Generate new Multi-Step CSRF POC clicked!");

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
		this.activePOCs.get(title).addToPOC(requests);
	}
}