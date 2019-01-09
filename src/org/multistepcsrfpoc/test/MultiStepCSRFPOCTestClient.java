package org.multistepcsrfpoc.test;

import java.util.ArrayList;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClient;
import org.multistepcsrfpoc.model.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.RequestModel;

public class MultiStepCSRFPOCTestClient implements MultiStepCSRFPOCClient {

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
		return "<NEW CSRF POC>";
	}

	@Override
	public void copyHTMLClicked(String csrfPOCText) {
		System.out.println("Copy HTML button clicked. Returned text is "+csrfPOCText);
	}
}