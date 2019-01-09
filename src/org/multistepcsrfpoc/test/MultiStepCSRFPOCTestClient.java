package org.multistepcsrfpoc.test;

import java.util.ArrayList;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClient;
import org.multistepcsrfpoc.model.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.RequestModel;

public class MultiStepCSRFPOCTestClient implements MultiStepCSRFPOCClient {

	@Override
	public void regenerateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests) {
		System.out.println("Regenerate Button Clicked!");
		System.out.println("CSRF POC Config is "+
							"Use Iframe: "+csrfPOCConfig.isUseIframe()+" "+
							"Use new tab: "+csrfPOCConfig.isUseNewTab()+" "+
							"Use XHR: "+csrfPOCConfig.isUseXhr()+" "+
							"Use Form: "+csrfPOCConfig.isUseForm()+" "+
							"Auto Submit: "+csrfPOCConfig.isAutoSubmit()+" "+
							"Allow Scripts: "+csrfPOCConfig.isAllowScripts()
		);
	}

	@Override
	public void copyHTMLClicked(String csrfPOCText) {
		System.out.println("Copy HTML button clicked. Returned text is "+csrfPOCText);
	}
}
