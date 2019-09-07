package org.multistepcsrfpoc.controller.client;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Set;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;
import org.multistepcsrfpoc.main.MultiStepCSRFPOC;
import org.multistepcsrfpoc.model.config.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.request.RequestModel;
import org.python.core.PyException;

import burp.IBurpExtenderCallbacks;
import requestparsergenerator.api.GenerationType;
import requestparsergenerator.api.TargetType;
import requestparsergenerator.proxy.ParserBuilderProxy;

public class MultiStepCSRFPOCClient implements MultiStepCSRFPOCClientInterface {
	private int activePOCCount;
	private final HashMap<String, MultiStepCSRFPOC> activePOCs;
	private static MultiStepCSRFPOCClient client;
	private MultiStepCSRFPOCController controller;
	private final IBurpExtenderCallbacks burpCallbacks;

	public static final String TITLE_STRING = "Enhanced CSRF POC ";

	public MultiStepCSRFPOCClient(IBurpExtenderCallbacks burpCallbacks) {
		this.activePOCs = new HashMap<String, MultiStepCSRFPOC>();
		this.controller = null;
		this.burpCallbacks = burpCallbacks;
	}

	/*Returns the instance of itself*/
	public static MultiStepCSRFPOCClientInterface getClient(IBurpExtenderCallbacks burpCallbacks) {
		if (client == null) {
			client = new MultiStepCSRFPOCClient(burpCallbacks);
			client.activePOCCount = 0;
		}
		return client;
	}

	@Override
	public void setController(MultiStepCSRFPOCController controller) {
		this.controller = controller;
	}

	@Override
	public String generateClicked(CSRFPOCConfigModel csrfPOCConfig, ArrayList<RequestModel> requests) {
		//System.out.println("Regenerate Button Clicked!");
		/*System.out.println("CSRF POC Config is "+"\n"+
							"Use new tab: "+csrfPOCConfig.isUseNewTab()+"\n"+
							"Use Iframe: "+csrfPOCConfig.isUseIframe()+"\n"+
							"Use XHR: "+csrfPOCConfig.isUseXhr()+"\n"+
							"Use Form: "+csrfPOCConfig.isUseForm()+"\n"+
							"Use jQuery: "+csrfPOCConfig.isUseJQuery()+"\n"+
							"Auto Submit: "+csrfPOCConfig.isAutoSubmit()
						  );
		*/
		try {
			//call the request_parser on all the requests
			ArrayList<byte[]> httpRequests = new ArrayList<byte[]>();
			for (RequestModel request: requests)
				httpRequests.add(request.getRequest());
			ParserBuilderProxy parserBuilder = new ParserBuilderProxy(requests);
			//System.out.println("Created ParserBuilder for all the byte[] requests.");

			//construct the generation type
			int generationType = -1;
			if (csrfPOCConfig.isUseForm()) generationType = GenerationType.form_request;
			else if (csrfPOCConfig.isUseXhr()) generationType = GenerationType.xhr_request;
			else if (csrfPOCConfig.isUseJQuery()) generationType = GenerationType.jquery_request;

			//construct target type
			int targetType = -1;
			if (csrfPOCConfig.isUseIframe()) targetType = TargetType.iframe;
			else if (csrfPOCConfig.isUseNewTab()) targetType = TargetType.new_tab;

			String htmlCode = parserBuilder.generate(generationType, targetType, csrfPOCConfig.isAutoSubmit());

			String classLoadPath = MultiStepCSRFPOCClient.class.getResource("MultiStepCSRFPOCClient.class").getPath();

			return htmlCode;
		}
		catch (PyException e) {
			OutputStream outpuStream = this.burpCallbacks.getStderr();
			StringWriter errors = new StringWriter();
			e.printStackTrace(new PrintWriter(errors));
			try {
				outpuStream.write(errors.toString().getBytes());
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			this.controller.updateMsgs(""+e.value);
		}
		return "";
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