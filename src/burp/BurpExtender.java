package burp;

import org.multistepcsrfpoc.contextmenu.MultiStepCSRFContextMenuHandler;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

public class BurpExtender implements IBurpExtender{
	
	public static String EXTENSION_NAME = "Multi-step CSRF POC Generator";	
	private IBurpExtenderCallbacks callbacks = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {	
		//save callbacks copy
		this.callbacks = callbacks;			
		//set extension name
		this.callbacks.setExtensionName(EXTENSION_NAME);
		//create context menu
		this.callbacks.registerContextMenuFactory(new MultiStepCSRFContextMenuHandler(callbacks.getHelpers()));
	}	
}
