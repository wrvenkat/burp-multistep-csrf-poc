package burp;

import burp.contextmenu.MultiStepCSRFContextMenuHandler;

public class BurpExtender implements IBurpExtender{

	public static String EXTENSION_NAME = "Multi-step CSRF POC Burp Extender";
	private IBurpExtenderCallbacks callbacks = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		//save callbacks copy
		this.callbacks = callbacks;
		//set extension name
		this.callbacks.setExtensionName(EXTENSION_NAME);
		//create context menu
		this.callbacks.registerContextMenuFactory(new MultiStepCSRFContextMenuHandler(callbacks));
	}
}
