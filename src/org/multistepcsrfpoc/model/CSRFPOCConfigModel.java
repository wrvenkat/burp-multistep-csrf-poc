package org.multistepcsrfpoc.model;

public class CSRFPOCConfigModel {
	private boolean useIframe;
	private boolean useNewTab;
	private boolean useXhr;
	private boolean useForm;
	private boolean allowScripts;
	private boolean autoSubmit;
	
	public CSRFPOCConfigModel() {
		//default config
		this.useIframe = true;
		this.useNewTab = false;
		//default config
		this.useXhr = true;
		this.useForm = false;
		this.allowScripts = true;
		//default config
		this.autoSubmit = true;
	}

	public boolean isUseIframe() {
		return useIframe;
	}

	public void setUseIframe(boolean useIframe) {
		this.useIframe = useIframe;
	}

	public boolean isUseNewTab() {
		return useNewTab;
	}

	public void setUseNewTab(boolean useNewTab) {
		this.useNewTab = useNewTab;
	}

	public boolean isUseXhr() {
		return useXhr;
	}

	public void setUseXhr(boolean useXhr) {
		this.useXhr = useXhr;
	}

	public boolean isUseForm() {
		return useForm;
	}

	public void setUseForm(boolean useForm) {
		this.useForm = useForm;
	}

	public boolean isAllowScripts() {
		return allowScripts;
	}

	public void setAllowScripts(boolean allowScripts) {
		this.allowScripts = allowScripts;
	}

	public boolean isAutoSubmit() {
		return autoSubmit;
	}

	public void setAutoSubmit(boolean autosSubmit) {
		this.autoSubmit = autosSubmit;
	}		
}