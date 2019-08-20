package org.multistepcsrfpoc.model.config;

public class CSRFPOCConfigModel {
	private boolean useIframe;
	private boolean useNewTab;
	private boolean useXhr;
	private boolean useForm;
	private boolean useJQuery;
	private boolean autoSubmit;

	public CSRFPOCConfigModel() {
		//default config
		this.useIframe = true;
		this.useNewTab = false;
		//default config
		this.useXhr = true;
		this.useForm = false;
		this.useJQuery = false;
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

	public boolean isUseJQuery() {
		return useJQuery;
	}

	public void setUseJQuery(boolean useJQuery) {
		this.useJQuery = useJQuery;
	}

	public boolean isAutoSubmit() {
		return autoSubmit;
	}

	public void setAutoSubmit(boolean autosSubmit) {
		this.autoSubmit = autosSubmit;
	}
}