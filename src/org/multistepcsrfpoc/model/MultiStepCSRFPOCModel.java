package org.multistepcsrfpoc.model;

import java.util.ArrayList;

public class MultiStepCSRFPOCModel {
	private RequestsTableModel tableModel;
	private CSRFPOCConfigModel csrfPOCConfig;
	private String selectedRequestText;
	private String csrfPOCText;
	
	public MultiStepCSRFPOCModel(RequestsTableModel tableModel, CSRFPOCConfigModel csrfPOCConfig) {
		this.tableModel = tableModel;
		this.csrfPOCConfig = csrfPOCConfig;
		this.selectedRequestText = "<Selected Request>";
		this.csrfPOCText = "<CSRF POC>";
	}
	
	/*removes rowIndex from the tableModel*/
	public void removeRow(int rowIndex) {
		tableModel.removeRow(rowIndex);
	}
	
	/*Adds a row*/
	public void addRow(RequestModel request) {
		tableModel.addRow(request);
	}
	
	/*Moves the selected row at rowIndex up one position*/
	public Boolean moveRowUp(int rowIndex) {
		return tableModel.moveRowUp(rowIndex);
	}
	
	/*Moves the selected row at rowIndex down one position*/
	public Boolean moveRowDown(int rowIndex) {
		return tableModel.moveRowDown(rowIndex);
	}
	
	/*Gets the request for the selected row*/
	public byte[] getSelectedRequest(int row) {
		return tableModel.getSelectedRequest(row);
	}
	
	public void setSelectedRequest(int row, byte[] request) {
		tableModel.setSelectedRequest(row, request);
	}

	public CSRFPOCConfigModel getCsrfPOCConfig() {
		return csrfPOCConfig;
	}

	public void setCsrfPOCConfig(CSRFPOCConfigModel csrfPOCConfig) {
		this.csrfPOCConfig = csrfPOCConfig;
	}
	
	public boolean isUseIframe() {
		return csrfPOCConfig.isUseIframe();
	}

	public void setUseIframe(boolean useIframe) {
		csrfPOCConfig.setUseIframe(useIframe);
	}

	public boolean isUseNewTab() {
		return csrfPOCConfig.isUseNewTab();
	}

	public void setUseNewTab(boolean useNewTab) {
		csrfPOCConfig.setUseNewTab(useNewTab);
	}

	public boolean isUseXhr() {
		return csrfPOCConfig.isUseXhr();
	}

	public void setUseXhr(boolean useXhr) {
		csrfPOCConfig.setUseXhr(useXhr);
	}

	public boolean isUseForm() {
		return csrfPOCConfig.isUseForm();
	}

	public void setUseForm(boolean useForm) {
		csrfPOCConfig.setUseForm(useForm);
	}

	public boolean isAllowScripts() {
		return csrfPOCConfig.isAllowScripts();
	}

	public void setAllowScripts(boolean allowScripts) {
		csrfPOCConfig.setAllowScripts(allowScripts);
	}

	public boolean isAutoSubmit() {
		return csrfPOCConfig.isAutoSubmit();
	}

	public void setAutoSubmit(boolean autosSubmit) {
		csrfPOCConfig.setAutoSubmit(autosSubmit);	
	}

	public void setSelectedRequestText(String selectedRequestText) {
		this.selectedRequestText = selectedRequestText;
	}

	public void setCsrfPOCText(String csrfPOCText) {
		this.csrfPOCText = csrfPOCText;
	}

	public String getSelectedRequestText() {
		return selectedRequestText;
	}

	public String getCsrfPOCText() {
		return csrfPOCText;
	}	

	public ArrayList<RequestModel> getRequests() {
		return tableModel.getRequests();
	}

	public RequestsTableModel getTableModel() {
		return tableModel;
	}
}