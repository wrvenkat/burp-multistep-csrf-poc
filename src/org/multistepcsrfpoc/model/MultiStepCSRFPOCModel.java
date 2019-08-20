package org.multistepcsrfpoc.model;

import java.util.ArrayList;

import org.multistepcsrfpoc.model.config.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.request.RequestModel;
import org.multistepcsrfpoc.model.table.RequestsTableModel;
import org.multistepcsrfpoc.model.table.SelectedRequestTextPaneModel;

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
	public SelectedRequestTextPaneModel getSelectedRequest(int row) {
		return tableModel.getSelectedRequest(row);
	}
	
	public void setSelectedRequest(int row, SelectedRequestTextPaneModel paneStatus) {
		tableModel.setSelectedRequest(row, paneStatus);
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

	public boolean isUseJQuery() {
		return csrfPOCConfig.isUseJQuery();
	}

	public void setUseJQuery(boolean useJquery) {
		csrfPOCConfig.setUseJQuery(useJquery);
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
		return this.selectedRequestText;
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