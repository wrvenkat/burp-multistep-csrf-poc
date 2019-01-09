package org.multistepcsrfpoc.controller;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JCheckBox;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClient;
import org.multistepcsrfpoc.model.MultiStepCSRFPOCModel;
import org.multistepcsrfpoc.view.MultiStepCSRFPOCWindow;

/*
 *  Ideally the MultiStepCSRFPOCController must be an implementation of a defined interface
 *  that the UI expects. That way the contract is more explicit and readable.
 * 
 *  TODO: The above can be implemented when required.
 * */
public class MultiStepCSRFPOCController implements ActionListener, ListSelectionListener {			
	private MultiStepCSRFPOCClient client;
	private MultiStepCSRFPOCModel model;
	private MultiStepCSRFPOCWindow view;
	
	private MultiStepCSRFPOCController() {
		
	}
	
	/*Accepts a client and returns an instance*/
	public static MultiStepCSRFPOCController connect(MultiStepCSRFPOCModel model, MultiStepCSRFPOCWindow view, MultiStepCSRFPOCClient client) {
		if(client == null || model == null) return null;		
		MultiStepCSRFPOCController controller = new MultiStepCSRFPOCController();
		//connect to the model and client
		controller.client = client;
		controller.model = model;
		controller.view = view;

		//registers this class as the handler for the UI components
		view.registerHandler(controller);
		view.registerTableModel(model.getTableModel());
		view.registerRowSelectionListener(controller);
	
		//initializes the UI based on default model values
		controller.initView();
		
		//also we select the first request if there is any such
		if(view.getRequestsTable().getModel().getValueAt(0, 2) != null) {
			view.highlightRow(0);
			model.setSelectedRequestText(model.getSelectedRequest(0));
			view.setSelectedRequestText(model.getSelectedRequestText());
		}
		return controller;
	}
	
	/*
	 * Sets the default values for the View
	 * */
	public void initView() {
		if(model.isAllowScripts())
			view.setAllowScript(true);
		
		if(model.isUseIframe())
			view.setIframe(true);
		else
			view.setIframe(false);
		
		if(model.isUseXhr())
			view.setXhr(true);
		else
			view.setXhr(false);
		
		if(model.isAutoSubmit())
			view.setAutoSubmit(true);
		
		//set the text for the selected request text pane
		view.setSelectedRequestText(model.getSelectedRequestText());
		//set the text for the CSRF poc text pane
		view.setCSRFPOCText(model.getCsrfPOCText());
	}	
	
	/*
	 * Here comes the event listener method
	 * */	
	@Override
	public void actionPerformed(ActionEvent actionEvent) {
		String actionCommand = actionEvent.getActionCommand();
		
		if(actionCommand == MultiStepCSRFPOCWindow.UP_BUTTON) {
			int rowIndex = view.getSelectedRow();
			if(rowIndex > -1) {
				//move the selected row up
				if(model.moveRowUp(rowIndex))
					//update the view to hold the highlight onto the moved row				
					view.highlightRow(rowIndex-1);
			}
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.DOWN_BUTTON) {
			int rowIndex = view.getSelectedRow();
			if(rowIndex > -1) {
				//move the selected row down
				if(model.moveRowDown(rowIndex))
					//update the view to hold the highlight onto the moved row				
					view.highlightRow(rowIndex+1);
			}
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.REMOVE_BUTTON) {
			int rowIndex = view.getSelectedRow();
			if(rowIndex > -1) {
				//update the model
				model.removeRow(rowIndex);
				//update the model for the selected request
				model.setSelectedRequestText("");
				//update the UI
				view.setSelectedRequestText(model.getSelectedRequestText());
			}
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.NEW_TAB_RADIOBUTTON) {
			model.setUseNewTab(true);			
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.IFRAME_RADIOBUTTON) {
			model.setUseIframe(true);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.XHR_RADIOBUTTON) {
			model.setUseXhr(true);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.FORM_RADIOBUTTON) {
			model.setUseForm(true);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.ALLOWSCRIPTS_CHECKBOX) {
			JCheckBox checkBox = (JCheckBox)actionEvent.getSource();
			if(checkBox.isSelected())
				model.setAllowScripts(true);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.AUTOSUBMIT_CHECKBOX) {
			JCheckBox checkBox = (JCheckBox)actionEvent.getSource();
			if(checkBox.isSelected())
				model.setAutoSubmit(true);			
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.REGENERATE_BUTTON) {
			client.regenerateClicked(model.getCsrfPOCConfig(), model.getRequests());
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.COPY_HTML_BUTTON) {
			//update the model
			model.setCsrfPOCText(this.view.getCSRFPOCText());
			//return the selected value
			client.copyHTMLClicked(model.getCsrfPOCText());
		}
	}

	
	@Override
	public void valueChanged(ListSelectionEvent event) {
		int selectedRow = view.getRequestsTable().getSelectedRow();
		if(selectedRow == -1) return;
		
		//update the model
		model.setSelectedRequestText(model.getSelectedRequest(selectedRow));
		//update the view
		view.setSelectedRequestText(model.getSelectedRequestText());
	}	
}