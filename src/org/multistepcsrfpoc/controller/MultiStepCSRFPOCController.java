package org.multistepcsrfpoc.controller;

import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

import javax.swing.JCheckBox;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClientInterface;
import org.multistepcsrfpoc.model.MultiStepCSRFPOCModel;
import org.multistepcsrfpoc.view.MultiStepCSRFPOCWindow;

/*
 *  Ideally the MultiStepCSRFPOCController must be an implementation of a defined interface
 *  that the UI expects. That way the contract is more explicit and readable.
 * 
 *  TODO: The above can be implemented when required.
 * */
public class MultiStepCSRFPOCController implements ActionListener, ListSelectionListener, WindowListener, DocumentListener {			
	private MultiStepCSRFPOCClientInterface client;
	private MultiStepCSRFPOCModel model;
	private MultiStepCSRFPOCWindow view;
	private int selectedRow;	
	
	private MultiStepCSRFPOCController() {		
	}
	
	/*Accepts a client and returns an instance*/
	public static MultiStepCSRFPOCController connect(MultiStepCSRFPOCModel model, MultiStepCSRFPOCWindow view, MultiStepCSRFPOCClientInterface client) {
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
		view.registerWindowListener(controller);		
	
		//initializes the UI based on default model values
		controller.initView();
		
		//also we select the first request if there is any such
		if(view.getRequestsTable().getModel().getValueAt(0, 2) != null) {
			view.highlightRow(0);
			model.setSelectedRequestText(new String(model.getSelectedRequest(0)));
			view.setSelectedRequestText(model.getSelectedRequestText());
		}
		
		//register the document listener last
		view.registerDocumentListener(controller);
		return controller;
	}
	
	/*
	 * Sets the default values for the View
	 * */
	public void initView() {
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
	
	public void updateMsgs(String msg) {
		if (msg != null)
			view.updateMsgs(msg);
	}
	
	/*
	 * Here comes the event listener method
	 * */	
	@Override
	public void actionPerformed(ActionEvent actionEvent) {
		String actionCommand = actionEvent.getActionCommand();
		
		//update the UI directly for msgs
		//view.updateMsgs("received event: "+actionEvent.toString()+"\n");
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
			model.setUseIframe(false);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.IFRAME_RADIOBUTTON) {
			model.setUseIframe(true);
			model.setUseNewTab(false);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.XHR_RADIOBUTTON) {
			model.setUseXhr(true);
			model.setUseForm(false);
			model.setUseJQuery(false);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.FORM_RADIOBUTTON) {
			model.setUseForm(true);
			model.setUseXhr(false);
			model.setUseJQuery(false);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.JQUERY_RADIOBUTTON) {
			model.setUseJQuery(true);
			model.setUseForm(false);
			model.setUseXhr(false);			
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.AUTO_SUBMIT_CHECKBOX) {
			JCheckBox checkBox = (JCheckBox)actionEvent.getSource();
			if(checkBox.isSelected())
				model.setAutoSubmit(true);
			else
				model.setAutoSubmit(false);
		}
		else if(actionCommand == MultiStepCSRFPOCWindow.REGENERATE_BUTTON) {
			String newCSRFPOC = client.regenerateClicked(model.getCsrfPOCConfig(), model.getRequests());
			model.setCsrfPOCText(newCSRFPOC);
			//update the UI
			view.setCSRFPOCText(model.getCsrfPOCText());
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
		selectedRow = view.getRequestsTable().getSelectedRow();
		if(selectedRow == -1) return;		
		
		//update the UI directly for msgs
		//view.updateMsgs("received event: "+event.toString()+"\n");		
				
		/*String currentRequestText = view.getSelectedRequestText();
		//update the requests model
		model.setSelectedRequest(selectedRow, currentRequestText.getBytes());*/
		//update the UI model
		model.setSelectedRequestText(new String(model.getSelectedRequest(selectedRow)));
		//update the view
		view.setSelectedRequestText(model.getSelectedRequestText());
	}

	public void windowClosing(WindowEvent e) {
		//inform our client that the window is closing
		System.out.println("Title: "+((Frame)(e.getWindow())).getTitle());
		this.client.csrfPOCWindowClosed(((Frame)(e.getWindow())).getTitle());
	}
	
	public void removeUpdate(DocumentEvent e) {		
		model.setSelectedRequest(selectedRow, view.getSelectedRequestText().getBytes());		
	}
	
	public void insertUpdate(DocumentEvent e) {		
		model.setSelectedRequest(selectedRow, view.getSelectedRequestText().getBytes());
	}
	
	/*Autogenerated stubs*/
	@Override
	public void windowActivated(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowClosed(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowDeactivated(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowDeiconified(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowIconified(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowOpened(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void changedUpdate(DocumentEvent e) {
		
	}
}
