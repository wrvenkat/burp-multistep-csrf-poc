package org.multistepcsrfpoc.controller;

import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JCheckBox;
import javax.swing.JTextPane;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.UndoableEditEvent;
import javax.swing.event.UndoableEditListener;
import javax.swing.text.Caret;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.undo.CannotUndoException;
import javax.swing.undo.UndoManager;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClientInterface;
import org.multistepcsrfpoc.model.MultiStepCSRFPOCModel;
import org.multistepcsrfpoc.model.table.SelectedRequestTextPaneModel;
import org.multistepcsrfpoc.view.MultiStepCSRFPOCWindow;

public class MultiStepCSRFPOCController implements ActionListener, ListSelectionListener, WindowListener, DocumentListener, MouseListener, UndoableEditListener{
	private MultiStepCSRFPOCClientInterface client;
	private MultiStepCSRFPOCModel model;
	private MultiStepCSRFPOCWindow view;
	private int selectedRow;

	private final UndoAction undoAction;
	private final RedoAction redoAction;
	private final UndoManager csrfPOCTextPaneUndoManager;

	private MultiStepCSRFPOCController() {
		this.undoAction = new UndoAction();
		this.redoAction = new RedoAction();
		this.csrfPOCTextPaneUndoManager = new UndoManager();
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
		view.registerMouseEventListener(controller);

		//initializes the UI based on default model values
		controller.initView();

		//register the document listener last
		view.registerDocumentListener(controller);
		view.registerSelectedRequestPaneUndoListener(controller);
		view.registerCSRFPOCTextPaneUndoListener(controller);
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

		//also we select the first request if there is any such
		if(view.getRequestsTable().getModel().getValueAt(0, 2) != null) {
			view.highlightRow(0);
			model.setSelectedRequestText(new String(model.getSelectedRequest(0).getTextByte()));
			view.setSelectedRequestText(model.getSelectedRequest(0));
		}

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
				view.setSelectedRequestText(new SelectedRequestTextPaneModel(model.getSelectedRequestText(), null));
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
		else if(actionCommand == MultiStepCSRFPOCWindow.GENERATE_BUTTON) {
			String newCSRFPOC = client.generateClicked(model.getCsrfPOCConfig(), model.getRequests());
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
		else if(actionCommand == MultiStepCSRFPOCWindow.CLEAR_MSGS_BUTTON) {
			view.clearMSgs();
		}
	}

	public class UndoAction extends AbstractAction {
		private static final long serialVersionUID = 1L;

		public UndoAction() {
			super("Undo");
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			JTextPane textPane = (JTextPane)e.getSource();
			String sourceDocumentName = (String)textPane.getDocument().getProperty("name");
			UndoManager undoManager = null;
			if (sourceDocumentName.equals(view.SELECTED_REQUEST_DOCUMENT_NAME)) {
				undoManager = model.getSelectedRequestModel(selectedRow).getUndoManager();
			}
			else if (sourceDocumentName.equals(view.CSRF_POC_DOCUMENT_NAME)) {
				undoManager = csrfPOCTextPaneUndoManager;
			}

			try {
				undoManager.undo();
			}
			catch (CannotUndoException ex) {
				//System.out.println("Cannot undo last action!");
			}
			updateUndoState(undoManager);
			redoAction.updateRedoState(undoManager);
		}

		public void updateUndoState(UndoManager undoManager) {
			if (undoManager.canUndo()) {
                setEnabled(true);
                putValue(Action.NAME, undoManager.getUndoPresentationName());
            } else {
                setEnabled(false);
                putValue(Action.NAME, "Undo");
            }
		}
	}

	public class RedoAction extends AbstractAction{

		private static final long serialVersionUID = 1L;

		public RedoAction() {
			super("Redo");
			setEnabled(false);
		}

		@Override
		public void actionPerformed(ActionEvent e) {
			JTextPane textPane = (JTextPane)e.getSource();
			String sourceDocumentName = (String)textPane.getDocument().getProperty("name");
			UndoManager undoManager = null;

			if (sourceDocumentName.equals(view.SELECTED_REQUEST_DOCUMENT_NAME)) {
				undoManager = model.getSelectedRequestModel(selectedRow).getUndoManager();
			}
			else if (sourceDocumentName.equals(view.CSRF_POC_DOCUMENT_NAME)) {
				undoManager = csrfPOCTextPaneUndoManager;
			}

			try {
				undoManager.undo();
			}
			catch (CannotUndoException ex) {
				//System.out.println("Cannot undo last action!");
			}
			updateRedoState(undoManager);
			undoAction.updateUndoState(undoManager);
		}

		public void updateRedoState(UndoManager undoManager) {
			if (undoManager.canRedo()) {
                setEnabled(true);
                putValue(Action.NAME, undoManager.getRedoPresentationName());
            } else {
                setEnabled(false);
                putValue(Action.NAME, "Redo");
            }
		}
	}

	public UndoAction getUndoAction() {
		return undoAction;
	}

	public RedoAction getRedoAction() {
		return redoAction;
	}

	//listener to listen for when the table selection changes
	@Override
	public void valueChanged(ListSelectionEvent event) {
		selectedRow = view.getRequestsTable().getSelectedRow();
		if(selectedRow == -1) return;

		//update the UI directly for msgs
		//view.updateMsgs("received event: "+event.toString()+"\n");

		/*String currentRequestText = view.getSelectedRequestText();
		//update the requests model
		model.setSelectedRequest(selectedRow, currentRequestText.getBytes());*/

		view.adjustSelectedRequestTextScrollPaneScroll(false);
		//update the UI model
		model.setSelectedRequestText(new String(model.getSelectedRequest(selectedRow).getTextByte()));
		//update the view
		view.setSelectedRequestText(model.getSelectedRequest(selectedRow));
	}

	@Override
	public void windowClosing(WindowEvent e) {
		//inform our client that the window is closing
		//System.out.println("Title: "+((Frame)(e.getWindow())).getTitle());
		this.client.csrfPOCWindowClosed(((Frame)(e.getWindow())).getTitle());
	}

	@Override
	public void removeUpdate(DocumentEvent e) {
		byte[] textBytes = view.getSelectedRequestText().getBytes();
		Caret caret = view.getSelectedRequestPaneCaret();
		model.setSelectedRequest(selectedRow, new SelectedRequestTextPaneModel(textBytes, caret));
	}

	@Override
	public void insertUpdate(DocumentEvent e) {
		byte[] textBytes = view.getSelectedRequestText().getBytes();
		Caret caret = view.getSelectedRequestPaneCaret();
		model.setSelectedRequest(selectedRow, new SelectedRequestTextPaneModel(textBytes, caret));
	}

	@Override
	public void mousePressed(MouseEvent e) {
		view.adjustSelectedRequestTextScrollPaneScroll(true);
		/*byte[] textBytes = view.getSelectedRequestText().getBytes();
		Caret caret = view.getSelectedRequestPaneCaret();
		model.setSelectedRequest(selectedRow, new SelectedRequestTextPaneModel(textBytes, caret));*/
	}

	@Override
	public void undoableEditHappened(UndoableEditEvent e) {
		DefaultStyledDocument document = (DefaultStyledDocument)e.getSource();
		String sourceDocumentName = (String)document.getProperty("name");
		UndoManager undoManager = null;
		boolean proceed = true;

		if (sourceDocumentName.equals(this.view.SELECTED_REQUEST_DOCUMENT_NAME)) {
			if (selectedRow < 0)
				proceed = false;
			if (proceed)
				undoManager = this.model.getSelectedRequestModel(selectedRow).getUndoManager();
		}
		else if (sourceDocumentName.equals(this.view.CSRF_POC_DOCUMENT_NAME))
			undoManager = this.csrfPOCTextPaneUndoManager;

		if (proceed) {
			undoManager.addEdit(e.getEdit());
			undoAction.updateUndoState(undoManager);
			redoAction.updateRedoState(undoManager);
		}
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

	@Override
	public void mouseClicked(MouseEvent e) {
		// TODO Auto-generated method stub

	}

	@Override
	public void mouseEntered(MouseEvent e) {
		// TODO Auto-generated method stub

	}

	@Override
	public void mouseExited(MouseEvent e) {
		// TODO Auto-generated method stub

	}

	@Override
	public void mouseReleased(MouseEvent e) {
		// TODO Auto-generated method stub

	}

}
