package org.multistepcsrfpoc.view;

import java.util.HashMap;
import java.awt.Dimension;
import java.awt.Rectangle;
import java.awt.event.MouseListener;
import java.awt.event.WindowListener;

import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.AbstractButton;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JTextPane;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import javax.swing.text.BadLocationException;
import javax.swing.text.Caret;
import javax.swing.text.DefaultCaret;
import javax.swing.text.StyledDocument;
import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;
import org.multistepcsrfpoc.model.table.SelectedRequestTextPaneModel;

public class MultiStepCSRFPOCWindow {
	//public Button names
	public static final String COPY_HTML_BUTTON = "Copy HTML";
	public static final String UP_BUTTON = "Up";
	public static final String DOWN_BUTTON = "Down";
	public static final String REMOVE_BUTTON = "Remove";
	public static final String REGENERATE_BUTTON = "Regenerate";
	public static final String NEW_TAB_RADIOBUTTON = "new tab";
	public static final String IFRAME_RADIOBUTTON = "iframe";
	public static final String FORM_RADIOBUTTON = "form";
	public static final String XHR_RADIOBUTTON = "XHR";
	public static final String JQUERY_RADIOBUTTON = "jQuery";
	public static final String AUTO_SUBMIT_CHECKBOX = "auto submit";
	
	//carries the buttons for which we need to register
	//listeners for
	private HashMap<String, AbstractButton> buttons;
	private JFrame frame;
	private JPanel mainPanel;
	private JScrollPane mainScrollPane;
	private JScrollPane tableScrollPane;
	private JTable requestsTable;
	private JButton removeButton;
	private JLabel selectedRequestLabel;
	private JTextPane selectedRequestTextPane;
	private JScrollPane selectedRequestScrollPane;
	private JButton regenerateButton;
	private JLabel csrfPOCLabel;
	private JTextPane csrfPOCTextPane;
	private JButton copyHTMLButton;
	private JButton upButton;
	private JButton downButton;
	private JRadioButton newTabRadioButton;
	private JRadioButton iframeRadioButton;
	private JLabel pocOpensInLabel;
	private JSeparator separator2;
	private JLabel techniqueLabel;
	private JRadioButton xhrRadioButton;
	private JRadioButton formRadioButton;
	private JRadioButton jqueryRadioButton;
	private JScrollPane csrfPOCScrollPane;
	private JSeparator separator3;
	private JCheckBox autoSubmitCheckBox;	
	private ButtonGroup pocOpenInGroup;
	private ButtonGroup techniqueButtonGroup;	
	private JScrollPane msgsScrollPane;
	private JTextPane txtpnMsgs;

	/**
	 * Create the application window.
	 */
	public MultiStepCSRFPOCWindow(String title) {
		initialize(title);
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize(String title) {
		this.buttons = new HashMap<String, AbstractButton>();
		frame = new JFrame();
		frame.setTitle(title);
		frame.setBounds(100, 100, 825, 675);
		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		frame.setPreferredSize(new Dimension(825,675));
		frame.setMaximizedBounds(new Rectangle(new Dimension(825,675)));
		mainScrollPane = new JScrollPane(getMainPanel());
		frame.getContentPane().add(mainScrollPane);
		this.getRequestsTable().getSelectionModel().setValueIsAdjusting(true);
	}
	
	private JPanel getMainPanel() {
		if (mainPanel == null) {
			mainPanel = new JPanel();
			mainPanel.setPreferredSize(new Dimension(800, 650));
			mainPanel.setLayout(null);
			
			//Requests Table								
			tableScrollPane = new JScrollPane(getRequestsTable());
			tableScrollPane.setBounds(7, 7, 676, 118);
			mainPanel.add(tableScrollPane);
			
			//Buttons						
			mainPanel.add(getRemoveButton());
			mainPanel.add(getUpButton());
			mainPanel.add(getDownButton());
			mainPanel.add(getSelectedRequestLabel());			
			mainPanel.add(getCsrfPOCLabel());
			mainPanel.add(getPocOpensInLabel());
			selectedRequestScrollPane = new JScrollPane(getSelectedRequestTextPane());
			selectedRequestScrollPane.setBounds(7, 159, 676, 188);
			mainPanel.add(selectedRequestScrollPane);
			
			//button groups
			pocOpenInGroup = new ButtonGroup();
			pocOpenInGroup.add(getNewTabRadioButton());
			pocOpenInGroup.add(getIframeRadioButton());			
			mainPanel.add(getNewTabRadioButton());
			mainPanel.add(getIframeRadioButton());
			mainPanel.add(getSeparator2());
			mainPanel.add(getTechniqueLabel());
			techniqueButtonGroup = new ButtonGroup();
			techniqueButtonGroup.add(getXhrRadioButton());
			techniqueButtonGroup.add(getFormRadioButton());
			techniqueButtonGroup.add(getJqueryRadioButton());
			mainPanel.add(getXhrRadioButton());
			mainPanel.add(getFormRadioButton());
			mainPanel.add(getJqueryRadioButton());
			mainPanel.add(getSeparator3());
			mainPanel.add(getAutoSubmitCheckBox());
			mainPanel.add(getRegenerateButton());
			
			//CSRF POC text pane
			//mainPanel.add(getCsrfPOCTextPane());
			mainPanel.add(getCopyHTMLButton());
			csrfPOCScrollPane = new JScrollPane(getCsrfPOCTextPane());
			csrfPOCScrollPane.setBounds(7, 371, 800, 235);
			mainPanel.add(csrfPOCScrollPane);
			
			//MSGS text pane
			msgsScrollPane = new JScrollPane(getTxtpnMsgs());
			msgsScrollPane.setBounds(7, 610, 675, 55);
			mainPanel.add(msgsScrollPane);
		}
		return mainPanel;
	}
	private JLabel getSelectedRequestLabel() {
		if (selectedRequestLabel == null) {
			selectedRequestLabel = new JLabel("Selected Request:");
			selectedRequestLabel.setBounds(7, 137, 182, 15);
		}
		return selectedRequestLabel;
	}
	private JTextPane getSelectedRequestTextPane() {
		if (selectedRequestTextPane == null) {
			selectedRequestTextPane = new JTextPane();
			selectedRequestTextPane.setText("HTML");
			selectedRequestTextPane.setBounds(7, 159, 676, 188);
		}
		
		return selectedRequestTextPane;
	}
	private JButton getRegenerateButton() {
		if (regenerateButton == null) {
			regenerateButton = new JButton(REGENERATE_BUTTON);
			regenerateButton.setBounds(690, 336, 118, 25);
			buttons.put(REGENERATE_BUTTON, regenerateButton);
		}
		return regenerateButton;
	}
	private JButton getRemoveButton() {
		if (removeButton == null) {
			removeButton = new JButton(REMOVE_BUTTON);
			removeButton.setBounds(705, 16, 89, 25);
			buttons.put(REMOVE_BUTTON, removeButton);
		}
		return removeButton;
	}
	private JLabel getCsrfPOCLabel() {
		if (csrfPOCLabel == null) {
			csrfPOCLabel = new JLabel("CSRF POC:");
			csrfPOCLabel.setBounds(7, 352, 89, 15);
		}
		return csrfPOCLabel;
	}
	private JTextPane getCsrfPOCTextPane() {
		if (csrfPOCTextPane == null) {
			csrfPOCTextPane = new JTextPane();
			csrfPOCTextPane.setText("CSRF POC");
			csrfPOCTextPane.setBounds(7, 371, 800, 235);
		}
		return csrfPOCTextPane;
	}
	private JButton getCopyHTMLButton() {
		if (copyHTMLButton == null) {
			copyHTMLButton = new JButton(COPY_HTML_BUTTON);
			copyHTMLButton.setBounds(690, 630, 117, 25);
			buttons.put(COPY_HTML_BUTTON, copyHTMLButton);
		}		
		return copyHTMLButton;
	}
	private JButton getUpButton() {
		if (upButton == null) {
			upButton = new JButton(UP_BUTTON);
			upButton.setBounds(705, 54, 89, 25);
			buttons.put(UP_BUTTON, upButton);
		}
		return upButton;
	}
	private JButton getDownButton() {
		if (downButton == null) {
			downButton = new JButton("Down");
			downButton.setBounds(705, 92, 89, 25);
			buttons.put(DOWN_BUTTON, downButton);
		}
		return downButton;
	}
	private JRadioButton getNewTabRadioButton() {
		if (newTabRadioButton == null) {
			newTabRadioButton = new JRadioButton(NEW_TAB_RADIOBUTTON);
			newTabRadioButton.setBounds(700, 170, 149, 23);
			buttons.put(NEW_TAB_RADIOBUTTON, newTabRadioButton);
		}
		return newTabRadioButton;
	}
	private JRadioButton getIframeRadioButton() {
		if (iframeRadioButton == null) {
			iframeRadioButton = new JRadioButton(IFRAME_RADIOBUTTON);
			iframeRadioButton.setBounds(700, 188, 149, 23);
			buttons.put(IFRAME_RADIOBUTTON, iframeRadioButton);
		}
		return iframeRadioButton;
	}
	private JLabel getPocOpensInLabel() {
		if (pocOpensInLabel == null) {
			pocOpensInLabel = new JLabel("Response In:");
			pocOpensInLabel.setBounds(690, 155, 125, 15);
		}
		return pocOpensInLabel;
	}
	private JSeparator getSeparator2() {
		if (separator2 == null) {
			separator2 = new JSeparator();
			separator2.setBounds(690, 218, 114, 2);
		}
		return separator2;
	}
	private JLabel getTechniqueLabel() {
		if (techniqueLabel == null) {
			techniqueLabel = new JLabel("Technique:");
			techniqueLabel.setBounds(690, 223, 125, 15);
		}
		return techniqueLabel;
	}
	private JRadioButton getXhrRadioButton() {
		if (xhrRadioButton == null) {
			xhrRadioButton = new JRadioButton(XHR_RADIOBUTTON);
			xhrRadioButton.setBounds(700, 237, 149, 23);
			buttons.put(XHR_RADIOBUTTON, xhrRadioButton);
		}
		return xhrRadioButton;
	}
	private JRadioButton getFormRadioButton() {
		if (formRadioButton == null) {
			formRadioButton = new JRadioButton(FORM_RADIOBUTTON);
			formRadioButton.setBounds(700, 257, 149, 23);
			buttons.put(FORM_RADIOBUTTON, formRadioButton);
		}
		return formRadioButton;
	}
	private JRadioButton getJqueryRadioButton() {
		if (jqueryRadioButton == null) {
			jqueryRadioButton = new JRadioButton(JQUERY_RADIOBUTTON);
			jqueryRadioButton.setBounds(700, 277, 149, 23);
			buttons.put(JQUERY_RADIOBUTTON, jqueryRadioButton);
			
		}
		return jqueryRadioButton;
	}	
	private JSeparator getSeparator3() {
		if (separator3 == null) {
			separator3 = new JSeparator();
			separator3.setBounds(690, 302, 114, 2);
		}
		return separator3;
	}
	private JCheckBox getAutoSubmitCheckBox() {
		if (autoSubmitCheckBox == null) {
			autoSubmitCheckBox = new JCheckBox(AUTO_SUBMIT_CHECKBOX);
			autoSubmitCheckBox.setBounds(690, 306, 129, 23);
			buttons.put(AUTO_SUBMIT_CHECKBOX, autoSubmitCheckBox);
		}
		return autoSubmitCheckBox;
	}
	public JTable getRequestsTable() {
		if(requestsTable == null) {
			requestsTable = new JTable();
			requestsTable.setBounds(7, 7, 676, 118);
			requestsTable.setPreferredSize(new Dimension(676, 118));
			
			//set the selection mode to Single Interval selection which only allows
			//contiguous rows selection
			requestsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);			
		}
		
		return requestsTable;
	}
	
	/**
	 * Method is used to register listeners for the UI
	 * */
	public void registerHandler(MultiStepCSRFPOCController controller) {
		for (AbstractButton button: buttons.values()) {
			button.addActionListener(controller);
		}
	}
	
	//registers the TableModel
	public void registerTableModel(TableModel tableModel) {
		requestsTable.setModel(tableModel);
		//once the model is set, we set the constraints
		requestsTable.getColumnModel().getColumn(0).setMaxWidth(35);
		requestsTable.getColumnModel().getColumn(1).setMaxWidth(100);		
	}
	
	//registers the ListSelectionListener
	public void registerRowSelectionListener(ListSelectionListener listener) {
		if(listener != null)
			this.getRequestsTable().getSelectionModel().addListSelectionListener(listener);
	}
	
	//registers windowListener
	public void registerWindowListener(WindowListener listener) {
		if (listener != null)
			this.frame.addWindowListener(listener);
	}
	
	public void registerDocumentListener(DocumentListener listener) {
		if (listener != null)
			this.selectedRequestTextPane.getDocument().addDocumentListener(listener);
	}
	
	public void registerMouseEventListener(MouseListener listener) {
		this.selectedRequestTextPane.addMouseListener(listener);
	}
	
	//DONE: Implement the necessary methods that update the UI which can be called form the controller
	public int getSelectedRow() {
		return requestsTable.getSelectedRow();
	}
	
	public void setVisible() {
		this.frame.setVisible(true);		
	}		
	
	public void setIframe(Boolean value) {
		this.iframeRadioButton.setSelected(value);
	}
		
	public void setXhr(Boolean value) {
		this.xhrRadioButton.setSelected(value);
	}
	
	public void setJQuery(Boolean value) {
		this.jqueryRadioButton.setSelected(value);
	}
	
	//sets iframe radio button to true
	public void setAutoSubmit(Boolean value) {
		this.autoSubmitCheckBox.setSelected(value);
	}
	
	//sets the SelectedRequestTextPane
	public void setSelectedRequestText(SelectedRequestTextPaneModel paneStatus) {
		if(paneStatus == null) return;		
		selectedRequestTextPane.setText(new String(paneStatus.getTextByte()));
		if (paneStatus.getCaret() != null)
			selectedRequestTextPane.setCaret(paneStatus.getCaret());
	}
	
	//highlights the row at index row
	public void highlightRow(int rowIndex) {
		requestsTable.setRowSelectionInterval(rowIndex, rowIndex);
	}
	
	//gets the SelectedRequestTextPane
	public String getSelectedRequestText() {
		return selectedRequestTextPane.getText();
	}
	
	//sets the CSRFPOCTextPane
	public void setCSRFPOCText(String text) {
		if(text == null) return;
		csrfPOCTextPane.setText(text);
	}
	
	//gets the SelectedRequestTextPane
	public String getCSRFPOCText() {
		return csrfPOCTextPane.getText();
	}
	
	private JTextPane getTxtpnMsgs() {
		if (txtpnMsgs == null) {
			txtpnMsgs = new JTextPane();
			txtpnMsgs.setText("msgs\n");
			txtpnMsgs.setBounds(7, 610, 675, 54);
		}
		return txtpnMsgs;
	}
	
	public Caret getSelectedRequestPaneCaret() {
		return selectedRequestTextPane.getCaret();
	}
	
	public void adjustSelectedRequestTextScrollPaneScroll(boolean allowScroll) {
		DefaultCaret caret = (DefaultCaret) selectedRequestTextPane.getCaret();
		
		if (allowScroll)
			caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		else if (!allowScroll)
			caret.setUpdatePolicy(DefaultCaret.NEVER_UPDATE);
	}
	
	public void updateMsgs(String msg) {
		if (msg == null) return;
		
		msg += "\n";
		StyledDocument document = (StyledDocument) txtpnMsgs.getDocument();
	    try {
			document.insertString(document.getLength(), msg, null);
		} catch (BadLocationException e) {
			e.printStackTrace();			
		}
	}	
}