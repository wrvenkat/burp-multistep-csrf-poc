package org.multistepcsrfpoc.view;

import java.util.HashMap;
import java.awt.Dimension;
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
import javax.swing.event.ListSelectionListener;
import javax.swing.table.TableModel;
import javax.swing.JCheckBox;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;

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
	public static final String ALLOW_SCRIPTS_CHECKBOX = "allow scripts";
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
	private JCheckBox allowScriptsCheckBox;
	private JRadioButton newTabRadioButton;
	private JRadioButton iframeRadioButton;
	private JSeparator separator1;
	private JLabel pocOpensInLabel;
	private JSeparator separator2;
	private JLabel techniqueLabel;
	private JRadioButton xhrRadioButton;
	private JRadioButton formRadioButton;
	private JScrollPane csrfPOCScrollPane;
	private JSeparator separator3;
	private JCheckBox autoSubmitCheckBox;	
	private ButtonGroup pocOpenInGroup;
	private ButtonGroup techniqueButtonGroup;	

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
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.setPreferredSize(new Dimension(825,675));
		mainScrollPane = new JScrollPane(getMainPanel());
		frame.getContentPane().add(mainScrollPane);		
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
			
			//selected request text pane			
			mainPanel.add(getAllowScriptsCheckBox());
			mainPanel.add(getSeparator1());
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
			mainPanel.add(getXhrRadioButton());
			mainPanel.add(getRegenerateButton());
			mainPanel.add(getFormRadioButton());
			
			//CSRF POC text pane
			mainPanel.add(getCsrfPOCTextPane());
			mainPanel.add(getCopyHTMLButton());
			csrfPOCScrollPane = new JScrollPane(getCsrfPOCTextPane());
			csrfPOCScrollPane.setBounds(7, 371, 800, 242);
			mainPanel.add(csrfPOCScrollPane);
			mainPanel.add(getSeparator3());
			mainPanel.add(getAutoSubmitCheckBox());
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
			csrfPOCTextPane.setBounds(7, 371, 800, 242);
		}
		return csrfPOCTextPane;
	}
	private JButton getCopyHTMLButton() {
		if (copyHTMLButton == null) {
			copyHTMLButton = new JButton(COPY_HTML_BUTTON);
			copyHTMLButton.setBounds(364, 630, 117, 25);
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
	private JCheckBox getAllowScriptsCheckBox() {
		if (allowScriptsCheckBox == null) {
			allowScriptsCheckBox = new JCheckBox(ALLOW_SCRIPTS_CHECKBOX);
			allowScriptsCheckBox.setBounds(690, 155, 129, 23);
			buttons.put(ALLOW_SCRIPTS_CHECKBOX, allowScriptsCheckBox);
		}
		return allowScriptsCheckBox;
	}
	private JRadioButton getNewTabRadioButton() {
		if (newTabRadioButton == null) {
			newTabRadioButton = new JRadioButton(NEW_TAB_RADIOBUTTON);
			newTabRadioButton.setBounds(700, 200, 149, 23);
			buttons.put(NEW_TAB_RADIOBUTTON, newTabRadioButton);
		}
		return newTabRadioButton;
	}
	private JRadioButton getIframeRadioButton() {
		if (iframeRadioButton == null) {
			iframeRadioButton = new JRadioButton(IFRAME_RADIOBUTTON);
			iframeRadioButton.setBounds(700, 218, 149, 23);
			buttons.put(IFRAME_RADIOBUTTON, iframeRadioButton);
		}
		return iframeRadioButton;
	}
	private JSeparator getSeparator1() {
		if (separator1 == null) {
			separator1 = new JSeparator();
			separator1.setBounds(690, 180, 114, 2);
		}
		return separator1;
	}
	private JLabel getPocOpensInLabel() {
		if (pocOpensInLabel == null) {
			pocOpensInLabel = new JLabel("Response In:");
			pocOpensInLabel.setBounds(690, 185, 125, 15);
		}
		return pocOpensInLabel;
	}
	private JSeparator getSeparator2() {
		if (separator2 == null) {
			separator2 = new JSeparator();
			separator2.setBounds(690, 243, 114, 2);
		}
		return separator2;
	}
	private JLabel getTechniqueLabel() {
		if (techniqueLabel == null) {
			techniqueLabel = new JLabel("Technique:");
			techniqueLabel.setBounds(690, 249, 125, 15);
		}
		return techniqueLabel;
	}
	private JRadioButton getXhrRadioButton() {
		if (xhrRadioButton == null) {
			xhrRadioButton = new JRadioButton(XHR_RADIOBUTTON);
			xhrRadioButton.setBounds(700, 263, 149, 23);
			buttons.put(XHR_RADIOBUTTON, xhrRadioButton);
		}
		return xhrRadioButton;
	}
	private JRadioButton getFormRadioButton() {
		if (formRadioButton == null) {
			formRadioButton = new JRadioButton(FORM_RADIOBUTTON);
			formRadioButton.setBounds(700, 283, 149, 23);
			buttons.put(FORM_RADIOBUTTON, formRadioButton);
		}
		return formRadioButton;
	}
	private JSeparator getSeparator3() {
		if (separator3 == null) {
			separator3 = new JSeparator();
			separator3.setBounds(690, 307, 114, 2);
		}
		return separator3;
	}
	private JCheckBox getAutoSubmitCheckBox() {
		if (autoSubmitCheckBox == null) {
			autoSubmitCheckBox = new JCheckBox(AUTO_SUBMIT_CHECKBOX);
			autoSubmitCheckBox.setBounds(690, 311, 129, 23);
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
	
	//DONE: Implement the necessary methods that update the UI which can be called form the controller
	public int getSelectedRow() {
		return requestsTable.getSelectedRow();
	}
	
	public void setVisible() {
		this.frame.setVisible(true);		
	}
	
	//sets allow script radio button to true
	public void setAllowScript(Boolean value) {
		this.allowScriptsCheckBox.setSelected(value);
	}
	
	//sets allow script radio button to true
	public void setIframe(Boolean value) {
		this.iframeRadioButton.setSelected(value);
	}
	
	//sets allow script radio button to true
	public void setXhr(Boolean value) {
		this.xhrRadioButton.setSelected(value);
	}		
	
	//sets iframe radio button to true
	public void setAutoSubmit(Boolean value) {
		this.autoSubmitCheckBox.setSelected(value);
	}
	
	//sets the SelectedRequestTextPane
	public void setSelectedRequestText(String text) {
		if(text == null) return;
		selectedRequestTextPane.setText(text);
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
}