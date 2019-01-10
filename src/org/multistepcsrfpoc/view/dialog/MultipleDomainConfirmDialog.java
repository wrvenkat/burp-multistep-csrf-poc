package org.multistepcsrfpoc.view.dialog;

import javax.swing.JOptionPane;

public class MultipleDomainConfirmDialog {
	public static final String DIALOG_MESSAGE = "Selected requests are for different domains."+"\n\t\t"+"Proceed with POC creation?";
	public static final String TITLE = "Confirm POC creation";
	
	public static int confirmMultipleDomainsDialog() {
		return JOptionPane.showConfirmDialog(null, DIALOG_MESSAGE, TITLE, JOptionPane.YES_NO_OPTION);
	}
}