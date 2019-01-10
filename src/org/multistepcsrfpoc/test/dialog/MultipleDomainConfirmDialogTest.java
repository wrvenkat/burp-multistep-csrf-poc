package org.multistepcsrfpoc.test.dialog;

import org.multistepcsrfpoc.view.dialog.MultipleDomainConfirmDialog;

public class MultipleDomainConfirmDialogTest {
	public static void main(String args[]) {
		int option = MultipleDomainConfirmDialog.confirmMultipleDomainsDialog();
		System.out.println("Opetion selected is "+option);
	}
}