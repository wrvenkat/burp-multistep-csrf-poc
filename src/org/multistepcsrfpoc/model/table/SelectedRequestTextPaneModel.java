package org.multistepcsrfpoc.model.table;

import javax.swing.text.Caret;

public class SelectedRequestTextPaneModel {
	/**
	 * Class that encapsulates the 'state' attribute for a text pane.
	 *
	 * Includes the text in the text pane and the caret object value.
	 * */

	private byte[] textByte;
	private final Caret caret;

	public SelectedRequestTextPaneModel(String textString, Caret caret) {
		if (textString == null)
			this.textByte = "".getBytes();
		else
			textByte = textString.getBytes();

		this.caret = caret;
	}

	public SelectedRequestTextPaneModel(byte[] textBytes, Caret caret) {
		if (textBytes == null)
			this.textByte = "".getBytes();
		else
			textByte = textBytes;

		this.caret = caret;
	}

	public byte[] getTextByte() {
		return textByte;
	}

	public Caret getCaret() {
		return caret;
	}

}
