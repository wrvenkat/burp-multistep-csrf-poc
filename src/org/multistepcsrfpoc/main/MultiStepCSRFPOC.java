package org.multistepcsrfpoc.main;

import java.awt.EventQueue;
import java.util.ArrayList;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;
import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClient;
import org.multistepcsrfpoc.model.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.MultiStepCSRFPOCModel;
import org.multistepcsrfpoc.model.RequestModel;
import org.multistepcsrfpoc.model.RequestsTableModel;
import org.multistepcsrfpoc.view.MultiStepCSRFPOCWindow;

public class MultiStepCSRFPOC {
	private MultiStepCSRFPOCWindow view;
	private MultiStepCSRFPOCModel model;	
	
	public MultiStepCSRFPOC(String title, ArrayList<RequestModel> requestList, MultiStepCSRFPOCClient client) {
		this.view = new MultiStepCSRFPOCWindow(title);
		this.model = new MultiStepCSRFPOCModel(new RequestsTableModel(requestList), new CSRFPOCConfigModel());
		//connect the controller with the model and the client
		MultiStepCSRFPOCController.connect(model, view, client);
		MultiStepCSRFPOC.showUI(this.view);
	}
	
	private static void showUI(final MultiStepCSRFPOCWindow view) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {					
					view.setVisible();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
}