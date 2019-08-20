package org.multistepcsrfpoc.main;

import java.awt.EventQueue;
import java.util.ArrayList;

import org.multistepcsrfpoc.controller.MultiStepCSRFPOCController;
import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClientInterface;
import org.multistepcsrfpoc.model.MultiStepCSRFPOCModel;
import org.multistepcsrfpoc.model.config.CSRFPOCConfigModel;
import org.multistepcsrfpoc.model.request.RequestModel;
import org.multistepcsrfpoc.model.table.RequestsTableModel;
import org.multistepcsrfpoc.view.MultiStepCSRFPOCWindow;

public class MultiStepCSRFPOC {
	private MultiStepCSRFPOCWindow view;
	private MultiStepCSRFPOCModel model;
	
	public MultiStepCSRFPOC(String title, ArrayList<RequestModel> requestList, MultiStepCSRFPOCClientInterface client) {
		this.view = new MultiStepCSRFPOCWindow(title);		
		this.model = new MultiStepCSRFPOCModel(new RequestsTableModel(requestList), new CSRFPOCConfigModel());
		//connect the controller with the model and the client
		MultiStepCSRFPOCController controller = MultiStepCSRFPOCController.connect(model, view, client);
		client.setController(controller);
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
	
	public void addToPOC(ArrayList<RequestModel> requests) {
		for (RequestModel request: requests)
			this.model.addRow(request);
	}

}