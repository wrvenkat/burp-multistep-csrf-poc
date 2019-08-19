package org.multistepcsrfpoc.model;

import java.util.ArrayList;
import java.util.HashMap;
import javax.swing.table.AbstractTableModel;

public class RequestsTableModel extends AbstractTableModel {	
	private static final long serialVersionUID = 1L;
	
	private static final int COLUMN_COUNT = 3;
	private static final String[] COLUMN_NAMES = {"No.", "Method", "Request URL"};
	private ArrayList<RequestModel> requests;
	private HashMap<Integer, Integer> rowToRequestNoMap;	
	
	public RequestsTableModel(ArrayList<RequestModel> requestList) {
		if(requestList != null && !requestList.isEmpty()) {
			this.requests = requestList;
			//initialize the row no to request no map 
			for(int index=1;index <= this.requests.size(); index++) {
				if(this.rowToRequestNoMap == null)
					this.rowToRequestNoMap = new HashMap<Integer, Integer>();				
				this.rowToRequestNoMap.put(index-1, index);
			}			
		}
		//otherwise empty rows
		else {
			this.requests = new ArrayList<RequestModel>();
			this.rowToRequestNoMap = new HashMap<Integer, Integer>();
		}
	}
	
	//gets the maximum request no from the rowToRequestNoMap
	private int getMaxRequestNo() {
		int currMax = 0;
		
		for(int value: this.rowToRequestNoMap.values()) {			
			if (value >= currMax)
				currMax = value;			
		}		
		return currMax+1;
	}
	
	//updates the row No to Request No map starting at the row
	//returns the last row index
	private int updateRowNoRequestMap(int row) {
		for(; row < requests.size(); row++) {			
			if(row + 1 < requests.size()) {
				rowToRequestNoMap.put(row, rowToRequestNoMap.get(row+1));
			}
		}
		return row-1;
	}
	
	/**
	 * Note that the next 4 methods in this model are also used to update the UI.
	 * 
	 * So, in this case, the model serves as the controller.
	 * */
	
	//removes a request
	public void removeRow(int row) {
		if (row < 0 || row >= requests.size())
			return;
		
		//update the row no to request no mapping and remove
		//the row returned by the row index returned		
		rowToRequestNoMap.remove(updateRowNoRequestMap(row));
		requests.remove(row);
		//fire off even that triggers the view to update
		fireTableRowsDeleted(row, row);
	}
	
	//adds a request
	public void addRow(RequestModel request) {
		//add the new request to the end
		requests.add(request);
		//update the rowToRequestNoMap
		int maxRequestNo = this.getMaxRequestNo();		
		int lastRow = requests.size()-1;
		//update the row No to Request No map
		rowToRequestNoMap.put(lastRow, maxRequestNo);
		//fire off even that triggers the view to update
		fireTableRowsInserted(lastRow, lastRow);
	}
	
	//moves a request up
	public Boolean moveRowUp(int row) {
		//System.out.println("Selected Row is "+row);
		
		if (row <= 0 || row > requests.size()-1) return false;
		
		RequestModel request = requests.remove(row);
		requests.add(row-1, request);
		
		//update the index map
		int currentRequestNo = rowToRequestNoMap.get(row);		
		rowToRequestNoMap.put(row, rowToRequestNoMap.get(row-1));
		rowToRequestNoMap.put(row-1, currentRequestNo);
		
		fireTableRowsUpdated(row-1,requests.size()-1);
		
		return true;
	}
	
	//moves a request down
	public Boolean moveRowDown(int row) {
		//System.out.println("Selected Row is "+row);
		
		if (row < 0 || row >= requests.size()-1) return false;
		
		RequestModel request = requests.remove(row);
		requests.add(row+1, request);
		
		//update the index map
		int currentRequestNo = rowToRequestNoMap.get(row);		
		rowToRequestNoMap.put(row, rowToRequestNoMap.get(row+1));
		rowToRequestNoMap.put(row+1, currentRequestNo);
		
		fireTableRowsUpdated(row,requests.size()-1);
		
		return true;
	}
	
	//returns the request associated with the request
	public byte[] getSelectedRequest(int row) {	
		if (row < 0 || row >= requests.size()) return null;
		return requests.get(row).getRequest();
	}
	
	//sets the request of the selected row	
	public void setSelectedRequest(int row, byte[] request) {
		if (row < 0 || row >= requests.size()) return;
				
		requests.get(row).setRequest(request);
	}
	
	//returns the column names	
	@Override
	public String getColumnName(int col) {
		return COLUMN_NAMES[col];
	}
	
	@Override
	public int getColumnCount() {
		return COLUMN_COUNT;
	}
	
	@Override
	public int getRowCount() {
		return requests.size();
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		int row = rowIndex;
		int column = columnIndex;
		
		//sanity check 1
		if(rowIndex >= requests.size()) return null;
		RequestModel request = requests.get(row);
		
		//sanity check 2
		if(request == null) return null;
		
		switch (column) {
			//request index column 
			case 0:
				return rowToRequestNoMap.get(rowIndex);
			//request method
			case 1:
				return request.getHttpMethod();
			//request URL
			case 2:
				return request.getUrl();
		}
		return null;
	}

	//returns the requests	
	public ArrayList<RequestModel> getRequests() {
		return requests;
	}
	
}