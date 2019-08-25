package burp.contextmenu;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import org.multistepcsrfpoc.controller.client.MultiStepCSRFPOCClient;
import org.multistepcsrfpoc.model.request.RequestModel;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class MultiStepCSRFContextMenuHandler implements IContextMenuFactory, ActionListener, MouseListener{

	private static final String MAIN_MENU_NAME = "Generate Multi-Step CSRF POC";
	private static final String MENU_ITEM_MAIN_NAME = "Generate new Multi-Step CSRF POC";
	private static final String MENU_ITEM_DYNAMIC_NAME = "Add to existing POC";

	private boolean init_done = false;

	//extension helpers
	private final IBurpExtenderCallbacks burpCallbacks;

	//menu items
	private JMenu mainMenu = null;
	private JMenuItem mainMenuItem = null;
	private JMenu dynamicMenuItem = null;
	private List<JMenuItem> menuItems = null;

	//current state of seelctedMessages
	IHttpRequestResponse[] selectedMessages = null;

	public MultiStepCSRFContextMenuHandler(IBurpExtenderCallbacks callbacks) {
		this.burpCallbacks = callbacks;
		this.menuItems = new ArrayList<JMenuItem>();
	}

	private void initMenuItems() {
		if (this.init_done ==  true) return;
		//main menu
		this.mainMenu = new JMenu(MAIN_MENU_NAME);

		//submenu
		this.mainMenuItem = new JMenuItem(MENU_ITEM_MAIN_NAME);

		//dynamic submenu
		this.dynamicMenuItem = new JMenu(MENU_ITEM_DYNAMIC_NAME);

		//register handlers
		this.mainMenuItem.addActionListener(this);
		this.dynamicMenuItem.addMouseListener(this);

		//add main menu to menuItems
		this.menuItems.add(mainMenu);

		//initialized
		this.init_done = true;
	}

	private void removeMenuItems() {
		//reset the selectedMessages object
		this.selectedMessages = null;

		this.mainMenu.remove(this.mainMenuItem);
		this.mainMenu.remove(this.dynamicMenuItem);
		this.dynamicMenuItem.removeAll();
	}

	private void mainCreateMenuItems(IContextMenuInvocation invocation) {
		byte invocationContext = invocation.getInvocationContext();
		//save the selectedMessages list
		this.selectedMessages = invocation.getSelectedMessages();

		if (invocationContext == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocationContext == invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE ||
		    invocationContext == invocation.CONTEXT_MESSAGE_VIEWER_REQUEST || invocationContext == invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE ||
		    invocationContext == invocation.CONTEXT_INTRUDER_PAYLOAD_POSITIONS || invocationContext == invocation.CONTEXT_INTRUDER_ATTACK_RESULTS ||
		    invocationContext == invocation.CONTEXT_TARGET_SITE_MAP_TABLE || invocationContext == invocation.CONTEXT_PROXY_HISTORY) {
			if (selectedMessages.length > 1)
				this.mainMenu.add(this.mainMenuItem);
			if (selectedMessages.length >= 1)
				this.mainMenu.add(this.dynamicMenuItem);
		}
		return;
	}

	private void generateMultiStepCSRFPOC() {
		MultiStepCSRFPOCClient.getClient(this.burpCallbacks).createCSRFPOCWindow(this.getRequests());
	}

	private void createDynamicSubMenus() {
		Set<String> openPOCs = MultiStepCSRFPOCClient.getClient(this.burpCallbacks).getActivePOCs();
		this.dynamicMenuItem.removeAll();
		for (String title: openPOCs) {
			//add the new dynamic menu item
			JMenuItem dynamicItem = new JMenuItem(title);
			this.dynamicMenuItem.add(dynamicItem);
			//add action listeners
			dynamicItem.addActionListener(this);
		}

		return;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		this.initMenuItems();
		this.removeMenuItems();
		this.mainCreateMenuItems(invocation);
		return this.menuItems;
	}

	private ArrayList<RequestModel> getRequests() {
		ArrayList<RequestModel> requests = new ArrayList<RequestModel>();
		for (IHttpRequestResponse message: this.selectedMessages) {
			URL url = message.getUrl();
			byte[] request = message.getRequest();
			String method = this.burpCallbacks.getHelpers().analyzeRequest(request).getMethod();
			RequestModel requestModel = new RequestModel(method, url, message.getProtocol(), request);
			requests.add(requestModel);
		}
		return requests;
	}

	@Override
	public void mouseExited(MouseEvent e) {

	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getActionCommand().equals(MENU_ITEM_MAIN_NAME))
			this.generateMultiStepCSRFPOC();
		else if (e.getActionCommand().startsWith(MultiStepCSRFPOCClient.TITLE_STRING)) {
			System.out.println("Menu item clicked is "+e.getActionCommand());
			MultiStepCSRFPOCClient.getClient(this.burpCallbacks).addToPOC(e.getActionCommand(), this.getRequests());
		}
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		// TODO Auto-generated method stub
		//display the list of available windows
		this.createDynamicSubMenus();
	}

	@Override
	public void mousePressed(MouseEvent e) {
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		// TODO Auto-generated method stub
	}
}
