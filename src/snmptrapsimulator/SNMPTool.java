/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package snmptrapsimulator;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author Mark Fieldhouse - MafitConsulting 
 */
import java.awt.HeadlessException;
import java.util.*; 
import java.awt.event.KeyListener;
import java.awt.KeyboardFocusManager;
import java.awt.event.*;
import java.io.IOException;
import javax.swing.border.Border;
import javax.swing.*; 
import org.snmp4j.*; 
import org.snmp4j.security.*;
import org.snmp4j.mp.*;
import org.snmp4j.transport.*;
import org.snmp4j.smi.*;




public final class SNMPTool extends JFrame  
{		static String v1 = "v1";
		static String v2 = "v2";
		static String v3 = "v3";
		String srvName = new String();
		String jselect = new String();
		String ipAddress = new String();
		JLabel[] varba = new JLabel[10];
		JLabel[] varbb = new JLabel[10];
		JTextField[] varbind = new JTextField[20];
		JTextField OID = new JTextField();
		JTextField SpecOID = new JTextField();
		JTextField portfield = new JTextField("162");
		JTextField communityfield = new JTextField("public");
		JTextField user = new JTextField("MD5DES");	
		JPasswordField password = new JPasswordField();
		boolean IsFieldMasked = password.echoCharIsSet();
		char c = password.getEchoChar();
		JRadioButton v1button = new JRadioButton(v1);
		JRadioButton v2button = new JRadioButton(v2);
		JRadioButton v3button = new JRadioButton(v3);
		String port = portfield.getText();
		ArrayList<JTextField> tfList = new ArrayList<>();
		ArrayList<JTextField> vbList = new ArrayList<>();
		ArrayList<JTextField> paylist = new ArrayList<>();
		static final JLabel v3usrlbl = new JLabel("<html>SNMPv3<br/>Username:</html>");
		static final JLabel v3pwdlbl = new JLabel("<html>SNMPv3<br/>Password:</html>");
		KeyboardFocusManager manager = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		
		
		
		
		public SNMPTool()  {
		
			// initialise and create gui interface
			createSwingInterface();	
	    
		}
	
	
		// Key Listener, needed to add this to combat screwy tab key
		// entry when jtextfields are created in a for loop	
		
		class MyKeyListener implements KeyListener{
		
			JTextField jtf;
			MyKeyListener(JTextField jtf) {   
                        this.jtf = jtf; }  

                        @Override
			public void keyPressed(KeyEvent arg0) {
					if (arg0.getKeyCode() == KeyEvent.VK_TAB) {
						manager.focusNextComponent();
							}
					} 
					
                        @Override
			public void keyReleased(KeyEvent k) {} // abstract override
         
                        @Override
			public void keyTyped(KeyEvent arg0) {} // abstract override 
					
		}
			
		
		class RadioListener implements ActionListener{
                                        @Override
					public void actionPerformed(ActionEvent e) {
			
						if (e.getActionCommand().equals(v1)) {
								jselect = e.getActionCommand();
								disablement();
						} 
						else 
						if (e.getActionCommand().equals(v2)) {
								jselect = e.getActionCommand();
								disablement();
						}
						else {
								jselect = e.getActionCommand();
								v3usrlbl.setVisible(true);
								v3pwdlbl.setVisible(true);
								user.setVisible(true);
								password.setVisible(true);
								communityfield.setText("");
								communityfield.setEditable(false);
						}
				}
			}


	
		class ItemHandler implements ActionListener{
                                @Override
				public void actionPerformed(ActionEvent e) {
					JComboBox cb = (JComboBox)e.getSource();
                                        cb.setSelectedIndex(2);
					srvName = (String)cb.getSelectedItem();
                                    switch (srvName) {
                                        case "tcemogwyw02":
                                            ipAddress = "172.28.237.6";
                                            break;
                                        case "tcemugwyw02":
                                            ipAddress = "172.28.236.5";
                                        default:
                                            ipAddress = srvName;
                                            break;
                                    }
										
						
						   
							
					}
			}
		
		class ButtonListener implements ActionListener {
				ButtonListener() {
			}
                                @Override
				public void actionPerformed(ActionEvent e) {
                                    switch (e.getActionCommand()) {
                                        case "Execute":
                                            execute();
                                            break;
                                        case "Clear":
                                            clear();
                                            break;
                                        case "Quit":
                                            System.exit(0);
                                    }
				
			}
		}
 
		public void execute()
		{	
			if (jselect.equals(v2)){
				sendSnmpV2Trap();}
			
			else
			if (jselect.equals(v3)){
				sendSnmpV3Trap();
				password.setText("");}
		
			else
				{sendSnmpV1Trap();}
		}
		
	
		public void sendSnmpV1Trap()
		{
			try {
		
				String trapOID = OID.getText();
				String community = communityfield.getText();
				int st = Integer.parseInt(SpecOID.getText());
			
			
				// Create Transport Mapping
				TransportMapping<?> transport = new DefaultUdpTransportMapping();
				transport.listen();


				// Create Target
				CommunityTarget comtarget = new CommunityTarget();
				comtarget.setCommunity(new OctetString(community));
				comtarget.setVersion(SnmpConstants.version1);
				comtarget.setAddress(new UdpAddress(ipAddress + "/" + port));
				comtarget.setRetries(2);
				comtarget.setTimeout(5000);


				// Create PDU for V1
				PDUv1 pdu = new PDUv1();
				pdu.setType(PDU.V1TRAP);
				pdu.setEnterprise(new OID(trapOID));
				pdu.setGenericTrap(PDUv1.ENTERPRISE_SPECIFIC);
				pdu.setSpecificTrap(st);
				pdu.setAgentAddress(new IpAddress(ipAddress));
				long sysUpTime = 111111;
				pdu.setTimestamp(sysUpTime);
			
				
				for (JTextField jtf : vbList) {
					//System.out.println(jtf.getText());
					pdu.add(new VariableBinding(new OID(trapOID), new OctetString(jtf.getText())));
				}
			
				Snmp snmp = new Snmp(transport);
				//System.out.println("Sending V1 Trap to " + ipAddress + " on Port " + port);
				snmp.send(pdu, comtarget);
				snmp.close();
				JOptionPane.showMessageDialog(null,"Trap Sent");
			
				// Send the PDU
			
			} catch (NumberFormatException | IOException | HeadlessException e) {
				//System.err.println("Error in Sending V1 Trap to " + ipAddress + " on Port " + port);
				//System.err.println("Exception Message = " + e.getMessage());
				JOptionPane.showMessageDialog(null,"problem sending trap.","Trap error",JOptionPane.ERROR_MESSAGE);
		
			}
		}

	
	
		public void sendSnmpV2Trap()
		{
			try {
				// Create Transport Mapping
				TransportMapping<?> transport = new DefaultUdpTransportMapping();
				transport.listen();
				String trapOID =  OID.getText() + "." + SpecOID.getText();
				String community = communityfield.getText();
			
			

				// Create Target
				CommunityTarget comtarget = new CommunityTarget();
				comtarget.setCommunity(new OctetString(community));
				comtarget.setVersion(SnmpConstants.version2c);
				comtarget.setAddress(new UdpAddress(ipAddress + "/" + port));
				comtarget.setRetries(2);
				comtarget.setTimeout(5000);

				// Create PDU for V2
				PDU pdu = new PDU();
				pdu.setType(PDU.TRAP);

				// need to specify the system up time
				long sysUpTime = 111111;
				pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(sysUpTime)));
				pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID, new OID(trapOID)));
				pdu.add(new VariableBinding(SnmpConstants.snmpTrapAddress, new IpAddress(ipAddress)));
			
			
				
                            //Testing purpose
                            //int value = paylist.size();
                            //System.out.println("Size: "+value);
                            vbList.stream().forEach((jtf) -> {
                                pdu.add(new VariableBinding(new OID(trapOID), new OctetString(jtf.getText())));
                            });


				// Send the PDU
		 		Snmp snmp = new Snmp(transport);
				snmp.send(pdu, comtarget);
				snmp.close();
				JOptionPane.showMessageDialog(null,"Trap Sent");
			} catch (IOException | HeadlessException e) {
			//System.err.println("Error in Sending V2 Trap to " + ipAddress + " on Port " + port);
			//System.err.println("Exception Message = " + e.getMessage());
				JOptionPane.showMessageDialog(null,"problem sending trap.","Trap error",JOptionPane.ERROR_MESSAGE);
			}
		}
	
		public void sendSnmpV3Trap() 
		{
			try {
				long start = System.currentTimeMillis();
				String trapOID = OID.getText();
				Address targetAddress = GenericAddress.parse("udp:" + ipAddress + "/" + port);
				password.setEchoChar('*');
				char[] passwd = password.getPassword();
				String username =  user.getText();
			
				// Create Transport Mapping
				TransportMapping<?> transport = new DefaultUdpTransportMapping();
				Snmp snmp = new Snmp(transport);
				USM usm = new USM(SecurityProtocols.getInstance(), new OctetString(MPv3.createLocalEngineID()), 0);
				SecurityModels.getInstance().addSecurityModel(usm);
				transport.listen();

				// Add SNMP USM User
				snmp.getUSM().addUser(new OctetString(username), new UsmUser(new OctetString(username), null, null, null,null));

				// Create Target
				UserTarget target = new UserTarget();
				target.setAddress(targetAddress);
				target.setRetries(1);

				// set timeout
				target.setTimeout(11500);
				target.setVersion(SnmpConstants.version3);
				target.setSecurityLevel(SecurityLevel.NOAUTH_NOPRIV);
				target.setSecurityName(new OctetString(username));

				// Create PDU for V3
				ScopedPDU pdu = new ScopedPDU();
				pdu.setType(ScopedPDU.NOTIFICATION);


				// need to specify the system up time
				long sysUpTime = (System.currentTimeMillis() - start) / 10;
				pdu.add(new VariableBinding(SnmpConstants.sysUpTime, new TimeTicks(sysUpTime)));
				pdu.add(new VariableBinding(SnmpConstants.snmpTrapOID,SnmpConstants.linkDown));
				pdu.add(new VariableBinding(new OID(trapOID),new Integer32(1)));
			
				// Lets map our varbinds from user input
				for (JTextField jtf : vbList) {
						//System.out.println(jtf.getText());
					pdu.add(new VariableBinding(new OID(trapOID), new OctetString(jtf.getText())));
				}


				// Send the PDU
				//System.out.println("Sending V3 Trap to " + ipAddress + " on Port " + port + "for OID: " + trapOID);
				snmp.send(pdu, target);
				snmp.addCommandResponder(new CommandResponder() {
					@Override
					public void processPdu(CommandResponderEvent arg0) {
						System.out.println(arg0);
					}
				});
				snmp.close();
			} catch (Exception e) {
				JOptionPane.showMessageDialog(null,"problem sending trap.","Trap error",JOptionPane.ERROR_MESSAGE);
				//System.err.println("Error in Sending V3 Trap to " + ipAddress + " on Port " + port );
				//System.err.println("Exception Message = " + e.getMessage());
			}
		}
	
		public void clear()
		{
                    tfList.stream().forEach((tf) -> {
                        tf.setText("");
                    }); 	
		}
	
		
	
	
		public void disablement()
		{
			v3usrlbl.setVisible(false);
			v3pwdlbl.setVisible(false);
			user.setVisible(false);
			password.setVisible(false);
			communityfield.setEditable(true);
			communityfield.setText("public");
			
		}
		
		public void createSwingInterface()
		{
			setTitle("SNMP Trap Simulater");
			setSize(300,300); 
			JTabbedPane jtp = new JTabbedPane();
			
			getContentPane().add(jtp);
			
			JPanel jp1 = new JPanel();
			JPanel jp2 = new JPanel();
			JPanel jp3 = new JPanel();
			JPanel jp4 = new JPanel();
			
			jp1.setLayout(null);
			jp2.setLayout(null);
			jp3.setLayout(null);
			jp4.setLayout(null);
		 
	
			jtp.addTab("Server", jp1);
			jtp.addTab("Config", jp2);
			jtp.addTab("VarBinds", jp3);
			jtp.addTab("VarBinds", jp4);
			
			// Nice textfield border
			Border border = BorderFactory.createLoweredBevelBorder();
	

			// Labels for Server TAB
			JLabel label1 = new JLabel("Server:");
			label1.setLocation(0, 10);
			label1.setSize(50, 40);
			label1.setHorizontalAlignment(JLabel.LEFT);
			jp1.add(label1);
		
			JLabel label2 = new JLabel("Port:");
			label2.setLocation(0, 60);
			label2.setSize(38, 50);
			label2.setHorizontalAlignment(JLabel.LEFT);
			jp1.add(label2);
		
			JLabel label3 = new JLabel("<html>Community<br/>String:</html>");
			label3.setLocation(0, 115);
			label3.setSize(70, 70);
			label3.setHorizontalAlignment(JLabel.LEFT);
			jp1.add(label3);
			
			// Labels for Config TAB
			JLabel label4 = new JLabel("OID:");
			label4.setLocation(0, 10);
			label4.setSize(50, 40);
			label4.setHorizontalAlignment(JLabel.LEFT);
			jp2.add(label4);
		
			JLabel label5 = new JLabel("SNMP:");
			label5.setLocation(0, 50);
			label5.setSize(50, 40);
			label5.setHorizontalAlignment(JLabel.LEFT);
			jp2.add(label5);
			
			JLabel spec = new JLabel("Specific:");
			spec.setLocation(0, 90);
			spec.setSize(50, 40);
			spec.setHorizontalAlignment(JLabel.LEFT);
			jp2.add(spec);
			
			// VarBinds TAB A Labels
			
			int inclbltab1 = 0;
			int count = 1;
			for (int i = 0; i < 10; i++)
			{
					varba[i] = new JLabel();
					varba[i].setSize(60, 45);
					varba[i].setLocation(0, inclbltab1);
					varba[i].setText("VAR"+count++);
					varba[i].setHorizontalAlignment(JLabel.LEFT);
					jp3.add(varba[i]);
					inclbltab1 += 22;
					
			}
			
			// VarBinds TAB B Labels
			
			int inclbltab2 = 0;
			count = 11;
			for (int i = 0; i < 10; i++)
			{
				varbb[i] = new JLabel();
				varbb[i].setSize(60, 45);
				varbb[i].setLocation(0, inclbltab2);
				varbb[i].setText("VAR"+count++);
				varbb[i].setHorizontalAlignment(JLabel.LEFT);
				jp4.add(varbb[i]);
				inclbltab2 += 22;
			}
			
			
			
			// Buttons
			JButton button1 = new JButton("Execute");
			button1.setLocation(9, 200);
			button1.setSize(80, 25);
			jp1.add(button1);
			button1.addActionListener(new ButtonListener());
		
			JButton button2 = new JButton("Quit");
			button2.setLocation(104, 200);
			button2.setSize(80, 25);
			jp1.add(button2);
			button2.addActionListener(new ButtonListener());
	
			JButton button3 = new JButton("Clear");
			button3.setLocation(199, 200);
			button3.setSize(80, 25);
			jp1.add(button3);
			button3.addActionListener(new ButtonListener());
			
			
			// HIDDEN FIELDS
			
			v3usrlbl.setLocation(0, 124);
			v3usrlbl.setSize(60, 70);
			v3usrlbl.setHorizontalAlignment(JLabel.LEFT);
			jp2.add(v3usrlbl);
			v3usrlbl.setVisible(false);
			
	
			v3pwdlbl.setLocation(0, 167);
			v3pwdlbl.setSize(60, 70);
			v3pwdlbl.setHorizontalAlignment(JLabel.LEFT);
			jp2.add(v3pwdlbl);
			v3pwdlbl.setVisible(false);
			
		
			// Creates new combobox
			String[] ServerStrings = {"","tcemogwyw02","tcemugwyw02"};
			JComboBox srvList = new JComboBox(ServerStrings);  
			srvList.setLocation(90, 18);
			srvList.setSize(145, 25);
			jp1.add(srvList);
                        srvList.setEditable(true);
                        
		
			// Server port field
			portfield.setLocation(90, 75);
			portfield.setSize(110, 21);
			portfield.setHorizontalAlignment(JTextField.LEFT);
			portfield.setBorder(border);
			jp1.add(portfield);
		
			communityfield.setLocation(90, 137);
			communityfield.setSize(110, 21);
			communityfield.setHorizontalAlignment(JTextField.LEFT);
			communityfield.setBorder(border);
			jp1.add(communityfield);
		
			OID.setLocation(70, 21);
			OID.setSize(200, 21);
			OID.setHorizontalAlignment(JTextField.LEFT);
			OID.setBorder(border);
			jp2.add(OID);
			tfList.add(OID);
		
			SpecOID.setLocation(70, 101);
			SpecOID.setSize(60, 21);
			SpecOID.setHorizontalAlignment(JTextField.LEFT);
			SpecOID.setBorder(border);
			jp2.add(SpecOID);
			tfList.add(SpecOID);
			
			user.setLocation(70, 149);
			user.setSize(200, 21);
			user.setHorizontalAlignment(JTextField.LEFT);
			user.setBorder(border);
			jp2.add(user);
			user.setVisible(false);
			
			password.setLocation(70, 192);
			password.setSize(200, 21);
			password.setHorizontalAlignment(JTextField.LEFT);
			password.setBorder(border);
			jp2.add(password);
			password.setVisible(false);
			
			//varbinds 1st tab fields
			int inctab1 = 10;
			for (int k = 0; k < 10; k++)
			{
					varbind[k] = new JTextField();
					varbind[k].setSize(200, 21);
					varbind[k].setLocation(50, inctab1);
					varbind[k].setHorizontalAlignment(JLabel.LEFT);
					varbind[k].setBorder(border);
					varbind[k].setFocusTraversalKeysEnabled(false);
					varbind[k].addKeyListener(new MyKeyListener(varbind[k]));  
					tfList.add(varbind[k]);
					vbList.add(varbind[k]);
					jp3.add(varbind[k]);					
					inctab1 += 22;
				
			}
			
			//var binds 2nd tab fields
			int inctab2 = 10;
			for ( int k = 0; k < 10; k++)
			{
					
					varbind[k] = new JTextField();
					varbind[k].setSize(200, 21);
					varbind[k].setLocation(50, inctab2);
					varbind[k].setHorizontalAlignment(JLabel.LEFT);
					varbind[k].setBorder(border);
					varbind[k].setFocusTraversalKeysEnabled(false);
					varbind[k].addKeyListener(new MyKeyListener(varbind[k]));
					jp4.add(varbind[k]);
					vbList.add(varbind[k]);
				    tfList.add(varbind[k]);
					inctab2 += 22;
			}
		
			
			// ButtonGroup
			
			v1button.setActionCommand(v1);
			v1button.setSelected(true);
			v2button.setActionCommand(v2);
			v3button.setActionCommand(v3);
			

			ButtonGroup bg = new ButtonGroup(); 
			bg.add(v1button);
			v1button.setBounds(63, 56, 50, 30);
			bg.add(v2button);
			v2button.setBounds(110, 56, 50, 30);
			bg.add(v3button);
			v3button.setBounds(157, 56, 50, 30);
			jp2.add(v1button);
			jp2.add(v2button);
			jp2.add(v3button);
			
		
			
			// ActionListerner for combobox
			
			ItemHandler handler = new ItemHandler();
			srvList.addActionListener(handler);
			srvList.setSelectedIndex(0);
			setVisible( true );
			
			// ActionListener for Radion Buttons
			RadioListener myListener = new RadioListener();
			v1button.addActionListener(myListener);
			v2button.addActionListener(myListener);
			v3button.addActionListener(myListener);
	}
	
	
      public static void main (String []args)
	  {
         SNMPTool tab = new SNMPTool();
		}
 }

