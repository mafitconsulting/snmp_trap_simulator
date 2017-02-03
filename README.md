# Java SNMP Trap Simulator 
Java swing GUI application for windows desktops. The application was developed to aid testing of
monitoring devices for SNMP enterprise MIB files.

Currently supports v1 and v2c snmp traps (tested). SNMPv3 method needs to be tested, and maybe tweaked.


####Inputs:

#####Server Tab

  **Servers:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;JComboBox (Editable):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;FQDN Server or IP address or SNMP Trap receiver
  
  **Port:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;JTextField (Editble):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Port number (Default 162) tyhe SNMP receiver is listening on
  
  **Community String:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;JTextField (Editble):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Used for SNMPv1 and 2c
  
#####Config Tab

  **OID:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;JTextField (Editable):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Enterprise ID or the MIB file
	
  **SNMP:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;RadioButton:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; v1 v2 or v3 options
	
  **Specific:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;JTextField (Editable):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Specific trap number (Example 12345)
	

#####Varbinds Tab

  **Var 1-20:**&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;JTextField (Editable):&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Variable bindings to pass into trap for parsing

## Getting Started

To clone this repository:     

git clone https://github.com/mafitconsulting/snmp_trap_simulator
        
Once the repository is cloned, there will be a requirement to customise the code as per users requirement


## Getting Started

To clone this repository:     

git clone https://github.com/mafitconsulting/snmp_trap_simulator
        
Once the repository is cloned, there will be a requirement to customise the code as per users requirement

### Prerequisites

####Runtime
jre 1.6 or above
####Development
Java JDK 6 or above

Netbeans IDE 8.1 (optional)


### Distributing and Running Standalone GUI Applications
As an example of how the GUI application for distribution runs from the command line:

Navigate to the project's dist folder in the location where you cloned the git repo
run the project from the command line, go to the dist folder and
type the following:

java -jar "SNMPTrapSimulator.jar" 

To distribute this project, zip up the dist folder (including the lib folder)
and distribute the ZIP file.

You'll need to recompile all the classes if you customised the classes.

## Built With
Netbeans 8.1.

Notes:

When you build a Java application project that has a main class, the IDE
automatically copies all of the JAR
files on the projects classpath to your projects dist/lib folder. The IDE
also adds each of the JAR files to the Class-Path element in the application
JAR files manifest file (MANIFEST.MF).


## Authors

Mark Fieldhouse - Mafitconsulting
	- Swing interface and SNMP trap methods.

Frank Fock and Jochen Katz
	- SNMP4J API - http://www.snmp4j.org/ 

## License
This project is licensed under the MIT License.

Please see notes for SNMP4J API
http://www.snmp4j.org/  Open Source license Apache 2.0 )
