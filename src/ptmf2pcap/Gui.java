package ptmf2pcap;
import java.util.ArrayList;
import java.awt.Frame;
import java.awt.TextArea;
import java.awt.GridLayout;
import java.awt.Color;
import java.awt.Font;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
/**
 * Graphical User Interface for ptmf2pcap
 *
 * Although much more options will be provided by a Command Line User Interface, the most
 * common use case is the user double clicking on the ptmf2pcap JAR file and expecting it
 * to convert all the PTMF files found in the same directory as the JAR file.
 * In such case, the JAR file is generally executed not by java but by javaw, which inhibits
 * the command prompt window, so there is no way to provide feedback to the user unless implementing
 * a graphical interface.
 * In this case, we will just create a window with a black text area as a replacement of the
 * command prompt window
 */
public class Gui extends Ui {

	/*
	 * LogWindow elements
	 */
	private Frame logWindowFrame = null;
	private TextArea logWindowTextArea = null;
	
	/**
	 * Constructs the Gui object with its corresponding Log Window
	 */
	public Gui() {
		super();
		this.logWindowFrame = new Frame("ptmf2pcap.v" + Gui.BUILD);
		this.logWindowFrame.setSize(640,480);
		this.logWindowFrame.setLayout(new GridLayout(1, 1));
		this.logWindowFrame.setBackground(Color.BLACK);
		this.logWindowFrame.addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent windowEvent){
				System.exit(0);
			}
		});
		this.logWindowTextArea = new TextArea("",80,480);
		this.logWindowTextArea.setRows(80);
		this.logWindowTextArea.setBackground(Color.BLACK);
		this.logWindowTextArea.setForeground(Color.WHITE);
		this.logWindowTextArea.setFont(new Font(Font.SANS_SERIF, Font.PLAIN, 12));
		this.logWindowFrame.add(logWindowTextArea);
		this.logWindowFrame.setVisible(true);
	}
	
	/**
	 * Writes text to GUI output
	 *
	 * @param	textOutput	the text to output
	 */
	public void guiOutput(String textOutput){
		if(this.logWindowTextArea != null) {
			this.logWindowTextArea.append(textOutput + "\r\n");
		}
	}
	
	/**
	 * Handles Text Output Event
	 *
	 * @param	textOutput	the text to output
	 */
	public void onTextOutput(String textOutput) {
		guiOutput(textOutput);
	}
	
	/**
	 * Handles onFinish event
	 *
	 */
	public void onFinish(int retValue) {
		// We are now simulating the "Press any key to continue" from the command prompt
		this.logWindowTextArea.addKeyListener(new KeyAdapter() {
			public void keyPressed(KeyEvent e) {
				System.exit(0);
			};
		});
		this.guiOutput("Press any key to continue . . .");
	}
	
	/**
	 * Main method
	 *
	 * @param	args	arguments
	 */
	public static void main(String[] args) {
		Gui gui = new Gui();
		gui.processInputOutputArrayList(Gui.getInputOutputArrayListFromDirPaths(".", "."));
	}
	
}