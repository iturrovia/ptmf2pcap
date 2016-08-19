package ptmf2pcap;
import java.util.ArrayList;
import java.io.File;

/**
 * Command Line Interface for ptmf2pcap
*/
public class Cli extends Ui {

	/*
	 * return value element
	 */
	public int retValue;
	
	/**
	 * Constructs the Cli object and initializes its return value
	 */
	public Cli() {
		this.retValue = 0;
	}
	
	/**
	 * Writes text console output
	 *
	 * @param	textOutput	the text to output
	 */
	private void consoleOutput(String textOutput){
		System.out.println(textOutput);
	}
	
	/**
	 * Handles Text Output Event
	 *
	 * @param	textOutput	the text to output
	 */
	public void onTextOutput(String textOutput) {
		consoleOutput(textOutput);
	}
	
	/**
	 * Handles User Interface Output
	 *
	 * @param	textOutput	the text to output
	 */
	public void onFinish(int retValue) {
		this.retValue = retValue;
	}
	
	/**
	 * Main method
	 *
	 * @param	args	arguments
	 */
	public static void main(String[] args) {
		String HELP_STRING =
		"ptmf2pcap.v" + Cli.BUILD + ":\r\n" +
		"\r\n" +
		"Usage 1 (converts the input PTMF file into the output PCAP file):" + "\r\n" +
		"\r\n" +
		"    ptmf2pcap -f <input_file> <output_file>" + "\r\n" +
		"\r\n" +
		"Usage 2 (converts the PTMF files from the input directory into PCAP files in the output directory):" + "\r\n" +
		"\r\n" +
		"    ptmf2pcap -d <input_directory> <output_directory>" + "\r\n";
		
		ArrayList<File[]> inputOutputArrayList = null;
		ArrayList<String> ptmfFilePathArrayList = null;
		String inputFilePath = null;
		String outputFilePath = null;
		String inputDirPath = null;
		String outputDirPath = null;
		byte[] pcapFile = null;
		byte[] fileContents = null;
		PtmfFile ptmfFile = null;
		String option = null;
		Cli cli = new Cli();
		
		/*
		 * Processing command line args
		 * I wonder why java standard library does not include an implementation for this...
		 */
		if(args.length > 0) {
			option = args[0];
			if(option == "-h") {
				cli.consoleOutput(HELP_STRING);
				cli.retValue = 1;
			} else if((option.equals("-f")) && (args.length == 3)) {
				inputFilePath = args[1];
				outputFilePath = args[2];
				inputOutputArrayList = new ArrayList<File[]>();
				inputOutputArrayList.add(Cli.getInputOutputFromFilePaths(inputFilePath, outputFilePath));
			} else if((option.equals("-d")) && (args.length == 3)) {
				inputDirPath = args[1];
				outputDirPath = args[2];
				inputOutputArrayList = Cli.getInputOutputArrayListFromDirPaths(inputDirPath, outputDirPath);
			} else {
				cli.consoleOutput(HELP_STRING);
				cli.retValue = 1;
			};
		} else {
			inputOutputArrayList = Cli.getInputOutputArrayListFromDirPaths(".", ".");
		};
		if(cli.retValue == 0) {
			// We can proceed
			cli.processInputOutputArrayList(inputOutputArrayList);
		}
		System.exit(cli.retValue);
	}
	
}