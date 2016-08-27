package ptmf2pcap;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;

/**
 * User Interface for ptmf2pcap
 *
 * This class contains the general functionality to implement user interfaces for ptmf2pcap
 * and is defined as an abstract one just to be extended by specific user interfaces
 * we might want to create (either command line or graphical user interfaces).
 *
 * It is true that all the abstract methods so far could have also been
 * implemented by Interfaces instead, but I also wanted to provide a shared implementation
 * for the common stuff, so using an abstract class for that all was the way to 
 * reduce boilerplate (at least when using JDK version < JDK 8)
 */
public abstract class Ui {

	/** Change these settings before running this class. */
	private static final boolean DEBUG_MODE = false;
	public static final String BUILD = "0.9.5.build20160827";
	
	/**
	 * Handles Text Output Event
	 *
	 * @param	textOutput	the text to output
	 */
	public abstract void onTextOutput(String textOutput);
	
	/**
	 * Handles User Interface Output
	 *
	 * @param	textOutput	the text to output
	 */
	public abstract void onFinish(int retValue);
	
	/**
	 * Reads the given binary file, and returns its contents as a byte array
	 * Some inspiration from http://stackoverflow.com/questions/156508/closing-a-java-fileinputstream
	 *
	 * @param	inputFilePath	the path to the input file
	 * @return	the byte content of the file
	 */
	private byte[] readFile(String inputFilePath) {
		byte[] readBytes = null;
		InputStream inputStream = null;
		File inputFile = new File(inputFilePath);
		try {
			try {
				inputStream = new BufferedInputStream(new FileInputStream(inputFile));
				readBytes = new byte[(int)inputFile.length()];
				int totalBytesRead = 0;
				while(totalBytesRead < readBytes.length){
					int bytesRead = inputStream.read(readBytes, totalBytesRead, readBytes.length - totalBytesRead); 
					if (bytesRead > 0){
						totalBytesRead = totalBytesRead + bytesRead;
					}
				}
			} finally {
				if(inputStream != null) {
					inputStream.close();
				}
			}
		} catch (FileNotFoundException e) {
			onTextOutput("ERROR:  Failed to open input file " + inputFilePath);
		} catch (IOException e) {
			onTextOutput("ERROR:  Exception when working with input file " + inputFilePath);
		}
		return readBytes;
	}

	/**
	 * Writes a byte array to the given file.
	 *
	 * @param	inputBytes	input byte array
	 * @param	inputBytes	input byte array
	 * @return			the names of each PTMF file found in the directory
	 */
	private boolean writeFile(byte[] inputBytes, String outputFilePath){
		boolean success = false;
		try {
			OutputStream outputStream = null;
			try {
				outputStream = new BufferedOutputStream(new FileOutputStream(outputFilePath));
				outputStream.write(inputBytes);
				success = true;
			} finally {
				if(outputStream != null) {
					outputStream.close();
				}
			}
		} catch(FileNotFoundException e){
			onTextOutput("ERROR:  Failed to open output file " + outputFilePath);
		} catch(IOException e){
			onTextOutput("ERROR:  Exception when working with output file " + outputFilePath);
		}
		return success;
	}
	
	/**
	 * Get list of all PTMF files in a directory. 
	 *
	 * @param	dirPath	path to the directory containing the PTMF files
	 * @return			the PTMF files found in the directory
	 */
	public static ArrayList<File> findPtmfFilesInDir(String dirPath) {
		File dir = new File(dirPath);
		File[] filesList = dir.listFiles();
		ArrayList<File> ptmfFileArrayList = new ArrayList<File>();
		for(File f : filesList){
			if(f.isFile()){
				if(f.getName().toUpperCase().endsWith(".PTMF")) {
					ptmfFileArrayList.add(f);
				}
			}
		}
		return ptmfFileArrayList;
    };
	
	public static File[] getInputOutputFromFilePaths(String inputFilePath, String outputFilePath) {
		File[] inputOutput = new File[2];
		inputOutput[0] = new File(inputFilePath);
		inputOutput[1] = new File(outputFilePath);
		return inputOutput;
	};
	
	public static ArrayList<File[]> getInputOutputArrayListFromDirPaths(String inputDirPath, String outputDirPath) {
		ArrayList<File[]> inputOutputArrayList = new ArrayList<File[]>();
		ArrayList<File> inputArrayList = findPtmfFilesInDir(inputDirPath);
		String inputFileName = null;
		String inputFilePath = null;
		String outputFileName = null;
		String outputFilePath = null;
		for(int i = 0; i < inputArrayList.size(); i++) {
			inputFilePath = inputArrayList.get(i).getPath();
			inputFileName = inputArrayList.get(i).getName();
			outputFileName = inputFileName.substring(0, inputFileName.length() - 5) + ".pcap";
			outputFilePath = (new File(outputDirPath, outputFileName)).getPath();
			inputOutputArrayList.add(getInputOutputFromFilePaths(inputFilePath, outputFilePath));
		}
		return inputOutputArrayList;
	};
	
	public void processInputOutputArrayList(ArrayList<File[]> inputOutputArrayList) {
		File inputFile = null;
		File outputFile = null;
		byte[] pcapFile = null;
		byte[] fileContents = null;
		PtmfFile ptmfFile = null;
		String result = null;
		String summary = null;
		int errorCounter = 0;
		
		this.onTextOutput("ptmf2pcap.v" + BUILD);
		this.onTextOutput("================================================================");
		for(int i = 0; i < inputOutputArrayList.size(); i++) {
			inputFile = inputOutputArrayList.get(i)[0];
			outputFile = inputOutputArrayList.get(i)[1];
			if(i > 0) {
				this.onTextOutput("----------------------------------------------------------------");
			}
			this.onTextOutput("Input:  " + inputFile.getPath());
			this.onTextOutput("Output: " + outputFile.getPath());
			fileContents = readFile(inputFile.getPath());
			if(fileContents != null) {
				ptmfFile = new PtmfFile(fileContents);
				if(DEBUG_MODE) {
					// Useful when parsing a new file type
					writeFile(ptmfFile.toString().getBytes(Charset.forName("UTF-8")), inputFile.getPath() + ".hex.txt");
				};
				if(!ptmfFile.getFileType().equals(PtmfFile.FILETYPE_UNKNOWN)) {
					pcapFile = ptmfFile.getPcapFile();
					if(writeFile(pcapFile, outputFile.getPath())) {
						result = "OK";
					} else {
						result = "ERROR(FAILED_TO_WRITE_TO_OUTPUT_FILE)";
						errorCounter++;
					};
				} else {
					result = "ERROR(INPUT_FILE_TYPE_UNKNOWN)";
					errorCounter++;
				};
			} else {
				result = "ERROR(FAILED_TO_READ_FROM_INPUT_FILE)";
				errorCounter++;
			}
			this.onTextOutput("Result: " + result);
		}
		this.onTextOutput("================================================================");
		summary = "Processed " + Integer.toString(inputOutputArrayList.size()) + " files with " + Integer.toString(errorCounter) + " errors";
		this.onTextOutput(summary);
		this.onFinish(errorCounter);
	}
	
}