package ptmf2pcap;

import java.util.ArrayList;
import java.lang.StringBuilder;
import java.util.logging.Logger;
import java.util.logging.FileHandler;
import java.util.logging.SimpleFormatter;
import java.util.HashMap;

/**
 * PtmfFile object represents a PTMF file, which is a binary file
 * containing network frames. Note that there are different types
 * of PTMF files, depending on the type of network frames it contains.
 *
 * Huawei has a great range of network products, which then output lots of
 * different types of network frames. However, ptmf2pcap implementation
 * only supports a few of them so far (those used by some Huawei SBCs,
 * belonging to SE2900 series in particular).
 *
 * PtmfFile object stores the file content in a byte array, and
 * provides methods to access the network frames
 */
public class PtmfFile {

	public static final byte[] FRAME_SEPARATOR_BYTES = { (byte) 0x6D, (byte) 0x73, (byte) 0x67, (byte) 0x30 };
	private static final int FILETYPE_OFFSET = 23;
	private static final int FILETYPE_LENGTH = 1;
	public static final String FILETYPE_USERINTERFACE = "UserInterface";
	public static final String FILETYPE_SIP = "SIP";
	public static final String FILETYPE_DIAMETER = "Diameter";
	public static final String FILETYPE_IP = "IP";
	public static final String FILETYPE_UNKNOWN = "UNKNOWN";
	private static final String[][] FILETYPE_TABLE = {
		{"01", FILETYPE_SIP},
		{"03", FILETYPE_DIAMETER},
		{"10", FILETYPE_USERINTERFACE},
		{"53", FILETYPE_IP}
	};
	private static HashMap<String,String> FILETYPE_MAP = createHashMap(FILETYPE_TABLE);
	
	/**
	 * Creates a HashMap reading the (key, value) pairs from an input table
	 *
	 * @param	table	a table where each row is a (key, value) pair
	 * @return			the newly created HashMap object
	 */
	private static HashMap<String,String> createHashMap(String[][] table) {
		HashMap<String,String> hashMap = new HashMap<String,String>();
		for(int i = 0; i < table.length; i++) {
			hashMap.put(table[i][0], table[i][1]);
		};
		return hashMap;
	};
	
	/*
	 * Instance variables
	 */
	private byte[] byteContent;
	
	/**
	 * Constructor method taking a byte array as input parameter
	 * The file type is inferred from the byte content
	 * 
	 * @param	byteContent	a byte array with the content of the file
	 * @return				the newly created PtmfFile object
	 */
	public PtmfFile(byte[] byteContent) {
		this.byteContent = byteContent;
	};
	
	/**
	 * Infers the file type by analysing the byte content
	 * It is only able to recognize some of the file types generated
	 * by Huawei SBCs (at least those from SE2900 series)
	 * 
	 * @return	The file type
	 */
	public String getFileType() {
		String fileType = FILETYPE_MAP.get(this.getFileTypeHex());
		if(fileType == null) {
			fileType = FILETYPE_UNKNOWN;
		}
		return fileType;
	};
	
	/**
	 * @return	The byte content of the PtmfFile object
	 */
	public byte[] getByteContent() {
		return this.byteContent;
	};
	
	/**
	 * Returns the content of the PtmfFile object represented as an Hex String
	 *
	 * @return	The content of the PtmfFile object represented as an Hex String
	 */
	public String toRawString() {
		return ByteUtils.bytesToHexString(this.getByteContent());
	};
	
	/**
	 * Returns a string representation of the PTMF file
	 * Hex representation is still used the same as toRawString() method does,
	 * but PTMF file header and different PTMF frames are splitted across
	 * different lines
	 *
	 * @return	The content of the PtmfFile object represented as an Hex String
	 */
	public String toString() {
		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append(ByteUtils.bytesToHexString(this.getHeader()));
		ArrayList<PtmfFrame> ptmfFrameArrayList = this.getPtmfFrameArrayList();
		if(ptmfFrameArrayList != null) {
			for (int index = 0; index < ptmfFrameArrayList.size(); index++) {
				stringBuilder.append('\r');
				stringBuilder.append('\n');
				stringBuilder.append(ptmfFrameArrayList.get(index).toString());
			};
		} else {
			ArrayList<byte[]> byteFrameArrayList = ByteUtils.split(this.getByteContent(), FRAME_SEPARATOR_BYTES);
			stringBuilder.append(ByteUtils.bytesToHexString(byteFrameArrayList.get(0)));
			for(int i = 1; i < byteFrameArrayList.size(); i++) {
				stringBuilder.append('\r');
				stringBuilder.append('\n');
				stringBuilder.append(ByteUtils.bytesToHexString(byteFrameArrayList.get(i)));
			};
		};
		return stringBuilder.toString();
	};
	
	/**
	 * Returns the header of the PTMF file
	 *
	 * @return	The header of the PTMF file
	 */
	public byte[] getHeader() {
		return ByteUtils.split(this.getByteContent(), FRAME_SEPARATOR_BYTES).get(0);
	};
	
	/**
	 * Returns the file type represented as a byte array
	 *
	 * @return	The file type
	 */
	public byte[] getFileTypeBytes() {
		return ByteUtils.subarray(this.getByteContent(), FILETYPE_OFFSET, FILETYPE_LENGTH);
	};
	
	/**
	 * Returns the file type represented as an Hex String
	 *
	 * @return	The file type
	 */
	public String getFileTypeHex() {
		return ByteUtils.bytesToHexString(this.getFileTypeBytes());
	};
	
	/**
	 * Returns all the PTMF frames that the PtmfFile contains
	 * The PTMF frames are returned as an ArrayList of PtmfFrame objects
	 *
	 * @return	The PtmfFrame ArrayList
	 */
	public ArrayList<PtmfFrame> getPtmfFrameArrayList() {
		ArrayList<PtmfFrame> ptmfFrameArrayList = null;
		PtmfFrame ptmfFrame = null;
		ArrayList<byte[]> byteFrameArrayList = ByteUtils.split(this.getByteContent(), FRAME_SEPARATOR_BYTES);
		byteFrameArrayList.remove(0); // We remove first element of the ArrayList, which is a the PTMF file header not a PTMF frame
		Pcap.resetTcpSeqNums();
		Pcap.resetSctpSeqNums();
		ptmfFrameArrayList = new ArrayList<PtmfFrame>();
		if(this.getFileType().equals(FILETYPE_USERINTERFACE)) {
			for(int index = 0; index < byteFrameArrayList.size(); index++) {
				ptmfFrame = new UserInterfacePtmfFrame(byteFrameArrayList.get(index), index);
				if(!(ptmfFrame.isTooShort() && (index == (byteFrameArrayList.size() - 1)))) {
					// We are only adding the PtmfFrame object if we are sure that it is not a "bogus" frame placed at the end of the file
					ptmfFrameArrayList.add(ptmfFrame);
				};
			};
		} else if (this.getFileType().equals(FILETYPE_SIP)) {
			for(int index = 0; index < byteFrameArrayList.size(); index++) {
				ptmfFrame = new SipPtmfFrame(byteFrameArrayList.get(index), index);
				if(!(ptmfFrame.isTooShort() && (index == (byteFrameArrayList.size() - 1)))) {
					// We are only adding the PtmfFrame object if we are sure that it is not a "bogus" frame placed at the end of the file
					ptmfFrameArrayList.add(ptmfFrame);
				};
			};
		} else if (this.getFileType().equals(FILETYPE_DIAMETER)) {
			for(int index = 0; index < byteFrameArrayList.size(); index++) {
				ptmfFrame = new DiameterPtmfFrame(byteFrameArrayList.get(index), index);
				if(!(ptmfFrame.isTooShort() && (index == (byteFrameArrayList.size() - 1)))) {
					// We are only adding the PtmfFrame object if we are sure that it is not a "bogus" frame placed at the end of the file
					ptmfFrameArrayList.add(ptmfFrame);
				};
			};
		} else if (this.getFileType().equals(FILETYPE_IP)) {
			for(int index = 0; index < byteFrameArrayList.size(); index++) {
				ptmfFrame = new IpPtmfFrame(byteFrameArrayList.get(index), index);
				if(!(ptmfFrame.isTooShort() && (index == (byteFrameArrayList.size() - 1)))) {
					// We are only adding the PtmfFrame object if we are sure that it is not a "bogus" frame placed at the end of the file
					ptmfFrameArrayList.add(ptmfFrame);
				};
			};
		} else {
			System.out.println("Error: fileType=" + this.getFileType() + " not recognized"); 
			ptmfFrameArrayList = null;
		};
		return ptmfFrameArrayList;
	};
	
	/**
	 * Returns a PCAP file containing all the PTMF frames that the PtmfFile contains
	 *
	 * @return	The PCAP file
	 */
	public byte[] getPcapFile() {
		ArrayList<byte[]> pcapFrameArrayList = new ArrayList<byte[]>();
		ArrayList<PtmfFrame> ptmfFrameArrayList = this.getPtmfFrameArrayList();
		PtmfFrame ptmfFrame = null;
		byte[] pcapFrame;
		for (int index = 0; index < ptmfFrameArrayList.size(); index++) {
			ptmfFrame = ptmfFrameArrayList.get(index);
			pcapFrame = ptmfFrame.getPcapFrame();
			if(pcapFrame != null) {
				pcapFrameArrayList.add(pcapFrame);
			};
		};
		return Pcap.createPcapFile(pcapFrameArrayList, Pcap.LINKTYPE_ETHERNET);
	}
};