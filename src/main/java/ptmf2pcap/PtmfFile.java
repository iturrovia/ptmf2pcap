package ptmf2pcap;

import java.util.List;
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
		List<PtmfFrame> ptmfFrameArrayList = this.getPtmfFrameList();
		if(ptmfFrameArrayList != null) {
			for (int index = 0; index < ptmfFrameArrayList.size(); index++) {
				stringBuilder.append('\r');
				stringBuilder.append('\n');
				stringBuilder.append(ptmfFrameArrayList.get(index).toString());
			};
		} else {
			ArrayList<byte[]> byteFrameList = ByteUtils.split(this.getByteContent(), FRAME_SEPARATOR_BYTES);
			stringBuilder.append(ByteUtils.bytesToHexString(byteFrameList.get(0)));
			for(int i = 1; i < byteFrameList.size(); i++) {
				stringBuilder.append('\r');
				stringBuilder.append('\n');
				stringBuilder.append(ByteUtils.bytesToHexString(byteFrameList.get(i)));
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
	 * Checks whether the input fileType is supported or not
	 *
	 * @param	fileType	the fileType
	 * @return				whether it is supported or not
	 */
	public static boolean isSupportedFileType(String fileType) {
		if(fileType.equals(FILETYPE_USERINTERFACE) || fileType.equals(FILETYPE_SIP) || fileType.equals(FILETYPE_DIAMETER) || fileType.equals(FILETYPE_IP)) {
			return true;
		} else {
			return false;
		}
	};

	/**
	 * Creates a PtmfFrame object using a different constructor depending on the fileType
	 * If the fileType is not recongized it returns null
	 *
	 * @param	byteFrame	the input bytes
	 * @param	frameIndex	the frame index
	 * @param	fileType	the fileType
	 * @return	the ptmfFrame
	 */
	public static PtmfFrame createPtmfFrame(byte[] byteFrame, int frameIndex, String fileType) {
		PtmfFrame ptmfFrame = null;
		if(fileType.equals(FILETYPE_USERINTERFACE)) {
			ptmfFrame = new UserInterfacePtmfFrame(byteFrame, frameIndex);
		} else if(fileType.equals(FILETYPE_SIP)) {
			ptmfFrame = new SipPtmfFrame(byteFrame, frameIndex);
		} else if(fileType.equals(FILETYPE_DIAMETER)) {
			ptmfFrame = new DiameterPtmfFrame(byteFrame, frameIndex);
		} else if(fileType.equals(FILETYPE_IP)) {
			ptmfFrame = new IpPtmfFrame(byteFrame, frameIndex);
		} else {
			ptmfFrame = null;
		};
		return ptmfFrame;
	}

	/**
	 * Returns all the PTMF frames that the PtmfFile contains
	 * The PTMF frames are returned as an ArrayList of PtmfFrame objects
	 *
	 * @return	The PtmfFrame ArrayList
	 */
	public List<PtmfFrame> getPtmfFrameList() {
		if(!isSupportedFileType(this.getFileType())) {
			// Really ugly handling, but I'm not changing it now as I'm planning to redesign the whole application someday
			System.out.println("Error: fileType=" + this.getFileType() + " not recognized");
			return null;
		};

		List<PtmfFrame> ptmfFrameList = null;
		PtmfFrame ptmfFrame = null;
		List<byte[]> byteFrameList = ByteUtils.split(this.getByteContent(), FRAME_SEPARATOR_BYTES);
		byteFrameList.remove(0); // We remove first element of the ArrayList, which is a the PTMF file header not a PTMF frame
		Pcap.resetTcpSeqNums();
		Pcap.resetSctpSeqNums();
		ptmfFrameList = new ArrayList<PtmfFrame>();
		int frameIndex = 0;
		int frameListSize = byteFrameList.size();
		String fileType = this.getFileType();
		for(byte[] byteFrame: byteFrameList) {
			ptmfFrame = createPtmfFrame(byteFrame, frameIndex, fileType);
			if(!(ptmfFrame.isTooShort() && (frameIndex == (frameListSize - 1)))) {
				// We are only adding the PtmfFrame object if we are sure that it is not a "bogus" frame placed at the end of the file
				ptmfFrameList.add(ptmfFrame);
			};
			frameIndex++;
			if(frameIndex >= frameListSize) {
				break;
			}
		};
		return ptmfFrameList;
	};
	
	/**
	 * Returns a PCAP file containing all the PTMF frames that the PtmfFile contains
	 *
	 * @return	The PCAP file
	 */
	public byte[] getPcapFile() {
		List<byte[]> pcapFrameList = new ArrayList<byte[]>();
		List<PtmfFrame> ptmfFrameList = this.getPtmfFrameList();
		byte[] pcapFrame;
		for (PtmfFrame ptmfFrame: ptmfFrameList) {
			pcapFrame = ptmfFrame.getPcapFrame();
			if(pcapFrame != null) {
				pcapFrameList.add(pcapFrame);
			};
		};
		return Pcap.createPcapFile(pcapFrameList, Pcap.LINKTYPE_ETHERNET);
	}
};