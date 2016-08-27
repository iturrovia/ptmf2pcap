package ptmf2pcap;

import java.util.Date;
import java.util.TimeZone;
import java.text.SimpleDateFormat;
import java.net.InetAddress;

/**
 * PtmfFrame object represents a PTMF frame, which is composed by the
 * following two components:
 *     - Frame body: it generally contains a network frame, but not necessarily containg
 *                   all layers (for instance, a SIP PTMF Frame body contains
 *                   the layer 5 only)
 *     - Frame header: contains frame number, arrival time and some description of underlying
 *                   network layers (such as IP addresses and tranport ports)
 *
 * Note that this PtmfFrame class is an abstract class, just to provide some constants and methods
 * that will be inherited by the different types of PtmfFrames
 *
 * PtmfFrame object stores the frame content in a byte array, and
 * provides methods to access the frame fields
 */
public abstract class PtmfFrame {

	/*
	 * PtmfFrame constants
	 */
	private static final byte[] DEFAULT_MAC = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
	private static final int FRAMENUMBER_OFFSET = 14;
	private static final int FRAMENUMBER_LENGTH = 4;
	private static final int YEAR_OFFSET = 24;
	private static final int YEAR_LENGTH = 2;
	private static final int MONTH_OFFSET = 26;
	private static final int MONTH_LENGTH = 1;
	private static final int DAY_OFFSET = 27;
	private static final int DAY_LENGTH = 1;
	private static final int HOUR_OFFSET = 28;
	private static final int HOUR_LENGTH = 1;
	private static final int MINUTE_OFFSET = 29;
	private static final int MINUTE_LENGTH = 1;
	private static final int SECOND_OFFSET = 30;
	private static final int SECOND_LENGTH = 1;
	private static final int MILISECOND_OFFSET = 34;
	private static final int MILISECOND_LENGTH = 2;
	public static final int SRCIP_LENGTH = 4;
	public static final int DSTIP_LENGTH = 4;
	public static final int SRCPORT_LENGTH = 2;
	public static final int DSTPORT_LENGTH = 2;
	/*
	 * Some parameters will take different values depending on
	 * the type of PTMF Frame.
	 * 
	 * Of course Java does not allow for abstract static constants,
	 * so we are getting the same from abstract member methods,
	 * which will be implemented to access the static constants
	 * that are defined at each class
	 */
	public abstract int GET_FRAME_HEADER_LENGTH();
	public abstract int GET_SRCIP_OFFSET(); 
	public abstract int GET_DSTIP_OFFSET();
	public abstract int GET_SRCPORT_OFFSET();
	public abstract int GET_DSTPORT_OFFSET();

	private byte[] byteContent;
	private int order;
	
	/**
	 * Constructor method taking no input parameters
	 * Note that order is taking 0 as default value, and byteContent should
	 * be set for the object to be usable.
	 * Thus the constructor taking byteContent and order as input parameters
	 * should be more useful for most use cases
	 *
	 * @return	the newly created PtmfFrame object
	 */
	public PtmfFrame() {
		this.byteContent = null;
		this.order = 0;
	};
	
	/**
	 * Constructor method taking a byte array as input parameter
	 * Note that order is taking 0 as default value
	 * The constructor taking not only byteContent but also order as
	 * input parameter should be more useful for most use cases
	 * 
	 * @param	byteContent	a byte array with the content of the PTMF Frame
	 * @return				the newly created PtmfFrame object
	 */
	public PtmfFrame(byte[] byteContent) {
		this.byteContent = byteContent;
		this.order = 0;
	};
	
	/**
	 * Constructor method taking a byte array and the order as input parameters
	 * 
	 * @param	byteContent	a byte array with the content of the PTMF Frame
	 * @param	order		the relative order that the new PTMF Frame takes in the parent file
	 * @return				the newly created PtmfFrame object
	 */
	public PtmfFrame(byte[] byteContent, int order) {
		this.byteContent = byteContent;
		this.order = order;
	};
	
	/**
	 * @return	The byte content of the PtmfFrame object
	 */
	public byte[] getByteContent() {
		return this.byteContent;
	};
	
	/**
	 * @return	The body of the PtmfFrame object
	 */
	public byte[] getBody() {
		return ByteUtils.subarray(this.getByteContent(), this.GET_FRAME_HEADER_LENGTH(), this.getByteContent().length - this.GET_FRAME_HEADER_LENGTH());
	};
	
	/**
	 * @return	The order of the PtmfFrame object
	 */
	public int getOrder() {
		return this.order;
	};
	
	/**
	 * Sets the order of the PtmfFrame object
	 * 
	 * @param	order		the relative order that the new PTMF Frame takes in the parent file
	 */
	public void setOrder(int order) {
		this.order = order;
	};
	
	/**
	 * @return	The string (HEX) representation of the PTMF Frame
	 */
	public String toString() {
		return ByteUtils.bytesToHexString(this.getByteContent());
	};
	
	/**
	 * @return	The frame number represented as a byte array
	 */
	public byte[] getFrameNumberBytes() {
		return ByteUtils.subarray(this.getByteContent(), FRAMENUMBER_OFFSET, FRAMENUMBER_LENGTH);
	};
	
	/**
	 * @return	The frame number
	 */
	public int getFrameNumber() {
		return Integer.parseInt("0" + ByteUtils.bytesToHexString(this.getFrameNumberBytes()), 16);
	};
	
	/**
	 * @return	The year component of the arrival date (represented as a byte array)
	 */
	public byte[] getYearBytes() {
		return ByteUtils.subarray(this.getByteContent(), YEAR_OFFSET, YEAR_LENGTH);
	};
	
	/**
	 * @return	The year component of the arrival date
	 */
	public int getYearInt() {
		return Integer.parseInt("0" + ByteUtils.bytesToHexString(this.getYearBytes()), 16);
	};
	
	/**
	 * @return	The month component of the arrival date (represented as a byte array)
	 */
	public byte[] getMonthBytes() {
		return ByteUtils.subarray(this.getByteContent(), MONTH_OFFSET, MONTH_LENGTH);
	};
	
	/**
	 * @return	The month component of the arrival date
	 */
	public int getMonthInt() {
		return Integer.parseInt(ByteUtils.bytesToHexString(this.getMonthBytes()), 16);
	};
	
	/**
	 * @return	The day component of the arrival date (represented as a byte array)
	 */
	public byte[] getDayBytes() {
		return ByteUtils.subarray(this.getByteContent(), DAY_OFFSET, DAY_LENGTH);
	};
	
	/**
	 * @return	The day component of the arrival date
	 */
	public int getDayInt() {
		return Integer.parseInt(ByteUtils.bytesToHexString(this.getDayBytes()), 16);
	};
	
	/**
	 * @return	The hour component of the arrival date (represented as a byte array)
	 */
	public byte[] getHourBytes() {
		return ByteUtils.subarray(this.getByteContent(), HOUR_OFFSET, HOUR_LENGTH);
	};
	
	/**
	 * @return	The hour component of the arrival date
	 */
	public int getHourInt() {
		return Integer.parseInt(ByteUtils.bytesToHexString(this.getHourBytes()), 16);
	};
	
	/**
	 * @return	The minute component of the arrival date (represented as a byte array)
	 */
	public byte[] getMinuteBytes() {
		return ByteUtils.subarray(this.getByteContent(), MINUTE_OFFSET, MINUTE_LENGTH);
	};
	
	/**
	 * @return	The year component of the arrival date
	 */
	public int getMinuteInt() {
		return Integer.parseInt(ByteUtils.bytesToHexString(this.getMinuteBytes()), 16);
	};
	
	/**
	 * @return	The second component of the arrival date (represented as a byte array)
	 */
	public byte[] getSecondBytes() {
		return ByteUtils.subarray(this.getByteContent(), SECOND_OFFSET, SECOND_LENGTH);
	};
	
	/**
	 * @return	The second component of the arrival date
	 */
	public int getSecondInt() {
		return Integer.parseInt(ByteUtils.bytesToHexString(this.getSecondBytes()), 16);
	};
	
	/**
	 * @return	The arrival date
	 */
	public Date getDate() {
		return createDate(this.getYearInt(), 
		this.getMonthInt(), 
		this.getDayInt(), 
		this.getHourInt(), 
		this.getMinuteInt(), 
		this.getSecondInt());
	};
	
	/**
	 * @return	The milisecond component of the arrival date (represented as a byte array)
	 */
	public byte[] getMilisecondBytes() {
		return ByteUtils.subarray(this.getByteContent(), MILISECOND_OFFSET, MILISECOND_LENGTH);
	};
	
	/**
	 * @return	The milisecond component of the arrival date
	 */
	public int getMilisecondInt() {
		return Integer.parseInt(ByteUtils.bytesToHexString(this.getMilisecondBytes()), 16);
	};
	
	/**
	 * @return	The source IP (represented as a byte array)
	 */
	public byte[] getSrcIpBytes() {
		return ByteUtils.subarray(this.getByteContent(), this.GET_SRCIP_OFFSET(), SRCIP_LENGTH);
	};
	
	/**
	 * @return	The source IP
	 */
	public InetAddress getSrcIp() {
		InetAddress ip = null;
		try {
			ip = InetAddress.getByAddress(this.getSrcIpBytes());
		} catch(Exception e) {
			System.err.println("Exception when parsing IP!!");
			System.err.println(e.toString());
		};
		return ip;
	};
	
	/**
	 * @return	The destination IP (represented as a byte array)
	 */
	public byte[] getDstIpBytes() {
		return ByteUtils.subarray(this.getByteContent(), this.GET_DSTIP_OFFSET(), DSTIP_LENGTH);
	};
	
	/**
	 * @return	The destination IP
	 */
	public InetAddress getDstIp() {
		InetAddress ip = null;
		try {
			ip = InetAddress.getByAddress(this.getDstIpBytes());
		} catch(Exception e) {
			System.err.println("Exception when parsing IP!!");
			System.err.println(e.toString());
		};
		return ip;
	};
	
	/**
	 * @return	The source port (represented as a byte array)
	 */
	public byte[] getSrcPortBytes() {
		return ByteUtils.subarray(this.getByteContent(), this.GET_SRCPORT_OFFSET(), SRCPORT_LENGTH);
	};
	
	/**
	 * @return	The source port
	 */
	public int getSrcPort() {
		return Integer.parseInt("0" + ByteUtils.reverseEndian(ByteUtils.bytesToHexString(this.getSrcPortBytes())), 16);
	};
	
	/**
	 * @return	The destination port (represented as a byte array)
	 */
	public byte[] getDstPortBytes() {
		return ByteUtils.subarray(this.getByteContent(), this.GET_DSTPORT_OFFSET(), DSTPORT_LENGTH);
	};
	
	/**
	 * @return	The destination port
	 */
	public int getDstPort() {
		return Integer.parseInt("0" + ByteUtils.reverseEndian(ByteUtils.bytesToHexString(this.getDstPortBytes())), 16);
	};
	
	/**
	 * This method checks whether the content is a SIP message sent over TCP
	 * We can use this to guess whether a SIP message contained in a PTMF frame
	 * was sent via TCP (which is an information not always present in the PTMF frame header)
	 * 
	 * @return	Whether the content is a SIP message sent over TCP
	 */
	public boolean isSipOverTcp() {
		boolean result = false;
		byte[] body;
		String sipMessage = null;
		String[] sipHeaders = null;
		String sipHeader;
		body = ByteUtils.subarray(this.getByteContent(), this.GET_FRAME_HEADER_LENGTH(), this.getByteContent().length - this.GET_FRAME_HEADER_LENGTH());
		sipMessage = ByteUtils.bytesToAsciiString(body);
		sipHeaders = sipMessage.split("\\r?\\n");
		for(int i=0; i < sipHeaders.length; i++) {
			sipHeader = sipHeaders[i].toUpperCase();
			if(sipHeader.indexOf("VIA") == 0) {
				if((sipHeader.indexOf("SIP/2.0/TCP") != -1) || (sipHeader.indexOf("SIP/2.0/TLS") != -1)) {
					result = true;
				};
				break;
			};
		};
		return result;
	};
	
	/**
	 * This method checks whether the content is a SIP message sent over SCTP
	 * We can use this to guess whether a SIP message contained in a PTMF frame
	 * was sent via SCTP (which is an information not always present in the PTMF frame header)
	 * 
	 * @return	Whether the content is a SIP message sent over SCTP
	 */
	public boolean isSipOverSctp() {
		boolean result = false;
		byte[] body;
		String sipMessage = null;
		String[] sipHeaders = null;
		String sipHeader;
		body = ByteUtils.subarray(this.getByteContent(), this.GET_FRAME_HEADER_LENGTH(), this.getByteContent().length - this.GET_FRAME_HEADER_LENGTH());
		sipMessage = ByteUtils.bytesToAsciiString(body);
		sipHeaders = sipMessage.split("\\r?\\n");
		for(int i=0; i < sipHeaders.length; i++) {
			sipHeader = sipHeaders[i].toUpperCase();
			if(sipHeader.indexOf("VIA") == 0) {
				if((sipHeader.indexOf("SIP/2.0/SCTP") != -1) || (sipHeader.indexOf("SIP/2.0/TLS-SCTP") != -1)) {
					result = true;
				};
				break;
			};
		};
		return result;
	};
	
	/**
	 * This method returns an IPv4 packet containing the information that was extracted from
	 * the PTMF Frame
	 * As explained before, the PTMF Frame does not always contain a complete IPv4 frame
	  * (it can happen that it contains just a layer 5 frame and some IP addresses and ports),
	 * so this IPv4 packet is just a reconstruction in which layer 5 as well as IP addresses
	 * and ports are real, but other values of IP and transport protocols might be just filled with
	 * default values
	 *
	 * Also note that this method is an abstract one, since the aforementioned reconstruction
	 * varies depending on the type of PTMF frame
	 * 
	 * @return	An IPv4 packet containing the information extracted from the PTMF Frame
	 */
	public abstract byte[] getIpv4Packet();
	
	/**
	 * This method returns an Ethernet packet containing the information that was extracted from
	 * the PTMF Frame
	 * As explained before, the PTMF Frame does not always contain a complete Ethernet frame
	 * (it can happen that it contains just a layer 5 frame and some IP addresses and ports),
	 * so this Ethernet packet is just a reconstruction in which layer 5 as well as IP addresses
	 * and ports are real, but other values of Ethernet, IP and transport protocols might be just
	 * filled with default values
	 * 
	 * @return	An Ethernet packet containing the information extracted from the PTMF Frame
	 */
	public byte[] getEthernetPacket() {
		byte[] ethPacket = null;
		byte[] ipv4Packet = this.getIpv4Packet();
		if(ipv4Packet != null) {
			ethPacket = Pcap.createEthernetPacket(DEFAULT_MAC, DEFAULT_MAC, Pcap.ETHERTYPE_IPV4, ipv4Packet);
		};
		return ethPacket;
	};
	
	/**
	 * This method returns a PCAP Frame containing the information that was extracted from
	 * the PTMF Frame
	 * As explained before, the PTMF Frame does not always contain a complete IPv4 frame
	 * (it can happen that it contains just a layer 5 frame and some IP addresses and ports),
	 * so this PCAP frame is just a reconstruction in which layer 5 as well as frame number,
	 * arrival date, IP addresses and ports are real, but other values of IP and transport
	 * protocols might be just filled with default values
	 * 
	 * @return	A PCAP frame containing the information extracted from the PTMF Frame
	 */
	public byte[] getPcapFrame() {
		byte[] pcapFrame = null;
		byte[] ethPacket = this.getEthernetPacket();
		int dateInt;
		if(ethPacket != null) {
			dateInt = (int) (this.getDate().getTime()/1000);
			pcapFrame = Pcap.createPcapFrame(dateInt, 1000 * this.getMilisecondInt(), ethPacket.length, ethPacket);
		};
		return pcapFrame;
	};
	
	/**
	 * Creates a date using its year, month, day, hour, minute and second components
	 * 
	 * @param	year	the year component
	 * @param	month	the month component
	 * @param	day		the day component
	 * @param	hour	the hour component
	 * @param	minute	the minute component
	 * @param	second	the second component
	 * @return			the date
	 */
	private static Date createDate(int year, int month, int day, int hours, int minutes, int seconds) {
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		String dateInString = Integer.toString(year)+"-"+Integer.toString(month)+"-"+Integer.toString(day)+" "+Integer.toString(hours)+":"+Integer.toString(minutes)+":"+Integer.toString(seconds);
		Date date = null;
		try {
			date = sdf.parse(dateInString);
		} catch (Exception e) {
			// This exception should never take place, but it is mandatory to try-catch
			System.err.println("Exception in createDate:");
			System.err.println(e.toString());
		};
		return date;
	};
	
	/**
	 * This method checks whether the byte content of a PtmfFrame is
	 * too short for an actual frame of its type
	 * 
	 * I'm introducing this method since we've found that recently
	 * upgraded SBCs are including some new content at the end of the
	 * PTMF file (so ptmf2pcap would try to parse it as another frame).
	 * This method is helpful to detect when this happens
	 * 
	 * @return	Whether the byte content is too short
	 */
	public boolean isTooShort() {
		boolean result = false;
		if(this.getByteContent().length < this.GET_FRAME_HEADER_LENGTH()) {
			result = true;
		}
		return result;
	};
	
};