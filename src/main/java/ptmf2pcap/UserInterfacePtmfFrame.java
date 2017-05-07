package ptmf2pcap;

import java.net.InetAddress;
import java.util.HashMap;
import java.nio.charset.Charset;

/**
 * UserInterfacePtmfFrame object represents a PTMF frame of UserInterface type
 *
 * This kind of PTMF frame is quite special as it can contain very different types of
 * content. The frame header contains the Message Interface Type field, which can take
 * different values defining different types of content. Thus, this class needs to take
 * care of reading the Message Interface Type field, recognizing its different values
 * and parsing the frame content accordingly.
 */
public class UserInterfacePtmfFrame extends PtmfFrame {

	/*
	 * UserInterfacePtmfFrame constants
	 */
	public static final int FRAME_HEADER_LENGTH = 98;
	private static final int SRCIP_OFFSET = 54;
	private static final int DSTIP_OFFSET = 73;
	private static final int SRCPORT_OFFSET = 70;
	private static final int DSTPORT_OFFSET = 89;
	private static final int MEDIAINFO_HEADER_LENGTH = 48;
	private static final int MESSAGEINTERFACETYPE_OFFSET = 91;
	private static final int MESSAGEINTERFACETYPE_LENGTH = 2;
	private static final byte[] SYSLOG_IPV4_BYTES = { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
	
	/*
	 * There are many different Message Interface Types, but we can group them in
	 * a few categories, where  Message Interface Types in the same category will
	 * require similar parsing and conversion to PCAP frame.
	 *
	 * Thus, we define the following categories:
	 *    - Network Signaling: network signaling traffic (SIP, Diameter, DNS): these frames contain just the signaling layer, IP and ports
	 *    - Network Media: network media traffic (RTP): these frames contain the IP layer, the UDP layer and the RTP layer (which might be truncated)
	 *    - Binary Log: system logs that are enconded in binary format
	 *    - Text Log: system logs that are enconded in text format
	 *    - Unknown: frames whose content is unknown
	 *
	 * Although Binary Log, Text Log and Unknow categories do not correspond to actual network packets, we will map each of those PTMF frames into a PCAP frame,
	 * such PCAP frame will contain a Syslog message in which we will include the body of the PTMF Frame. The main purpose of doing this is to always keep a
	 * frame to frame allignment between input PTMF file and the ouput PCAP file. This way, we can analyse a network traffic capture in  Wireshark, and after that
	 * report on it making reference to the frame numbers, which are the same ones in the official PTMF files
	 */
	private static final String[][] MESSAGEINTERFACETYPE_NETWORK_SIGNALING_TABLE = {
		{"2C01", "TRACE_SIPC_UP"},
		{"2D01", "TRACE_SIPC_DOWN"},
		{"FC01", "TRACE_DNSENUM"},
		{"F901", "TRACE_DIAM_GQ"}
	};
	private static final String[][] MESSAGEINTERFACETYPE_NETWORK_MEDIA_TABLE = {
		{"1827", "TRACE_MEDIA_UP"},
		{"1927", "TRACE_MEDIA_DOWN"}
	};
	
	private static final String[][] MESSAGEINTERFACETYPE_BINLOG_TABLE = {
		{"2727", "TRACE_SIG_ACCESS_UP"},
		{"2527", "TRACE_SIG_ACCESS_DOWN"},
		{"A523", "TRACE_MI_CALL_HLLM"},
		{"5624", "TRACE_MSG_TPTD_SIPC_SUCC"},
		{"1F00", "TRACE_BC_DIAMRM"},
		{"2200", "TRACE_DIAMRM_BC"},
		{"5424", "TRACE_MSG_TPTD_SEND_SIPC"},
		{"3723", "TRACE_REG_IPB"},
		{"8D23", "TRACE_CALL_SDB"},
		{"2103", "TRACE_SDB_CALL"},
		{"2000", "TRACE_BC_DBMS"},
		{"1527", "TRACE_TOPO_TM"},
		{"1427", "TRACE_TM_TOPO"},
		{"1327", "TRACE_TM_DIST"},
		{"4101", "TRACE_SIPC_ENUM"},
		{"3001", "TRACE_SIPC_ABCF"},
		{"5524", "TRACE_MSG_SIPC_SEND_TPTD"},
		{"0100", "TRACE_LOG"},
		{"1727", "TRACE_HRU_MCU"},
		{"6902", "TRACE_H248_CRO"},
		{"6001", "TRACE_ENUM_DNS"},
		{"5E01", "TRACE_ENUM_3263"},
		{"1227", "TRACE_DIST_TM"},
		{"6302", "TRACE_CRO_SM"},
		{"6602", "TRACE_CRO_H248"},
		{"6802", "TRACE_CRO_CRO"},
		{"1627", "TRACE_CMU_HRU"},
		{"1127", "TRACE_CMU_BSU"},
		{"5203", "TRACE_CDB_CALL"},
		{"8C23", "TRACE_CALL_SIPC"},
		{"A123", "TRACE_CALL_PCDR"},
		{"8E23", "TRACE_CALL_DBMS"},
		{"8F23", "TRACE_CALL_BC"},
		{"1027", "TRACE_BSU_CMU"},
		{"2100", "TRACE_BC_RO"},
		{"A223", "TRACE_ABCF_SIPC"},
		{"1E00", "TRACE_BC_CALL"},
		{"2823", "TRACE_REG_SIPC"},
		{"8025", "TRACE_MSG_REG_SEND_AKA"},
		{"8325", "TRACE_MSG_HLLM_SEND_REG"},
		{"2923", "TRACE_REG_SDB"},
		{"2E23", "TRACE_REG_DBMS"},
		{"5A03", "TRACE_CDB_ASDB"},
		{"8125", "TRACE_MSG_AKA_SEND_REG"},
		{"4303", "TRACE_DBMS_SIPC"},
		{"2503", "TRACE_SDB_DBMS"},
		{"B824", "TRACE_MSG_SDB_IPB"},
		{"2003", "TRACE_SDB_REG"},
		{"8225", "TRACE_MSG_REG_SEND_HLLM"},
		{"5403", "TRACE_MSG_PDISP_QUERY_HLLM_DBMS"},
		{"3E01", "TRACE_SIPC_CDB"}
	};
	private static final String[][] MESSAGEINTERFACETYPE_TEXTLOG_TABLE = {
		{"0100", "TRACE_LOG"},
		{"5301", "TRACE_SIPC_TXNUP"},
		{"5401", "TRACE_SIPC_TUDOWN"},
		{"5201", "TRACE_SIPC_APP"},
		{"9E23", "TRACE_BCF_SIPC"},
		{"2227", "TRACE_QOS_UP"},
		{"2327", "TRACE_QOS_DOWN"},
		{"1C25", "TRACE_SDG_DIAG_INFO"},
		{"1C27", "TRACE_HRU_CONFIGINFO_DIAG_INFO"},
		{"1D25", "TRACE_CALL_DIAG_INFO"},
		{"2025", "TRACE_BC_DIAG_INFO"},
		{"2125", "TRACE_CRO_DIAG_INFO"},
		{"1A27", "TRACE_CMU_DIAG_INFO"},
		{"1B27", "TRACE_HRU_TERMINFO_DIAG_INFO"}
	};
	public static HashMap<String,String> MESSAGEINTERFACETYPE_NETWORK_SIGNALING_MAP = createHashMap(MESSAGEINTERFACETYPE_NETWORK_SIGNALING_TABLE);
	public static HashMap<String,String> MESSAGEINTERFACETYPE_NETWORK_MEDIA_MAP = createHashMap(MESSAGEINTERFACETYPE_NETWORK_MEDIA_TABLE);
	public static HashMap<String,String> MESSAGEINTERFACETYPE_BINLOG_MAP = createHashMap(MESSAGEINTERFACETYPE_BINLOG_TABLE);
	public static HashMap<String,String> MESSAGEINTERFACETYPE_TEXTLOG_MAP = createHashMap(MESSAGEINTERFACETYPE_TEXTLOG_TABLE);
	
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
	
	/**
	 * Returns a UserInterfacePtmfFrame object
	 *
	 * @return	The UserInterfacePtmfFrame object
	 */
	public UserInterfacePtmfFrame() {
		super();
	};
	
	/**
	 * Returns a UserInterfacePtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @return	The UserInterfacePtmfFrame object
	 */
	public UserInterfacePtmfFrame(byte[] byteContent) {
		super(byteContent);
	};
	
	/**
	 * Returns a UserInterfacePtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @param	order	the relative order of the frame
	 * @return	The UserInterfacePtmfFrame object
	 */
	public UserInterfacePtmfFrame(byte[] byteContent, int order) {
		super(byteContent, order);
	};
	
	public byte[] getMessageInterfaceTypeBytes() {
		return ByteUtils.subarray(this.getByteContent(), MESSAGEINTERFACETYPE_OFFSET, MESSAGEINTERFACETYPE_LENGTH);
	};
	public String getMessageInterfaceTypeHex() {
		return ByteUtils.bytesToHexString(this.getMessageInterfaceTypeBytes());
	};
	public String getMessageInterfaceType() {
		String messageInterfaceType = null;
		if(MESSAGEINTERFACETYPE_NETWORK_SIGNALING_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			messageInterfaceType = MESSAGEINTERFACETYPE_NETWORK_SIGNALING_MAP.get(this.getMessageInterfaceTypeHex());
		} else if(MESSAGEINTERFACETYPE_NETWORK_MEDIA_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			messageInterfaceType = MESSAGEINTERFACETYPE_NETWORK_MEDIA_MAP.get(this.getMessageInterfaceTypeHex());
		} else if(MESSAGEINTERFACETYPE_TEXTLOG_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			messageInterfaceType = MESSAGEINTERFACETYPE_TEXTLOG_MAP.get(this.getMessageInterfaceTypeHex());
		} else if(MESSAGEINTERFACETYPE_BINLOG_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			messageInterfaceType = MESSAGEINTERFACETYPE_BINLOG_MAP.get(this.getMessageInterfaceTypeHex());
		} else {
			messageInterfaceType = "UNKNOWN(0x" + this.getMessageInterfaceTypeHex() + ")";
		};
		return messageInterfaceType;
	};
	
	/**
	 * Returns the frame in an IPv4 packet
	 * 
	 * The process to do so is highly dependent on the Message Interface Type
	 * of the UserInterfacePtmfFrame
	 *
	 * @return	The IPv4 packet
	 */
	public byte[] getIpv4Packet() {
		byte[] udpPacket = null;
		byte[] tcpPacket = null;
		byte[] sctpPacket = null;
		byte[] ipv4Packet = null;
		byte[] messageInterfaceTypePrefix = null;
		byte[] hexLog = null;
		byte[] logBody = null;
		
		InetAddress syslogIp = null;
		try {
			syslogIp = InetAddress.getByAddress(SYSLOG_IPV4_BYTES);
		} catch(Exception e) {
			/*
			 * This should never happen since the argument we are passing to
			 * InetAddress.getByAddress is a constant whose value is correct,
			 * but we need to provide try-catch anyway
			 */
			System.out.println("Exception when creating syslogIp!!");
		};
		if(MESSAGEINTERFACETYPE_NETWORK_SIGNALING_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			if(this.isSipOverTcp()) {
				tcpPacket = Pcap.createTcpPacket(this.getSrcPort(), this.getDstPort(), this.getBody(), this.getSrcIp(), this.getDstIp());
				ipv4Packet = Pcap.createIpv4Packet(this.getSrcIp(), this.getDstIp(), Pcap.IP_PROTOCOL_TCP, tcpPacket);
			} else if(this.isSipOverSctp() || this.getMessageInterfaceType().equals("TRACE_DIAM_GQ")){
				sctpPacket = Pcap.createSctpPacket(this.getSrcPort(), this.getDstPort(), this.getBody(), this.getSrcIp(), this.getDstIp());
				ipv4Packet = Pcap.createIpv4Packet(this.getSrcIp(), this.getDstIp(), Pcap.IP_PROTOCOL_SCTP, sctpPacket);
			} else {
				udpPacket = Pcap.createUdpPacket(this.getSrcPort(), this.getDstPort(), this.getBody());
				ipv4Packet = Pcap.createIpv4Packet(this.getSrcIp(), this.getDstIp(), Pcap.IP_PROTOCOL_UDP, udpPacket);
			}
		} else if(MESSAGEINTERFACETYPE_NETWORK_MEDIA_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			ipv4Packet = ByteUtils.subarray(this.getBody(), MEDIAINFO_HEADER_LENGTH, this.getBody().length - MEDIAINFO_HEADER_LENGTH);
		} else if(MESSAGEINTERFACETYPE_TEXTLOG_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			// Instead of ignoring, we insert the log in a syslog message
			messageInterfaceTypePrefix = (this.getMessageInterfaceType() + ": ").getBytes(Charset.forName("UTF-8"));
			logBody = new byte[messageInterfaceTypePrefix.length + this.getBody().length];
			System.arraycopy(messageInterfaceTypePrefix, 0, logBody, 0, messageInterfaceTypePrefix.length);
			System.arraycopy(this.getBody(), 0, logBody, messageInterfaceTypePrefix.length, this.getBody().length);
			udpPacket = Pcap.createUdpPacket(Pcap.UDP_PROTOCOL_SYSLOG, Pcap.UDP_PROTOCOL_SYSLOG, logBody);
			ipv4Packet = Pcap.createIpv4Packet(syslogIp, syslogIp, Pcap.IP_PROTOCOL_UDP, udpPacket);
		} else if(MESSAGEINTERFACETYPE_BINLOG_MAP.get(this.getMessageInterfaceTypeHex()) != null) {
			// Instead of ignoring, we insert the log in a syslog message
			messageInterfaceTypePrefix = (this.getMessageInterfaceType() + ": ").getBytes(Charset.forName("UTF-8"));
			hexLog = ("0x" + ByteUtils.bytesToHexString(this.getBody())).getBytes(Charset.forName("UTF-8"));;
			logBody = new byte[messageInterfaceTypePrefix.length + hexLog.length];
			System.arraycopy(messageInterfaceTypePrefix, 0, logBody, 0, messageInterfaceTypePrefix.length);
			System.arraycopy(hexLog, 0, logBody, messageInterfaceTypePrefix.length, hexLog.length);
			udpPacket = Pcap.createUdpPacket(Pcap.UDP_PROTOCOL_SYSLOG, Pcap.UDP_PROTOCOL_SYSLOG, logBody);
			ipv4Packet = Pcap.createIpv4Packet(syslogIp, syslogIp, Pcap.IP_PROTOCOL_UDP, udpPacket);
		} else {
			// Instead of ignoring, we insert the content in a syslog message
			messageInterfaceTypePrefix = (this.getMessageInterfaceType() + ": ").getBytes(Charset.forName("UTF-8"));
			hexLog = ("0x" + ByteUtils.bytesToHexString(this.getBody())).getBytes(Charset.forName("UTF-8"));;
			logBody = new byte[messageInterfaceTypePrefix.length + hexLog.length];
			System.arraycopy(messageInterfaceTypePrefix, 0, logBody, 0, messageInterfaceTypePrefix.length);
			System.arraycopy(hexLog, 0, logBody, messageInterfaceTypePrefix.length, hexLog.length);
			udpPacket = Pcap.createUdpPacket(Pcap.UDP_PROTOCOL_SYSLOG, Pcap.UDP_PROTOCOL_SYSLOG, logBody);
			ipv4Packet = Pcap.createIpv4Packet(syslogIp, syslogIp, Pcap.IP_PROTOCOL_UDP, udpPacket);
		};
		return ipv4Packet;
	};
	
	/*
	 * Member methods to access the static constants that are
	 * defined/overriden at this class
	 */
	public int GET_FRAME_HEADER_LENGTH() {
		return FRAME_HEADER_LENGTH;
	};
	public int GET_SRCIP_OFFSET() {
		return SRCIP_OFFSET;
	};
	public int GET_DSTIP_OFFSET() {
		return DSTIP_OFFSET;
	};
	public int GET_SRCPORT_OFFSET() {
		return SRCPORT_OFFSET;
	};
	public int GET_DSTPORT_OFFSET() {
		return DSTPORT_OFFSET;
	};
	
};