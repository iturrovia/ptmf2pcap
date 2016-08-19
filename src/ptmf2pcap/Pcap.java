package ptmf2pcap;

import java.util.ArrayList;
import java.net.InetAddress;
import java.util.HashMap;

/*
 * This class provides the tools that ptmf2pcap application needs to insert network
 * messages in a PCAP file. Thus, it provides methods to:
 *     - Create a PCAP file out of a group of PCAP frames
 *     - Create a PCAP frame out of an Ethernet packet
 *     - Create an Ethernet packet out of an IP packet
 *     - Create an IPv4 packet out of a transport (UDP, TCP or SCTP) packet
 *     - Create a transport packet (UDP, TCP or SCTP) out of a network message (SIP, Diameter, etc)
 * Note that, the methods creating IP and transport packets take as input only the most relevant parameters
 * (IPs, ports, protocol and body) but not all the parameters that are used to fill the IP and transport
 * headers (which will take default values), this is done this way because the PTMF frames that this ptmf2pcap
 * application is translating do not contain the whole IP and transport frames, but just those most relevant
 * parameters (IPs, ports, protocol and body), so the rest of the IP and transport headers need to be reconstructed
 * with default values.
 */
public class Pcap {
	/*
	 * Constants for PCAP file header (Thanks to http://www.kroosec.com/2012/10/a-look-at-pcap-file-format.html for the info)
	 * Note that data in headers is written in little endian
	 */
	private static final byte[] PCAP_HEADER_FILE_SIGNATURE 		= { (byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1 }; // PCAP file signature (magic number) 
	private static final byte[] PCAP_HEADER_VERSION 			= { (byte) 0x02, (byte) 0x00, (byte) 0x04, (byte) 0x00 }; // PCAP File format version 2.4
	private static final byte[] PCAP_HEADER_GMT_OFFSET 			= { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }; // GMT timezone offset minus timezone used in the headers (seconds)
	private static final byte[] PCAP_HEADER_TIMESTAMP_ACCURACY	= { (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 }; // Accuracy of the timestamps in the capture
	private static final byte[] PCAP_HEADER_SNAPSHOT_LENGTH		= { (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00 }; // Snapshot length (maximum length of the captured packets) (bytes)
	
	/*
	 * Constants for LINKTYPE definitions
	 * We are only defining the one for Ethernet since it is the only one we are using so far
	 * Doc on the Link Types can be found on http://www.tcpdump.org/linktypes.html
	 */
	public static final int LINKTYPE_ETHERNET = 1;
	
	/*
	 * Constants for ETHERNET PROTOCOL definitions
	 * We are only defining the IDs for IPv4 protocol, since it is the only one we are using so far
	 */
	public static final byte[] ETHERTYPE_IPV4 = { (byte) 0x08, (byte) 0x00};
	
	/*
	 * Constants for IP PROTOCOL definitions
	 * We are only defining the IDs for transport protocols UDP, TCP and SCTP since they are the only transport protocols we are using so far
	 */
	public static final int IP_PROTOCOL_TCP = 6; 
	public static final int IP_PROTOCOL_UDP = 17;
	public static final int IP_PROTOCOL_SCTP = 132;
	
	/*
	 * Constants for UDP PROTOCOL definitions
	 * We are only defining the ports for Syslog since it is the only one we need so far
	 */
	public static final int UDP_PROTOCOL_SYSLOG = 514; 

	/*
	 * As transport layers (TCP and SCTP) make use of sequence numbers, we need to keep track of them
	 * so we can fill them consistently in the transport frames we will generate (otherwise Wireshark
	 * would mark them as resent or out of order frames)
	 * Thus, in order to keep track of sequence numbers, for each transport layer we define a
	 * "socket_id to sequence_number" hashmap
	 *
	 * Regarding SCTP, note that we are storing just a generic sequence number, whereas SCTP needs to manage
	 * not just one but two different sequence numbers (Transmission Sequence Number and Stream Sequence Number).
	 * However,since this ptmf2pcap application will only use one stream, one sequence number is enough to
	 * easily generate both Transmission Sequence Number and Stream Sequence Number
	 *
	 * Note that this implementation for sequence number handling takes the assumption that the Pcap class
	 * is only used in the context of one execution of ptmf2pcap application, so we never have two concurrent
	 * processes making use of the Pcap class and possibly colisioning when updating the sequence number hashmap.
	 * Otherwise we would need to implement sequence number handling at each TCP/SCTP encoding session, so we could
	 * allow two TCP/SCTP encoding sessions to encode traffic for equivalent (same IPs and ports) sockets without
	 * collisions in the sequence number handling
	 */
	private static HashMap<String,Long> tcpSeqNumHashMap = new HashMap<String,Long>();
	private static HashMap<String,Integer> sctpTsnHashMap = new HashMap<String,Integer>();
	
	/**
	 * Resets all TCP sequence numbering
	 */
	public static void resetTcpSeqNums() {
		tcpSeqNumHashMap.clear();
	};
	
	/**
	 * Returns the TCP Sequence Number for the new TCP packet to be created with the provided parameters
	 *
	 * @param	srcPort		the source port of the TCP packet to be created
	 * @param	dstPort		the destination port of the TCP packet to be created
	 * @param	bodyLength	the body length of the TCP packet to be created
	 * @param	srcIp		the source IP of the TCP packet to be created
	 * @param	dstIp		the destination IP of the TCP packet to be created
	 * @return				the TCP sequence number
	 */
	public static long getTcpSeqNum(int srcPort, int dstPort, int bodyLength, InetAddress srcIp, InetAddress dstIp) {
		String seqNumKey = srcIp.getHostAddress() + ":" +Integer.toString(srcPort) + "-" + dstIp.getHostAddress() + ":" + Integer.toString(dstPort);
		Long currentSeqNum = tcpSeqNumHashMap.get(seqNumKey);
		if(currentSeqNum == null) {
			currentSeqNum = new Long(0);
		};
		tcpSeqNumHashMap.put(seqNumKey, new Long((currentSeqNum.longValue() + (long)bodyLength)  % 4294967296L));
		return currentSeqNum.longValue();
	}
	
	/**
	 * Returns the TCP Sequence Number to be acknowled by the new TCP packet to be created with the provided parameters
	 *
	 * @param	srcPort		the source port of the TCP packet to be created
	 * @param	dstPort		the destination port of the TCP packet to be created
	 * @param	bodyLength	the body length of the TCP packet to be created
	 * @param	srcIp		the source IP of the TCP packet to be created
	 * @param	dstIp		the destination IP of the TCP packet to be created
	 * @return				the TCP sequence number to be acknowledged
	 */
	public static long getTcpAckNum(int srcPort, int dstPort, int bodyLength, InetAddress srcIp, InetAddress dstIp) {
		String ackNumKey = dstIp.getHostAddress() + ":" +Integer.toString(dstPort) + "-" + srcIp.getHostAddress() + ":" + Integer.toString(srcPort);
		Long ackNum = tcpSeqNumHashMap.get(ackNumKey);
		if(ackNum == null) {
			ackNum = new Long(0);
		};
		return ackNum.longValue();
	}
	
	/**
	 * Resets all SCTP sequence numbering
	 */
	public static void resetSctpSeqNums() {
		sctpTsnHashMap.clear();
	};
	
	/**
	 * Returns the SCTP Sequence Number for the new SCTP packet to be created with the provided parameters
	 * Note that we are storing just a generic sequence number, whereas SCTP needs to manage not just one but
	 * two different sequence numbers (Transmission Sequence Number and Stream Sequence Number). However,
	 * since this ptmf2pcap application will only use one stream, one sequence number is enough to easily generate
	 * both Transmission Sequence Number and Stream Sequence Number
	 *
	 * @param	srcPort		the source port of the SCTP packet to be created
	 * @param	dstPort		the destination port of the SCTP packet to be created
	 * @param	bodyLength	the body length of the SCTP packet to be created
	 * @param	srcIp		the source IP of the SCTP packet to be created
	 * @param	dstIp		the destination IP of the SCTP packet to be created
	 * @return				the SCTP sequence number
	 */
	public static int getSctpSeqNum(int srcPort, int dstPort, int bodyLength, InetAddress srcIp, InetAddress dstIp) {
		String seqNumKey = srcIp.getHostAddress() + ":" +Integer.toString(srcPort) + "-" + dstIp.getHostAddress() + ":" + Integer.toString(dstPort);
		int seqNum;
		Integer currentSeqNum = sctpTsnHashMap.get(seqNumKey);
		if(currentSeqNum == null) {
			currentSeqNum = new Integer(0);
		};
		sctpTsnHashMap.put(seqNumKey, new Integer((currentSeqNum.intValue() + 1) % 65536));
		return currentSeqNum.intValue();
	}
	
	/**
	 * Returns a PCAP file containing all the PCAP frames provided in the input ArrayList
	 *
	 * @param	pcapFrameArrayList	the frames to be included in the PCAP file
	 * @param	linkType			the link type
	 * @return						the PCAP file
	 */
	public static byte[] createPcapFile(ArrayList<byte[]> pcapFrameArrayList, int linkType) {
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		bytesArrayList.add(PCAP_HEADER_FILE_SIGNATURE);
		bytesArrayList.add(PCAP_HEADER_VERSION);
		bytesArrayList.add(PCAP_HEADER_GMT_OFFSET);
		bytesArrayList.add(PCAP_HEADER_TIMESTAMP_ACCURACY);
		bytesArrayList.add(PCAP_HEADER_SNAPSHOT_LENGTH);
		bytesArrayList.add(ByteUtils.intToByteArray(linkType, 4, true));
		for(int index = 0; index < pcapFrameArrayList.size(); index++) {
			bytesArrayList.add(pcapFrameArrayList.get(index));
		};
		return ByteUtils.join(bytesArrayList);
	};
	
	/**
	 * Returns a PCAP frame
	 *
	 * @param	dateInt					the date in integer format
	 * @param	microseconds			the microseconds to be added to the date
	 * @param	originalFrameSizeInt	the size of the original frame (before possible cropping)
	 * @param	packet					the packet to be included within the PCAP frame
	 * @return							the PCAP frame
	 */
	public static byte[] createPcapFrame(int dateInt, int microseconds, int originalFrameSizeInt, byte[] packet) {
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		bytesArrayList.add(ByteUtils.intToByteArray(dateInt, 4, true));					// Date
		bytesArrayList.add(ByteUtils.intToByteArray(microseconds, 4, true));			// Microseconds
		bytesArrayList.add(ByteUtils.intToByteArray(packet.length, 4, true));			// Saved Frame Size
		bytesArrayList.add(ByteUtils.intToByteArray(originalFrameSizeInt, 4, true));	// Original Frame Size
		bytesArrayList.add(packet);														// The packet itself
		return ByteUtils.join(bytesArrayList);
	};

	/**
	 * Returns an ethernet packet
	 *
	 * @param	srcMac		the source MAC address
	 * @param	dstMac		the destination MAC address
	 * @param	protocol	the protocol of the body to be included in the Ethernet packet
	 * @param	body		the body to be included in the Ethernet packet
	 * @return				the Ethernet packet
	 */
	public static byte[] createEthernetPacket(byte[] srcMac, byte[] dstMac, byte[] protocol, byte[] body) {
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		bytesArrayList.add(srcMac);		// source MAC
		bytesArrayList.add(dstMac);		// destination MAC
		bytesArrayList.add(protocol);	// protocol
		bytesArrayList.add(body);		// the body itself
		return ByteUtils.join(bytesArrayList);
	};
	
	/**
	 * Returns an IPv4 packet
	 *
	 * @param	srcIp		the source IP address
	 * @param	dstIp		the destination IP address
	 * @param	protocol	the protocol of the body to be included in the IPv4 packet
	 * @param	body		the body to be included in the IPv4 packet
	 * @return				the IPv4 packet
	 */
	public static byte[] createIpv4Packet(InetAddress srcIp, InetAddress dstIp, int protocol, byte[] body) {
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		bytesArrayList.add(new byte[]{ (byte) 0x45, (byte) 0x00});											// version, header length, type of service
		bytesArrayList.add(ByteUtils.intToByteArray(20 + body.length, 2, false));							// total length
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00, (byte) 0x40, (byte) 0x00, (byte) 0x40});	// identification, flags, fragment offset, time to live
		bytesArrayList.add(ByteUtils.intToByteArray(protocol, 1, false));									// protocol
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00});											// checksum
		bytesArrayList.add(srcIp.getAddress());																// source IP
		bytesArrayList.add(dstIp.getAddress());																// destination IP
		bytesArrayList.add(body);																			// the body itself
		return ByteUtils.join(bytesArrayList);
	};
	
	/**
	 * Returns an UDP packet
	 *
	 * @param	srcPort	the source port
	 * @param	dstPort	the destination port
	 * @param	body	the body to be included in the UDP packet
	 * @return			the UDP packet
	 */
	public static byte[] createUdpPacket(int srcPort, int dstPort, byte[] body) {
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		bytesArrayList.add(ByteUtils.intToByteArray(srcPort, 2, false));			// source port
		bytesArrayList.add(ByteUtils.intToByteArray(dstPort, 2, false));			// destination port
		bytesArrayList.add(ByteUtils.intToByteArray(8 + body.length, 2, false));	// packet length
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00});					// checksum
		bytesArrayList.add(body);													// the body itself
		return ByteUtils.join(bytesArrayList);
	};
	
	/**
	 * Returns an TCP packet
	 *
	 * @param	srcPort	the source port
	 * @param	dstPort	the destination port
	 * @param	srcIp	the source IP address
	 * @param	dstIp	the destination IP address
	 * @param	body	the body to be included in the TCP packet
	 * @return			the TCP packet
	 */
	public static byte[] createTcpPacket(int srcPort, int dstPort, byte[] body, InetAddress srcIp, InetAddress dstIp) {
		byte[] tcpPacket = new byte[32 + body.length];
		long seqNum = getTcpSeqNum(srcPort, dstPort, body.length, srcIp, dstIp);
		long ackNum = getTcpAckNum(srcPort, dstPort, body.length, srcIp, dstIp);
		byte[] flags = new byte[1];
		if(ackNum == 0) {
			flags[0] = (byte) 0x08;	// PSH=1
		} else {
			flags[0] = (byte) 0x18;	// PSH=1, ACK=1
		};
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		bytesArrayList.add(ByteUtils.intToByteArray(srcPort, 2, false));	// source port
		bytesArrayList.add(ByteUtils.intToByteArray(dstPort, 2, false));	// destination port
		bytesArrayList.add(ByteUtils.longToByteArray(seqNum, 4, false));	// sequence number
		bytesArrayList.add(ByteUtils.longToByteArray(ackNum, 4, false));	// ack number
		bytesArrayList.add(new byte[]{ (byte) 0x80});						// header length
		bytesArrayList.add(flags);											// flags
		bytesArrayList.add(new byte[]{ (byte) 0xFF, (byte) 0xFF});			// windowSize
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00});			// checkSum
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00});			// urgentPointer
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00,
										(byte) 0x00, (byte) 0x00,
										(byte) 0x00, (byte) 0x00,
										(byte) 0x00, (byte) 0x00,
										(byte) 0x00, (byte) 0x00,
										(byte) 0x00, (byte) 0x00});			// options
		bytesArrayList.add(body);											// body
		return ByteUtils.join(bytesArrayList);
	};
	
	/**
	 * Returns an SCTP packet
	 *
	 * @param	srcPort	the source port
	 * @param	dstPort	the destination port
	 * @param	srcIp	the source IP address
	 * @param	dstIp	the destination IP address
	 * @param	body	the body to be included in the SCTP packet
	 * @return			the SCTP packet
	 */
	public static byte[] createSctpPacket(int srcPort, int dstPort, byte[] body, InetAddress srcIp, InetAddress dstIp) {
		int paddingLength = (4 - (16 + body.length) % 4) % 4;
		byte[] paddingByte = { (byte) 0xFF};
		byte[] paddingBytes = null;
		paddingBytes = new byte[paddingLength];
		for(int i = 0; i < paddingBytes.length; i++) {
			System.arraycopy(paddingByte, 0, paddingBytes, i, paddingByte.length);
		};
		int seqNum = getSctpSeqNum(srcPort, dstPort, body.length, srcIp, dstIp);
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		bytesArrayList.add(ByteUtils.intToByteArray(srcPort, 2, false));			// source port
		bytesArrayList.add(ByteUtils.intToByteArray(dstPort, 2, false));			// destination port
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00,
										(byte) 0x00, (byte) 0x00});					// verification tag
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00,
										(byte) 0x00, (byte) 0x00});					// checksum
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x03});					// chunk type and flags
		bytesArrayList.add(ByteUtils.intToByteArray(16 + body.length, 2, false));	// chunk length
		bytesArrayList.add(ByteUtils.intToByteArray(seqNum, 4, false));				// transmission sequence number (TSN)
		bytesArrayList.add(new byte[]{ (byte) 0x00, (byte) 0x00});					// stream ID
		bytesArrayList.add(ByteUtils.intToByteArray(seqNum, 2, false));				// stream sequence number
		bytesArrayList.add(ByteUtils.intToByteArray(0, 4, false));					// payload protocol ID
		bytesArrayList.add(body);													// the body itself
		bytesArrayList.add(paddingBytes);											// padding bytes
		return ByteUtils.join(bytesArrayList);
	};
	
};