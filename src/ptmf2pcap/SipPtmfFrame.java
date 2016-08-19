package ptmf2pcap;

/**
 * SipPtmfFrame object represents a PTMF frame of SIP type
 *
 * The frames of this type do not contain an Ethernet packet with all the upper layers,
 * but contains just the SIP layer, IP and ports. Thus:
 *    - The transport protocol is guessed by analysing the SIP message
 *    - MAC addresses, checksums and so on are filled with default values (typically zeroes)
 */
public class SipPtmfFrame extends PtmfFrame {

	/*
	 * SipPtmfFrame constants
	 */
	public static final int FRAME_HEADER_LENGTH = 145;
	private static final int SRCIP_OFFSET = 60;
	private static final int DSTIP_OFFSET = 82;
	private static final int SRCPORT_OFFSET = 76;
	private static final int DSTPORT_OFFSET = 98;
	
	/**
	 * Returns a SipPtmfFrame object
	 *
	 * @return	The SipPtmfFrame object
	 */
	public SipPtmfFrame() {
		super();
	};
	
	/**
	 * Returns a SipPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @return	The SipPtmfFrame object
	 */
	public SipPtmfFrame(byte[] byteContent) {
		super(byteContent);
	};
	
	/**
	 * Returns a SipPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @param	order	the relative order of the frame
	 * @return	The SipPtmfFrame object
	 */
	public SipPtmfFrame(byte[] byteContent, int order) {
		super(byteContent, order);
	};
	
	/**
	 * Returns the frame in an IPv4 packet
	 * The transport layer is guessed by analysing the SIP message content
	 *
	 * @return	The IPv4 packet
	 */
	public byte[] getIpv4Packet() {
		byte[] udpPacket = null;
		byte[] tcpPacket = null;
		byte[] sctpPacket = null;
		byte[] ipv4Packet = null;
		
		if(this.isSipOverTcp()) {
			tcpPacket = Pcap.createTcpPacket(this.getSrcPort(), this.getDstPort(), this.getBody(), this.getSrcIp(), this.getDstIp());
			ipv4Packet = Pcap.createIpv4Packet(this.getSrcIp(), this.getDstIp(), Pcap.IP_PROTOCOL_TCP, tcpPacket);
		} else if(this.isSipOverSctp()) {
			sctpPacket = Pcap.createSctpPacket(this.getSrcPort(), this.getDstPort(), this.getBody(), this.getSrcIp(), this.getDstIp());
			ipv4Packet = Pcap.createIpv4Packet(this.getSrcIp(), this.getDstIp(), Pcap.IP_PROTOCOL_SCTP, sctpPacket);
		} else {
			udpPacket = Pcap.createUdpPacket(this.getSrcPort(), this.getDstPort(), this.getBody());
			ipv4Packet = Pcap.createIpv4Packet(this.getSrcIp(), this.getDstIp(), Pcap.IP_PROTOCOL_UDP, udpPacket);
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