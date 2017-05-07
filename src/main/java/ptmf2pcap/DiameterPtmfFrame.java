package ptmf2pcap;

/**
 * DiameterPtmfFrame object represents a PTMF frame of Diameter type
 *
 * The frames of this type do not contain an Ethernet packet with all the upper layers,
 * but contains just the SIP layer, IP and ports. Thus:
 *    - The transport protocol is assumed to be SCTP
 *    - MAC addresses, checksums and so on are filled with default values (typically zeroes)
 */
public class DiameterPtmfFrame extends PtmfFrame {

	/*
	 * DiameterPtmfFrame constants
	 */
	public static final int FRAME_HEADER_LENGTH = 108;
	private static final int SRCIP_OFFSET = 64;
	private static final int DSTIP_OFFSET = 86;
	private static final int SRCPORT_OFFSET = 80;
	private static final int DSTPORT_OFFSET = 102;
	
	/**
	 * Returns a DiameterPtmfFrame object
	 *
	 * @return	The DiameterPtmfFrame object
	 */
	public DiameterPtmfFrame() {
		super();
	};
	
	/**
	 * Returns a DiameterPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @return	The DiameterPtmfFrame object
	 */
	public DiameterPtmfFrame(byte[] byteContent) {
		super(byteContent);
	};
	
	/**
	 * Returns a DiameterPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @param	order	the relative order of the frame
	 * @return	The DiameterPtmfFrame object
	 */
	public DiameterPtmfFrame(byte[] byteContent, int order) {
		super(byteContent, order);
	};
	
	/**
	 * Returns the frame in an IPv4 packet
	 * The transport layer is assumed to be SCTP, although
	 * there the original PTMF frame contains no information about it
	 * SCTP is assumed because it is often the case in Telco
	 * deployments in which Huawei SBCs and their PTMF traces are found
	 *
	 * @return	The IPv4 packet
	 */
	public byte[] getIpv4Packet() {
		byte[] sctpPacket = null;
		byte[] ipv4Packet = null;
		
		sctpPacket = Pcap.createSctpPacket(this.getSrcPort(), this.getDstPort(), this.getBody(), this.getSrcIp(), this.getDstIp());
		ipv4Packet = Pcap.createIpv4Packet(this.getSrcIp(), this.getDstIp(), Pcap.IP_PROTOCOL_SCTP, sctpPacket);
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