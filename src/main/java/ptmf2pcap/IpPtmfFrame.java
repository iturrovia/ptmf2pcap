package ptmf2pcap;

/**
 * IpPtmfFrame object represents a PTMF frame of IP type
 *
 * The frames of this type contain an Ethernet packet with all the upper layers,
 * so the conversion to a PCAP frame is so straightforward.
 * In fact, this conversion for this PTMF frame type should
 * be supported by Huawei Trace Viewer too.
 */
public class IpPtmfFrame extends PtmfFrame {

	/*
	 * IpPtmfFrame constants
	 */
	public static final int FRAME_HEADER_LENGTH = 87;
	private static final int FRAMENUMBER_OFFSET = 14;
	
	/**
	 * Returns a IpPtmfFrame object
	 *
	 * @return	The IpPtmfFrame object
	 */
	public IpPtmfFrame() {
		super();
	};
	
	/**
	 * Returns a IpPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @return	The IpPtmfFrame object
	 */
	public IpPtmfFrame(byte[] byteContent) {
		super(byteContent);
	};
	
	/**
	 * Returns a IpPtmfFrame object
	 *
	 * @param	byteContent	a byte array with the content of the frame
	 * @param	order	the relative order of the frame
	 * @return	The IpPtmfFrame object
	 */
	public IpPtmfFrame(byte[] byteContent, int order) {
		super(byteContent, order);
	};
	
	/**
	 * We are overriding this method from the parent class, since
	 * the PTMF frames of IP type do contain the whole Ethernet packet,
	 * so we want to preserve the original instead of having
	 * the parent class inventing one
	 *
	 * @return	the ethernet packet
	 */
	public byte[] getEthernetPacket() {
		return this.getBody();
	};
	
	/*
	 * The following method is not really useful in PTMF frames of IP type
	 * However, the abstract parent class makes it necessary to define
	 * this method, as such class was designed for all the other frames
	 * We might make this class to extend from a different one, but the
	 * redesign would mean either replicating code or redesigning the application,
	 * which is not justifiable unless we need to add more features
	 */
	 
	/**
	 * Providing an implementation although the ptmf2pcap app does not actually need it
	 * Note that this implementation only works if the payload of the Ethernet
	 * packet is actually an IP packet, since it just returns the payload
	 * of the Ethernet packet
	 * Thus, if IP packet is embedded in a VLAN packet, this method will
	 * return both the VLAN and the IP packet.
	 * Thus, support is incomplete, but completing it is not really necessary
	 * since this method is never invoked by the application
	 *
	 * @return	the payload of the Ethernet packet
	 */
	public byte[] getIpv4Packet() {
		return ByteUtils.subarray(this.getEthernetPacket(), 14, this.getEthernetPacket().length - 14);
	};
	
	/*
	 * These methods do not make much sense in PTMF frames of IP type,
	 * since the fields they retrieve do not exist in this PTMF frames'
	 * headers, and the application will never try to retrieve them for
	 * this frame type
	 * However, the abstract parent class makes it necessary to define
	 * these methods, as such class was designed for all the other frames
	 * We might make this class to extend from a different one, but the
	 * redesign would mean either replicating code or redesigning the application,
	 * which is not justifiable unless we need to add more features
	 */
	public int GET_FRAME_HEADER_LENGTH() {
		return FRAME_HEADER_LENGTH;
	};
	public int GET_SRCIP_OFFSET() {
		return 0;
	};
	public int GET_DSTIP_OFFSET() {
		return 0;
	};
	public int GET_SRCPORT_OFFSET() {
		return 0;
	};
	public int GET_DSTPORT_OFFSET() {
		return 0;
	};
	
};