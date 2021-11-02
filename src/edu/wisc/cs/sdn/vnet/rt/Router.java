package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        { 
        	// send icmp time exceed
        	sendIcmpPacket(etherPacket, inIface, ICMP.TYPE_TIME_EXCEED, ICMP.CODE_TTL_ZERO);
        	return; 
        }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{ 
        		switch(ipPacket.getProtocol())
        		{
        		case IPv4.PROTOCOL_TCP:
        		case IPv4.PROTOCOL_UDP:
        			sendIcmpPacket(etherPacket, inIface, ICMP.TYPE_DESTINATION_UNREACHABLE, ICMP.CODE_UNREACHABLE_PORT);
        			break;
        		case IPv4.PROTOCOL_ICMP:
        			sendIcmpPacket(etherPacket, inIface, ICMP.TYPE_ECHO_REPLY, ICMP.CODE_ECHO_REPLY);
        			break;
        		}
        		return; 
        	}
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        { 
        	sendIcmpPacket(etherPacket, inIface, ICMP.TYPE_DESTINATION_UNREACHABLE, ICMP.CODE_UNREACHABLE_NET);
        	return; 
        }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        {
        	sendIcmpPacket(etherPacket, inIface, ICMP.TYPE_DESTINATION_UNREACHABLE, ICMP.CODE_UNREACHABLE_HOST);
        	return; 
        }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }
    
    private void sendIcmpPacket(Ethernet etherPacket, Iface inIface, byte icmpType, byte icmpCode) 
    {
    	Ethernet ether = new Ethernet();
    	IPv4 ip = new IPv4();
    	ICMP icmp = new ICMP();
    	Data data = new Data();
    	ether.setPayload(ip);
    	ip.setPayload(icmp);
    	icmp.setPayload(data);
    	// set ethernet header
    	ether.setEtherType(Ethernet.TYPE_IPv4);
    	// Get IP header
		IPv4 ipPacket = (IPv4) etherPacket.getPayload();
		int dstAddr = ipPacket.getSourceAddress();

		// Find matching route table entry
		RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

		// If no entry matched, do nothing
		if (null == bestMatch) {
			return;
		}

		// Make sure we don't sent a packet back out the interface it came in
		Iface outIface = bestMatch.getInterface();

		// Set source MAC address in Ethernet header
		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());

		// If no gateway, then nextHop is IP destination
		int nextHop = bestMatch.getGatewayAddress();
		if (0 == nextHop) {
			nextHop = dstAddr;
		}

		// Set destination MAC address in Ethernet header
		ArpEntry arpEntry = this.arpCache.lookup(nextHop);
		if (null == arpEntry) {
			return;
		}
		ether.setDestinationMACAddress(arpEntry.getMac().toBytes());
		
		// set ip header
		ip.setTtl((byte) (64));
    	ip.setProtocol(IPv4.PROTOCOL_ICMP);
    	ip.setSourceAddress(outIface.getIpAddress());
    	ip.setDestinationAddress(ipPacket.getSourceAddress());
    	
    	// set icmp header
    	icmp.setIcmpType(icmpType);
		icmp.setIcmpCode(icmpCode);
		
		
		int length;
		byte[] databyte;
		ByteBuffer bb;
		switch(icmpType)
		{
		case ICMP.TYPE_ECHO_REPLY:
			// set icmp payload 
			ICMP icmpPacket = (ICMP) ipPacket.getPayload();
			icmp.setPayload(icmpPacket.getPayload());
			break;
		default:
			// set icmp payload
			length = 4 + ipPacket.getHeaderLength() + 8;
			databyte = new byte[length];
			bb = ByteBuffer.wrap(databyte);
			// 4 bytes paddings
			for (int i = 0; i < 4; ++i) {
				bb.put((byte) (0));
			}
			// ip header and 8 byte following payload
			bb.put(ipPacket.serialize(), 0, ipPacket.getHeaderLength() + 8);
			data.setData(databyte);
			icmp.setPayload(data);
			break;
		}
    	this.sendPacket(ether, outIface);
    }
    
    
}
