package edu.wisc.cs.sdn.vnet.rt;

import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;
import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Data;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMP;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.MACAddress;
import net.floodlightcontroller.packet.RIPv2;
import net.floodlightcontroller.packet.RIPv2Entry;
import net.floodlightcontroller.packet.UDP;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	private ConcurrentHashMap<Integer, LinkedBlockingQueue<EtherpacketAndInIface>> ipToQueue;
	
	public static final long ROUTETEBLE_TIME_OUT = 30000;
	public static final long RIP_RESPONSE_INTERVAL = 10000;
	static final Object lockObj = new Object();
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
		this.ipToQueue = new ConcurrentHashMap<Integer, LinkedBlockingQueue<EtherpacketAndInIface>>();
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
		case Ethernet.TYPE_ARP:
			this.handleArpPacket(etherPacket, inIface);
			break;
		}
		
		/********************************************************************/
	}
	
	private void handleArpPacket(Ethernet etherPacket, Iface inIface)
	{
		if (etherPacket.getEtherType() != Ethernet.TYPE_ARP)
		{ return; }
		
		ARP arpPacket = (ARP)etherPacket.getPayload();
		
		if (arpPacket.getOpCode() == ARP.OP_REQUEST)
		{
//			System.out.println("request");
			int targetIp = ByteBuffer.wrap(arpPacket.getTargetProtocolAddress()).getInt();
			if (targetIp != inIface.getIpAddress())
				{ return; }
			sendArpReply(etherPacket, inIface);
		} else if(arpPacket.getOpCode() == ARP.OP_REPLY)
		{
			// handle arp reply
			int ip;
			if (arpPacket.getProtocolType() == ARP.PROTO_TYPE_IP) {
				ByteBuffer wrapped = ByteBuffer.wrap(arpPacket.getSenderProtocolAddress());
				ip = wrapped.getInt();
				arpCache.insert(MACAddress.valueOf(arpPacket.getSenderHardwareAddress()), ip);
//				System.out.println(MACAddress.valueOf(arpPacket.getSenderHardwareAddress()));
				if (ipToQueue.get(ip) != null) {
					for (EtherpacketAndInIface ether : ipToQueue.get(ip)) {
						ether.ethernet.setDestinationMACAddress(arpPacket.getSenderHardwareAddress());
						sendPacket(ether.ethernet, inIface);
					}
				}
				// remove queue
				ipToQueue.remove(ip);
			}		
		}
		return;
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
        
        // handle RIP 
     	// destination 224.0.0.9, a protocol type of UDP, and a UDP destination port of 520
     	if (ipPacket.getDestinationAddress() == IPv4.toIPv4Address("224.0.0.9") && ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
     		UDP udpPacket = (UDP) ipPacket.getPayload();
     		if (udpPacket.getDestinationPort() == UDP.RIP_PORT) {
     			RIPv2 rip = (RIPv2) udpPacket.getPayload();
     			switch(rip.getCommand()) 
     			{
     			case RIPv2.COMMAND_REQUEST:
     				sendRipReply(etherPacket, inIface);
     				break;
     			case RIPv2.COMMAND_RESPONSE:
     				ripResponseHandler(rip, inIface);
     				break;
     			}
     		return;
     		}
     	}
        
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
        			ICMP icmp = (ICMP)ipPacket.getPayload();
        			if (icmp.getIcmpType() == ICMP.TYPE_ECHO_REQUEST)
        			{ sendIcmpPacket(etherPacket, inIface, ICMP.TYPE_ECHO_REPLY, ICMP.CODE_ECHO_REPLY); }
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
        	ipToQueue.computeIfAbsent(nextHop, v -> new LinkedBlockingQueue<EtherpacketAndInIface>());
        	ipToQueue.computeIfPresent(nextHop, (k, v) -> {
        		try {
        			v.put(new EtherpacketAndInIface(etherPacket, inIface));
        		} catch (InterruptedException e) {
        			e.printStackTrace();
        		} return v;
        		});
        	
        	if (ipToQueue.get(nextHop) != null && ipToQueue.get(nextHop).size() == 1)
        	{
        		Thread t = new Thread(new ArpRequestSender(nextHop, ipToQueue, inIface, this));
        		t.start();
        	}
        	
//        	// sendIcmpPacket(etherPacket, inIface, ICMP.TYPE_DESTINATION_UNREACHABLE, ICMP.CODE_UNREACHABLE_HOST);
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
		case ICMP.TYPE_TIME_EXCEED:
			// set icmp payload 
			ICMP icmpPacket = (ICMP) ipPacket.getPayload();
			icmp.setPayload(icmpPacket.getPayload());
			break;
		default:
			// set icmp payload
			length = 4 + ipPacket.getHeaderLength() * 4 + 8;
			databyte = new byte[length];
			bb = ByteBuffer.wrap(databyte);
			// 4 bytes paddings
			for (int i = 0; i < 4; ++i) {
				bb.put((byte) (0));
			}
			// ip header and 8 byte following payload
			bb.put(ipPacket.serialize(), 0, ipPacket.getHeaderLength() * 4 + 8);
			data.setData(databyte);
			icmp.setPayload(data);
			break;
		}
    	this.sendPacket(ether, outIface);
    }
    
    private void sendArpReply(Ethernet etherPacket, Iface inIface)
    {
    	ARP arpPacket = (ARP)etherPacket.getPayload();
    	
    	// set reply packet
    	Ethernet ether = new Ethernet();
    	ARP arp = new ARP();
    	
    	// set ethernet header
    	ether.setPayload(arp);
    	ether.setEtherType(Ethernet.TYPE_ARP);
    	ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
    	ether.setDestinationMACAddress(etherPacket.getSourceMACAddress());
    	
    	// set arp header
    	arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
    	arp.setProtocolType(ARP.PROTO_TYPE_IP);
    	arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
    	arp.setProtocolAddressLength((byte) 4);
    	arp.setOpCode(ARP.OP_REPLY);
    	arp.setSenderHardwareAddress(inIface.getMacAddress().toBytes());
    	arp.setSenderProtocolAddress(ByteBuffer.allocate(Integer.BYTES).putInt(inIface.getIpAddress()).array());
    	arp.setTargetHardwareAddress(arpPacket.getSenderHardwareAddress());
    	arp.setTargetProtocolAddress(arpPacket.getSenderProtocolAddress());
    	
//    	System.out.println(MACAddress.valueOf(arp.getSenderHardwareAddress()));
    	this.sendPacket(ether, inIface);
    }
    
    private void sendArpRequest(Iface outIface, int ip)
    {	
    	// set reply packet
    	Ethernet ether = new Ethernet();
    	ARP arp = new ARP();
    	
    	// set ethernet header
    	ether.setPayload(arp);
    	ether.setEtherType(Ethernet.TYPE_ARP);
    	ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
    	ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
    	
    	// set arp header
    	arp.setHardwareType(ARP.HW_TYPE_ETHERNET);
    	arp.setProtocolType(ARP.PROTO_TYPE_IP);
    	arp.setHardwareAddressLength((byte) Ethernet.DATALAYER_ADDRESS_LENGTH);
    	arp.setProtocolAddressLength((byte) 4);
    	arp.setOpCode(ARP.OP_REQUEST);
    	arp.setSenderHardwareAddress(outIface.getMacAddress().toBytes());
    	arp.setSenderProtocolAddress(ByteBuffer.allocate(Integer.BYTES).putInt(outIface.getIpAddress()).array());
    	arp.setTargetHardwareAddress(MACAddress.valueOf(0).toBytes());
    	arp.setTargetProtocolAddress(ByteBuffer.allocate(Integer.BYTES).putInt(ip).array());
    	
    	this.sendPacket(ether, outIface);
    }
    
    private class ArpRequestSender implements Runnable
    {
    	private int ip;
    	private ConcurrentHashMap<Integer, LinkedBlockingQueue<EtherpacketAndInIface>> ipToQueue;
    	private Iface inIface;
    	private Router router;
    	
    	public ArpRequestSender(int ipAddress, ConcurrentHashMap<Integer, LinkedBlockingQueue<EtherpacketAndInIface>> map, Iface inIface, Router router)
    	{
    		this.ip = ipAddress;
    		this.ipToQueue = map;
    		this.inIface = inIface;
    		this.router = router;
    	}
		@Override
		public void run() {
			// TODO Auto-generated method stub
			for (int i = 0; i < 3; ++i) 
			{
				// if map does not contain ip, the ip is in arp cache
				if (ipToQueue.containsKey(ip))
				{
					// broadcast arp request
					for (Iface iface : router.interfaces.values()) 
					{
							sendArpRequest(iface, ip);
					}
					try {
						Thread.sleep((long) 1000);
					} catch (InterruptedException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				} else {
					return;
				}
			}
			// 3 times and no corresponding ARP reply. send destination unreachable
			if (ipToQueue.containsKey(ip))
			{
				for (EtherpacketAndInIface ether : ipToQueue.get(ip)) {
					sendIcmpPacket(ether.ethernet, ether.inIface, ICMP.TYPE_DESTINATION_UNREACHABLE, ICMP.CODE_UNREACHABLE_HOST);
				}
				
			}
			ipToQueue.remove(ip);
		}	
    }
    
    private class EtherpacketAndInIface {
    	public Ethernet ethernet;
    	public Iface inIface;
    	
    	public EtherpacketAndInIface(Ethernet ethernet, Iface inIface) {
    		this.ethernet = ethernet;
    		this.inIface = inIface;
    	}
    }
    
    public void ripBroadcast(int ripCommand) {
    	Ethernet ether = new Ethernet();
    	IPv4 ip = new IPv4();
    	UDP udp = new UDP();
    	RIPv2 rip = new RIPv2();
    	ether.setPayload(ip);
    	ip.setPayload(udp);
    	udp.setPayload(rip);
    	// set ethernet header
    	ether.setEtherType(Ethernet.TYPE_IPv4);
    	ether.setDestinationMACAddress("FF:FF:FF:FF:FF:FF");
    	
    	// set ip header
    	ip.setDestinationAddress("224.0.0.9");
    	ip.setProtocol(IPv4.PROTOCOL_UDP);
    	ip.setTtl((byte) (15));
    	
    	// set udp
    	udp.setDestinationPort(UDP.RIP_PORT);
    	udp.setSourcePort(UDP.RIP_PORT);
    	// set rip
    	switch(ripCommand) 
    	{
    	case RIPv2.COMMAND_RESPONSE:
    		// set entries
    		for (Iface outIface : this.interfaces.values()) {
        		ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
        		ip.setSourceAddress(outIface.getIpAddress());
				for (RouteEntry entry : routeTable.getEntries()) {
					RIPv2Entry ripEntry = new RIPv2Entry(entry.getDestinationAddress(), entry.getMaskAddress(), entry.getMetric());
					ripEntry.setNextHopAddress(outIface.getIpAddress());
					rip.addEntry(ripEntry);
				}
				rip.setCommand(RIPv2.COMMAND_RESPONSE);
				this.sendPacket(ether, outIface);
    		}
        	break;
    	case RIPv2.COMMAND_REQUEST:
    		for (Iface outIface : this.interfaces.values()) {
    			ether.setSourceMACAddress(outIface.getMacAddress().toBytes());
        		ip.setSourceAddress(outIface.getIpAddress());
				for (RouteEntry entry : routeTable.getEntries()) {
					RIPv2Entry ripEntry = new RIPv2Entry(entry.getDestinationAddress(), entry.getMaskAddress(), entry.getMetric());
					ripEntry.setNextHopAddress(outIface.getIpAddress());
					rip.addEntry(ripEntry);
				}
				rip.setCommand(RIPv2.COMMAND_REQUEST);
				this.sendPacket(ether, outIface);
        	}
    		break;
    	}
    }
    
    public void sendRipReply(Ethernet ethernet, Iface inIface) {
    	Ethernet ether = new Ethernet();
    	IPv4 ip = new IPv4();
    	UDP udp = new UDP();
    	RIPv2 rip = new RIPv2();
    	ether.setPayload(ip);
    	ip.setPayload(udp);
    	udp.setPayload(rip);
    	// set ethernet header
    	ether.setEtherType(Ethernet.TYPE_IPv4);
    	ether.setDestinationMACAddress(ethernet.getSourceMACAddress());
    	
    	IPv4 inIp = (IPv4) ethernet.getPayload();
    	// set ip header
    	ip.setDestinationAddress(inIp.getSourceAddress());
    	ip.setProtocol(IPv4.PROTOCOL_UDP);
    	ip.setTtl((byte) (15));
    	
    	// set udp
    	udp.setDestinationPort(UDP.RIP_PORT);
    	udp.setSourcePort(UDP.RIP_PORT);
    	// set rip
    	rip.setCommand(RIPv2.COMMAND_RESPONSE);
    	
    	// set entries
    	for (RouteEntry entry : routeTable.getEntries()) {
    		RIPv2Entry ripEntry = new RIPv2Entry(entry.getDestinationAddress(), entry.getMaskAddress(), entry.getMetric());
    		ripEntry.setNextHopAddress(inIface.getIpAddress());
    		rip.addEntry(ripEntry);
    	}

    	ether.setSourceMACAddress(inIface.getMacAddress().toBytes());
    	ip.setSourceAddress(inIface.getIpAddress());
    	this.sendPacket(ether, inIface);
    }
    
    private class RouteTableHandler implements Runnable {
    	
    	private Router router;
    	private long lastResponseAt;
    	
    	public RouteTableHandler(Router router) {
    		this.router = router;
    		for (Iface iface : this.router.interfaces.values()) {
    			this.router.routeTable.insert2(iface.getIpAddress(), 0, iface.getSubnetMask(), iface, -1, 0);
    		}
//    		System.out.println(router.routeTable);
    		this.router.ripBroadcast(RIPv2.COMMAND_REQUEST);
    		this.router.ripBroadcast(RIPv2.COMMAND_RESPONSE);
    		this.lastResponseAt = System.currentTimeMillis();
    	}
    	
		@Override
		public void run() {
			// TODO Auto-generated method stub
			while (true) {
				// send response every 10 seconds
				synchronized(lockObj) {
					if (System.currentTimeMillis() - this.lastResponseAt > RIP_RESPONSE_INTERVAL) {
						router.ripBroadcast(RIPv2.COMMAND_RESPONSE);
						this.lastResponseAt = System.currentTimeMillis();
					}

					// time out route table entries for which an update has not been received for
					// more than 30 seconds

					Iterator<RouteEntry> iter = this.router.routeTable.getEntries().iterator();
					while (iter.hasNext()) {
						RouteEntry entry = iter.next();
						if (entry.getUpdatedAt() != -1
								&& (System.currentTimeMillis() - entry.getUpdatedAt()) > ROUTETEBLE_TIME_OUT) {
							iter.remove();
						}
					}
				}
				try {
					Thread.sleep(1000);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			
			
		}
    }
    
    public void initializeRouterTable() {
    	Thread t = new Thread(new RouteTableHandler(this));
		t.start();
    }
    
    public void ripResponseHandler(RIPv2 rip, Iface inIface) {
    	synchronized(lockObj) {
    		RouteEntry bestMatch;
			for (RIPv2Entry ripEntry : rip.getEntries()) {
				bestMatch = routeTable.lookup(ripEntry.getAddress());
				if (bestMatch != null && bestMatch.getDestinationAddress() == ripEntry.getAddress()) {
					if (bestMatch.getMetric() > ripEntry.getMetric() + 1) {
						routeTable.update2(ripEntry.getAddress(), ripEntry.getSubnetMask(),
								ripEntry.getNextHopAddress(), inIface, System.currentTimeMillis(),
								ripEntry.getMetric() + 1);
					}
				} else {
					routeTable.insert2(ripEntry.getAddress(), ripEntry.getNextHopAddress(), ripEntry.getSubnetMask(),
							inIface, System.currentTimeMillis(), ripEntry.getMetric() + 1);
				}
//				System.out.println(routeTable);
			}
    	}

    }
    
    
}
