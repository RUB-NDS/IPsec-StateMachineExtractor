/**
 * IPsec-StateMachineExtractor - Extract the state machine of an IKEv1/IKEv2 implementation
 *
 * Copyright © 2020 Ruhr University Bochum
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.ipsec.statemachineextractor.util;

import de.rub.nds.ipsec.statemachineextractor.ike.v1.attributes.IKEv1Attribute;
import de.rub.nds.ipsec.statemachineextractor.ipsec.AHTransformIDEnum;
import java.util.HashMap;
import java.util.Map;

/**
 * The Internet Protocol numbers found in the Protocol field of the IPv4 header
 * and the Next Header field of the IPv6 header. Based on the Assigned Internet
 * Protocol Numbers list maintained be IANA.
 *
 * @see http://www.iana.org/assignments/protocol-numbers
 * @author Dennis Felsch <dennis.felsch at ruhr-uni-bochum.de>
 */
public enum IPProtocolsEnum {
    HOPOPT("IPv6 Hop-by-Hop Option", 0),
    ICMP("Internet Control Message Protocol", 1),
    IGMP("Internet Group Management Protocol", 2),
    GGP("Gateway-to-Gateway Protocol", 3),
    IPv4("IPv4 encapsulation", 4),
    ST("Stream", 5),
    TCP("Transmission Control Protocol", 6),
    CBT("CBT", 7),
    EGP("Exterior Gateway Protocol", 8),
    IGP("any private interior gateway (used by Cisco for their IGRP)", 9),
    BBNRCCMON("BBN RCC Monitoring", 10),
    NVPII("Network Voice Protocol", 11),
    PUP("PUP", 12),
    ARGUS("ARGUS  (deprecated)", 13),
    EMCON("EMCON", 14),
    XNET("Cross Net Debugger", 15),
    CHAOS("Chaos", 16),
    UDP("User Datagram Protocol", 17),
    MUX("Multiplexing", 18),
    DCNMEAS("DCN Measurement Subsystems", 19),
    HMP("Host Monitoring", 20),
    PRM("Packet Radio Measurement", 21),
    XNSIDP("XEROX NS IDP", 22),
    TRUNK1("Trunk-1", 23),
    TRUNK2("Trunk-2", 24),
    LEAF1("Leaf-1", 25),
    LEAF2("Leaf-2", 26),
    RDP("Reliable Data Protocol", 27),
    IRTP("Internet Reliable Transaction", 28),
    ISOTP4("ISO Transport Protocol Class 4", 29),
    NETBLT("Bulk Data Transfer Protocol", 30),
    MFENSP("MFE Network Services Protocol", 31),
    MERITINP("MERIT Internodal Protocol", 32),
    DCCP("Datagram Congestion Control Protocol", 33),
    THREEPC("Third Party Connect Protocol", 34),
    IDPR("Inter-Domain Policy Routing Protocol", 35),
    XTP("XTP", 36),
    DDP("Datagram Delivery Protocol", 37),
    IDPRCMTP("IDPR Control Message Transport Proto", 38),
    TPPLUSPLUS("TP++ Transport Protocol", 39),
    IL("IL Transport Protocol", 40),
    IPv6("IPv6 encapsulation", 41),
    SDRP("Source Demand Routing Protocol", 42),
    IPv6Route("Routing Header for IPv6", 43),
    IPv6Frag("Fragment Header for IPv6", 44),
    IDRP("Inter-Domain Routing Protocol", 45),
    RSVP("Reservation Protocol", 46),
    GRE("Generic Routing Encapsulation", 47),
    DSR("Dynamic Source Routing Protocol", 48),
    BNA("BNA", 49),
    ESP("Encap Security Payload", 50),
    AH("Authentication Header", 51),
    INLSP("Integrated Net Layer Security  TUBA", 52),
    SWIPE("IP with Encryption (deprecated)", 53),
    NARP("NBMA Address Resolution Protocol", 54),
    MOBILE("IP Mobility", 55),
    TLSP("Transport Layer Security Protocol using Kryptonet key management", 56),
    SKIP("SKIP", 57),
    IPv6ICMP("ICMP for IPv6", 58),
    IPv6NoNxt("No Next Header for IPv6", 59),
    IPv6Opts("Destination Options for IPv6", 60),
    ANYHOST("any host internal protocol", 61),
    CFTP("CFTP", 62),
    ANYNET("any local network", 63),
    SATEXPAK("SATNET and Backroom EXPAK", 64),
    KRYPTOLAN("Kryptolan", 65),
    RVD("MIT Remote Virtual Disk Protocol", 66),
    IPPC("Internet Pluribus Packet Core", 67),
    ANYFS("any distributed file system", 68),
    SATMON("SATNET Monitoring", 69),
    VISA("VISA Protocol", 70),
    IPCV("Internet Packet Core Utility", 71),
    CPNX("Computer Protocol Network Executive", 72),
    CPHB("Computer Protocol Heart Beat", 73),
    WSN("Wang Span Network", 74),
    PVP("Packet Video Protocol", 75),
    BRSATMON("Backroom SATNET Monitoring", 76),
    SUNND("SUN ND PROTOCOL-Temporary", 77),
    WBMON("WIDEBAND Monitoring", 78),
    WBEXPAK("WIDEBAND EXPAK", 79),
    ISOIP("ISO Internet Protocol", 80),
    VMTP("VMTP", 81),
    SECUREVMTP("SECURE-VMTP", 82),
    VINES("VINES", 83),
    TTP("Transaction Transport Protocol", 84),
    IPTM("Internet Protocol Traffic Manager", 84),
    NSFNETIGP("NSFNET-IGP", 85),
    DGP("Dissimilar Gateway Protocol", 86),
    TCF("TCF", 87),
    EIGRP("EIGRP", 88),
    OSPFIGP("OSPFIGP", 89),
    SpriteRPC("Sprite RPC Protocol", 90),
    LARP("Locus Address Resolution Protocol", 91),
    MTP("Multicast Transport Protocol", 92),
    AX25("AX.25 Frames", 93),
    IPIP("IP-within-IP Encapsulation Protocol", 94),
    MICP("Mobile Internetworking Control Pro. (deprecated)", 95),
    SCCSP("Semaphore Communications Sec. Pro.", 96),
    ETHERIP("Ethernet-within-IP Encapsulation", 97),
    ENCAP("Encapsulation Header", 98),
    ANYENC("any private encryption scheme", 99),
    GMTP("GMTP", 100),
    IFMP("Ipsilon Flow Management Protocol", 101),
    PNNI("PNNI over IP", 102),
    PIM("Protocol Independent Multicast", 103),
    ARIS("ARIS", 104),
    SCPS("SCPS", 105),
    QNX("QNX", 106),
    AN("Active Networks", 107),
    IPComp("IP Payload Compression Protocol", 108),
    SNP("Sitara Networks Protocol", 109),
    CompaqPeer("Compaq Peer Protocol", 110),
    IPXinIP("IPX in IP", 111),
    VRRP("Virtual Router Redundancy Protocol", 112),
    PGM("PGM Reliable Transport Protocol", 113),
    ANY0HOP("any 0-hop protocol", 114),
    L2TP("Layer Two Tunneling Protocol", 115),
    DDX("D-II Data Exchange (DDX)", 116),
    IATP("Interactive Agent Transfer Protocol", 117),
    STP("Schedule Transfer Protocol", 118),
    SRP("SpectraLink Radio Protocol", 119),
    UTI("UTI", 120),
    SMP("Simple Message Protocol", 121),
    SM("Simple Multicast Protocol (deprecated)", 122),
    PTP("Performance Transparency Protocol", 123),
    ISISoverIPv4("ISIS over IPv4", 124),
    FIRE("FIRE", 125),
    CRTP("Combat Radio Transport Protocol", 126),
    CRUDP("Combat Radio User Datagram", 127),
    SSCOPMCE("SSCOPMCE", 128),
    IPLT("IPLT", 129),
    SPS("Secure Packet Shield", 130),
    PIPE("Private IP Encapsulation within IP", 131),
    SCTP("Stream Control Transmission Protocol", 132),
    FC("Fibre Channel", 133),
    RSVPE2EIGNORE("RSVPE2EIGNORE", 134),
    MobilityHeader("Mobility", 135),
    UDPLite("UDPLite", 136),
    MPLSinIP("MPLSinIP", 137),
    manet("MANET Protocols", 138),
    HIP("Host Identity Protocol", 139),
    Shim6("Shim6 Protocol", 140),
    WESP("Wrapped Encapsulating Security Payload", 141),
    ROHC("Robust Header Compression", 142);

    private final String protocolName;
    private final byte protocolNumber;
    
    private IPProtocolsEnum(String name, int number) {
        protocolName = name;
        protocolNumber = (byte) number;
    }

    public byte value() {
        return protocolNumber;
    }

    @Override
    public String toString() {
        return protocolName;
    }

    public static String getProtocolName(byte number) {
        IPProtocolsEnum result = byNumber(number);
        if (result != null) {
            return result.toString();
        }
        return "Unknown protocol 0x" + Integer.toHexString(number);
    }
    
    // Reverse-lookup map
    private static final Map<Byte, IPProtocolsEnum> lookup = new HashMap<Byte, IPProtocolsEnum>();

    static {
        for (IPProtocolsEnum proto : IPProtocolsEnum.values()) {
            lookup.put(proto.value(), proto);
        }
    }

    public static IPProtocolsEnum byNumber(byte number) {
        return lookup.get(number);
    }
}
