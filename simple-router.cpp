/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>
#include <climits>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::processPacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  //std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  const uint8_t *buf = packet.data();
  size_t length = packet.size();
  size_t minlength = sizeof(ethernet_hdr);
  if (length < minlength) {
    std::cerr << "Insufficient length (eth hdr)... dropped" << std::endl;
    return;
  }
  const ethernet_hdr *ehdr = (const ethernet_hdr *) buf;

  // Check if packet is destined to the router.
  if (iface->addr.size() != ETHER_ADDR_LEN) {
     std::cerr << "addr field of Interface has size not equal to ETHER_ADDR_LEN... dropped" << std::endl;
     return;
  }
  bool correct_dest = true;
  for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
     if (ehdr->ether_dhost[i] != 255) {
        correct_dest = false;
        break;
     }
  }
  // If correct_dest, then message is a broadcast
  // If not correct_dest, then we still need to compare dest mac to mac of this interface
  if (!correct_dest) {
     correct_dest = true;
     for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
       if (iface->addr[i] != ehdr->ether_dhost[i]) {
         correct_dest = false;
         break;
       }
     }
  }
  // If not correct_dest, then dest mac is neither a broadcast nor for this interface
  if (!correct_dest) {
     std::cerr << "Received packet not destined for router... dropped" << std::endl;
     return;
  }

  uint16_t ether_type = ntohs(ehdr->ether_type);
  if (ether_type == ethertype_arp) {
    minlength += sizeof(arp_hdr);
    if (length < minlength) {
        std::cerr << "Insufficient length (arp hdr)... dropped" << std::endl;
        return;
    }
    const arp_hdr *ahdr = (const arp_hdr *) (buf + sizeof(ethernet_hdr));
    unsigned short arp_op = ntohs(ahdr->arp_op);

    if (arp_op == arp_op_request) {
        // ARP request asking for one of our interface IP addresses
        std::cerr << "Received ARP request" << std::endl;
        const Interface *requested_interface = findIfaceByIp(ahdr->arp_tip);
        // TODO: What is ARP request is for IP not for this router interface (i.e., we get
        // request from another router, not a node...)
        if (requested_interface == nullptr) {
            std::cerr << "Received ARP request for an unknown interface on this router... dropped" << std::endl;
            return;
        }

        // Set the ethernet_hdr
        ethernet_hdr eth_reply = {0};
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            eth_reply.ether_dhost[i] = ahdr->arp_sha[i];
            eth_reply.ether_shost[i] = requested_interface->addr[i];
        }
        eth_reply.ether_type = htons(ethertype_arp);

        // Set the arp_hdr
        arp_hdr arp_reply = {0};
        arp_reply.arp_hrd = ahdr->arp_hrd;
        arp_reply.arp_pro = ahdr->arp_pro;
        arp_reply.arp_hln = ahdr->arp_hln;
        arp_reply.arp_pln = ahdr->arp_pln;
        arp_reply.arp_op = htons(arp_op_reply);
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            arp_reply.arp_sha[i] = requested_interface->addr[i];
        }
        arp_reply.arp_sip = requested_interface->ip;
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            arp_reply.arp_tha[i] = ahdr->arp_sha[i];
        }
        arp_reply.arp_tip = ahdr->arp_sip;

        Buffer arp_reply_packet;
        const uint8_t *eth_buf = (const uint8_t *) &eth_reply;
        for (size_t i = 0; i < sizeof(ethernet_hdr); ++i) {
            arp_reply_packet.push_back(eth_buf[i]);
        }
        const uint8_t *arp_buf = (const uint8_t *) &arp_reply;
        for (size_t i = 0; i < sizeof(arp_hdr); ++i) {
            arp_reply_packet.push_back(arp_buf[i]);
        }
        std::cerr << "Sending ARP reply" << std::endl;
        sendPacket(arp_reply_packet, iface->name);
        return;
    }
    else if (arp_op == arp_op_reply) {
        std::cerr << "Received ARP reply" << std::endl;

        // Get the mac address of the ARP reply
        Buffer mac_reply;
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            mac_reply.push_back(ahdr->arp_sha[i]);
        }

        // Get the ip of the ARP reply
        uint32_t ip_reply = ahdr->arp_sip;

        // Check if the entry is already in the cache
        std::shared_ptr<ArpEntry> entry = m_arp.lookup(ip_reply);
        if (entry != nullptr) { // Entry already in cache
            std::cerr << "Received duplicate ARP reply... dropped" << std::endl;
            return;
        }

        std::shared_ptr<ArpRequest> areq = m_arp.insertArpEntry(mac_reply, ip_reply);

        if (areq != nullptr) {
            for (auto it = areq->packets.begin(); it != areq->packets.end(); ++it) {
                Buffer &packet_fwd = it->packet;
                std::string &iface_str = it->iface;

                ethernet_hdr *ehdr = (ethernet_hdr *) packet_fwd.data();

                const Interface *iface_fwd = findIfaceByName(iface_str);
                for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
                    ehdr->ether_dhost[i] = mac_reply[i];
                    ehdr->ether_shost[i] = iface_fwd->addr[i];
                }
                ehdr->ether_type = htons(ethertype_ip);

                sendPacket(packet_fwd, iface_str);
            }
            // Remove packets we just sent
            m_arp.removeArpRequest(areq);
        }

        return;
    }
    else {
        std::cerr << "Unkown ARP packet with arp_op " << ahdr->arp_op << "... dropped" << std::endl;
        return;
    }
  }
  else if (ether_type == ethertype_ip) {
    std::cerr << "Received IP packet" << std::endl;

    // Verify header length
    minlength += sizeof(ip_hdr);
    if (length < minlength) {
        std::cerr << "Insufficient length (ip hdr)... dropped" << std::endl;
        return;
    }

    const ip_hdr *ihdr = (const ip_hdr *) (buf + sizeof(ethernet_hdr));

    // Verify header length again using the ip_hl field
    if ((4 * ihdr->ip_hl) != sizeof(ip_hdr)) {
        std::cerr << "ihdr->ip_hl is not equal to size of ip_hdr struct... dropped" << std::endl;
        return;
    }

    // Verify data length
    uint16_t actual_ip_len = packet.size() - sizeof(ethernet_hdr);
    uint16_t hdr_ip_len = ntohs(ihdr->ip_len);
    if (actual_ip_len != hdr_ip_len) {
        std::cerr << "ip_len field on IP header differs from the packet length... dropped" << std::endl;
        return;
    }

    // Make a copy of the packet
    Buffer packet_fwd(packet);
    ethernet_hdr *ehdr_fwd = (ethernet_hdr *) packet_fwd.data();
    ip_hdr *ihdr_fwd = (ip_hdr *) (packet_fwd.data() + sizeof(ethernet_hdr));

    // Verify checksum
    ihdr_fwd->ip_sum = 0; // Zero out the ip sum before computing the checksum
    uint16_t computed_sum = cksum(ihdr_fwd, sizeof(ip_hdr));
    if (computed_sum != ihdr->ip_sum) {
        std::cerr << "Incorrect IP header checksum... dropped" << std::endl;
        return;
    }

    // Verify IP version
    if (ihdr_fwd->ip_v != 4) {
        std::cerr << "IP is not version 4... dropped" << std::endl;
        return;
    }

    // Check ACL and drop if necessary
    try {
        ACLTableEntry acl_entry;
        if (ihdr->ip_p == ip_protocol_tcp || ihdr->ip_p == ip_protocol_udp) {
            std::cerr << "TCP or UDP header" << std::endl;

            // Ensure the packet has at least 4 more bytes to avoid seg fault
            minlength += 4;
            if (length < minlength) {
                std::cerr << "Insufficient length (TCP/UDP header)... dropped" << std::endl;
                return;
            }
            struct port_hdr {
                uint16_t src;
                uint16_t dst;
            };
            const port_hdr *phdr = (const port_hdr *) (buf + sizeof(ethernet_hdr) + sizeof(ip_hdr));
            acl_entry = m_aclTable.lookup(ntohl(ihdr->ip_src), ntohl(ihdr->ip_dst), ihdr->ip_p, ntohs(phdr->src), ntohs(phdr->dst));
        }
        else if (ihdr->ip_p == ip_protocol_icmp) {
            acl_entry = m_aclTable.lookup(ntohl(ihdr->ip_src), ntohl(ihdr->ip_dst), ihdr->ip_p, 0, 0);
        }
        else {
            std::cerr << "Not TCP, UDP, or ICMP... dropped" << std::endl;
            return;
        }

        if (acl_entry.action == "deny") {
            std::cerr << "ACL entry found: packet denied... dropped" << std::endl;
            return;
        }
        else {
            std::cerr << "ACL entry found: packet accepted" << std::endl;
        }
    }
    catch (std::runtime_error &e) {
        std::cerr << "ACL entry NOT found: packet accepted" << std::endl;
    }

    // Check if packet is destined for the router
    const Interface *ip_dst_iface = findIfaceByIp(ihdr_fwd->ip_dst);
    if (ip_dst_iface != nullptr) {
        std::cerr << "IP packet is destined for router... dropped" << std::endl;
        return;
    }

    // Decrement TTL
    if (ihdr_fwd->ip_ttl == 0) {
        std::cerr << "TTL is 0... dropped" << std::endl;
        return;
    }
    --ihdr_fwd->ip_ttl;
    if (ihdr_fwd->ip_ttl == 0) {
        std::cerr << "TTL is 0... dropped" << std::endl;
        return;
    }

    // Recompute checksum
    // Note ip_sum in ihdr_fwd is already 0, so we can compute sum right now
    ihdr_fwd->ip_sum = cksum(ihdr_fwd, sizeof(ip_hdr));

    RoutingTableEntry rtable_entry = m_routingTable.lookup(ihdr_fwd->ip_dst);
    const Interface *next_hop_iface = findIfaceByName(rtable_entry.ifName);

    // Forward packet
    // Check arp cache for MAC address
    //    If not found, send ARP request on the interface
    //        Add packet to queue
    //    If found, forward packet
    std::shared_ptr<ArpEntry> a_entry = m_arp.lookup(rtable_entry.gw);
    if (a_entry) {
        std::cerr << "ARP entry for next hop found" << std::endl;

        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            ehdr_fwd->ether_dhost[i] = a_entry->mac[i];
            ehdr_fwd->ether_shost[i] = next_hop_iface->addr[i];
        }
        ehdr_fwd->ether_type = htons(ethertype_ip);

        sendPacket(packet_fwd, rtable_entry.ifName);
        return;
    }
    else {
        std::cerr << "ARP entry for next hop not found. Sending ARP request on interface " << rtable_entry.ifName << std::endl;

        // Set the ethernet_hdr
        ethernet_hdr eth_req = {0};
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            eth_req.ether_dhost[i] = 255;
            eth_req.ether_shost[i] = next_hop_iface->addr[i];
        }
        eth_req.ether_type = htons(ethertype_arp);

        // Set the arp_hdr
        arp_hdr arp_req = {0};
        arp_req.arp_hrd = htons(1);
        arp_req.arp_pro = htons(2048);
        arp_req.arp_hln = 6;
        arp_req.arp_pln = 4;
        arp_req.arp_op = htons(arp_op_request);
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            arp_req.arp_sha[i] = next_hop_iface->addr[i];
        }
        arp_req.arp_sip = next_hop_iface->ip;
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            arp_req.arp_tha[i] = 0;
        }
        arp_req.arp_tip = rtable_entry.gw;

        Buffer arp_req_packet;
        const uint8_t *eth_buf = (const uint8_t *) &eth_req;
        for (size_t i = 0; i < sizeof(ethernet_hdr); ++i) {
            arp_req_packet.push_back(eth_buf[i]);
        }
        const uint8_t *arp_buf = (const uint8_t *) &arp_req;
        for (size_t i = 0; i < sizeof(arp_hdr); ++i) {
            arp_req_packet.push_back(arp_buf[i]);
        }
        std::cerr << "Sending ARP request packet" << std::endl;
        sendPacket(arp_req_packet, rtable_entry.ifName);

        // Add packet_fwd to queue
        m_arp.queueArpRequest(rtable_entry.gw, packet_fwd, rtable_entry.ifName);

        return;
    }
  }
  else {
    std::cerr << "Unrecognized ethernet header... dropped" << std::endl;
    return;
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
  m_aclLogFile.open("router-acl.log");
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

bool
SimpleRouter::loadACLTable(const std::string& aclConfig)
{
  return m_aclTable.load(aclConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}

} // namespace simple_router {
