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

template <typename T>
T swap_endian(T u) {
    union {
        T u;
        unsigned char u8[sizeof(T)];
    } source, dest;
    source.u = u;
    for (size_t k = 0; k < sizeof(T); k++) {
        dest.u8[k] = source.u8[sizeof(T) - k - 1];
    }
    return dest.u;
}

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

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  const uint8_t *buf = packet.data();
  size_t length = packet.size();
  print_hdrs(buf, length);
  size_t minlength = sizeof(ethernet_hdr);
  if (length < minlength) {
    std::cerr << "Insufficient length (eth hdr)... dropped" << std::endl;
    return;
  }
  const ethernet_hdr *ehdr = (const ethernet_hdr *) buf;
  const uint8_t *ether_dest_addr = ehdr->ether_dhost;
  const uint8_t *ether_src_addr = ehdr->ether_shost; 
  // Convert endianness of ether_type:
  //uint16_t ether_type = (ehdr->ether_type>>8) | (ehdr->ether_type<<8);
  uint16_t ether_type = swap_endian(ehdr->ether_type);
  std::cout << "Received ethernet header with ether_type of " << ehdr->ether_type << std::endl;
  if (ether_type == ethertype_arp) {
    std::cout << "Received ARP ethernet type" << std::endl;
    minlength += sizeof(arp_hdr);
    if (length < minlength) {
        std::cerr << "Insufficient length (arp hdr)... dropped" << std::endl;
        return;
    }
    const arp_hdr *ahdr = (const arp_hdr *) (buf + sizeof(ethernet_hdr));
    unsigned short arp_op = swap_endian(ahdr->arp_op);
    if (arp_op == arp_op_request) { /* ARP Request */
        // TODO
        std::cout << "Received ARP request" << std::endl;
        uint32_t arp_tip = swap_endian(ahdr->arp_tip);
        std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(arp_tip);
        Buffer mac = arp_entry->mac;
        struct arp_hdr arp_reply = {0};
        arp_reply->arp_hrd = ahdr->arp_hrd;
        arp_reply->arp_pro = ahdr->arp_pro;
        arp_reply->arp_hln = ahdr->arp_hln;
        arp_reply->arp_pln = ahdr->arp_pln;
        arp_reply->arp_op = arp_op_reply;
        for (size_t i = 0; i < iface->addr.size(); ++i) {
            arp_reply->arp_sha[i] = iface->addr[i];
        }
        arp_reply->arp_sip = iface->ip;
        // TODO
    }
    else if (ahdr->arp_op == arp_op_reply) { /* ARP Reply */
        std::cout << "Received ARP reply" << std::endl;
        const unsigned char *arp_sha = ahdr->arp_sha;
        const uint32_t ip = ahdr->arp_sip;
        Buffer mac;
        for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
            mac.push_back(arp_sha[i]);
        }
        m_arp.insertArpEntry(mac, ip);
        // TODO Send out all packets waiting on this ARP request in the queue
    }
    else {
        std::cout << "Unkown ARP packet with arp_op " << ahdr->arp_op << "... dropped" << std::endl;
        return;
    }
  }
  else if (ether_type == ethertype_ip) {
    std::cout << "Received IP ethernet type" << std::endl;
  }
  else {
    std::cerr << "Unrecognized ethernet header... dropped" << std::endl;
    return;
  }


  // Extract ethernet header:
  // [NOTE] 300-350 lines are in this function
  // - This function is called whenever a client reaches a router. For example, we send a ping from client
  //   to the server, so packets will reach the rotuer first.
  // - Pox and mininet will do the redirction and transfer for you.
  // - Router has three interfaces I1, I2, I3.  Client connected to I1, server1 on I2, server2 on I3
  // - CASE 1: Check MAC address and ensure on interfaces connected to router.
  //   dst: I1, src: I4 ... invalid interface, so drop the packet
  // - Check if ARP or not ARP
  //    - if ARP:
  //         - Request:
  //              Given IP address, lookup in ARP table and return MAC
  //              Create the reply packet with the MAC address, send back on the same interface request
  //               came from
  //         - Reply:
  //              First add mapping to table (insertEntry?? -- already implemented in arp-cache.hpp|cpp)
  //                 Takes (IP, MAC) and adds it to the ARP cache (IP -> MAC)
  //              Send out all packets waiting on this ARP request
  //                 Iterate over packets in queue and send those waiting on this IP address
  //    - If IP: (Anything that is not ARP (TCP, UDP, etc. -- indicated by protocol number))
  //         - Verify the checksum
  //             - Compute checksum and see if it matches checksum in IP header
  //             - If checksum is wrong, drop packet (just return from function)
  //         - Verify ethernet header length to given length (rigth format)
  //         - Check IP version (must be IPv4)
  //         - Check ACL and drop if necessary (call ACL function we implement later)
  //         - Check if packet is destined for the router
  //              - If so, drop
  //        - Else
  //              - Decrement TTL, if TTL = 0, drop
  //              - Look up next hop IP
  //                 - Look up next hop given destination in routing_table.hpp|cpp
  //                 - Now we have IP address we need to send to next
  //                 - Table entry in routing_table.cpp
  //                    - dest == final IP
  //                    - GW == next hop IP
  //                    - Mask -- do IP addr & MASK to get IP address we want
  //                    - Interface name to send out on
  //                - Look up next hop IP in ARP cache (call lookup in arp-cache.cpp)
  //                    - If MAC found, forward as normal
  //                    - If MAC not found, send an ARP request
  //                         - Queue the packet
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
