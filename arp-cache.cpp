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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{

  // FILL THIS IN
  // Summary: ARP cache entries, ARP requests resends
  // ARP entries can timeout. This function is called every 30 seconds. Check if any of the entries
  // are older than 30 seconds.

  // ARP cache
  //    Iterate over all entries in the ARP cache.
  //        If entry is invalid, call remove function on the entry
  //        Else, do nothing
  // ARP requests -- need to be resend once per second until we get a reply
  //    Maintain a queue of all ARP requests you have sent and have not received a reply for
  //    Iterate over queued requests
  //    Each request has a counter of number of times it has been sent
  //    Compare times sent to MAX_TIMES_SENT (?)
  //    If has been sent too many times:
  //         Remove request from the queue (also remove request if a reply is received IN ANOTHER FUNCTION)
  //         Drop packets waiting for this reply
  //    Else
  //         Increment times sent (update header)
  //         Resend


  // Resend ARP requests
  auto it = m_arpRequests.begin();
  while (it != m_arpRequests.end()) {
    if ((*it)->nTimesSent >= MAX_SENT_TIME - 1) {
      it = m_arpRequests.erase(it);     
      continue;
    }
    // Resend ARP Request
    ++((*it)->nTimesSent);
    RoutingTable rtable = m_router.getRoutingTable();
    RoutingTableEntry rtable_entry = rtable.lookup((*it)->ip);
    const Interface *iface = m_router.findIfaceByName(rtable_entry.ifName);
    if (iface == nullptr) {
      continue;
    }
    // Have to send ARP request on iface
    // Ethernet header:
    ethernet_hdr eth_req = {0};
    for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
      eth_req.ether_dhost[i] = 255;
      eth_req.ether_shost[i] = iface->addr[i];
    }
    eth_req.ether_type = htons(ethertype_arp);
    // ARP header:
    arp_hdr arp_req = {0};
    arp_req.arp_hrd = htons(1);
    arp_req.arp_pro = htons(2048);
    arp_req.arp_hln = 6;
    arp_req.arp_pln = 4;
    arp_req.arp_op = htons(arp_op_request);
    for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
      arp_req.arp_sha[i] = iface->addr[i];
    }
    arp_req.arp_sip = iface->ip;
    for (size_t i = 0; i < ETHER_ADDR_LEN; ++i) {
      arp_req.arp_tha[i] = 0;
    }
    arp_req.arp_tip = (*it)->ip;
    // Send the ARP request packet:
    Buffer arp_req_packet;
    const uint8_t *eth_buf = (const uint8_t *) &eth_req;
    for (size_t i = 0; i < sizeof(ethernet_hdr); ++i) {
      arp_req_packet.push_back(eth_buf[i]);
    }
    const uint8_t *arp_buf = (const uint8_t *) &arp_req;
    for (size_t i = 0; i < sizeof(arp_hdr); ++i) {
      arp_req_packet.push_back(arp_buf[i]);
    }
    m_router.sendPacket(arp_req_packet, iface->name);
    ++it;
  }

  // Remove invalid entries
  m_cacheEntries.remove_if([](const std::shared_ptr<ArpEntry> &entry) {
    return entry && !entry->isValid;
  });
  
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueArpRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeArpRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
