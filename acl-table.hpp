/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2022 Changrong Wu
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

#ifndef SIMPLE_ROUTER_ACL_TABLE_HPP
#define SIMPLE_ROUTER_ACL_TABLE_HPP

#include <list>
#include <vector>
#include <string>
#include <stdint.h>
#include <iostream>
#include <fstream>

namespace simple_router {

struct ACLTableEntry
{
  uint32_t dest;
  uint32_t destMask;
  uint32_t src;
  uint32_t srcMask;
  uint16_t destPort;
  uint16_t destPortMask;
  uint16_t srcPort;
  uint16_t srcPortMask;
  uint8_t protocol;
  uint8_t protocolMask;
  uint16_t priority;
  std::string action;
};

/**
 * Routing table of the simple router
 */
class ACLTable
{
public:
  /**
   * IMPLEMENT THIS METHOD
   *
   * This method should lookup a proper entry in the ACL table
   * using "ternary match" algorithm
   *
   * If ACL table not found, `throw std::runtime_error("ACL entry not found")`
   */
  ACLTableEntry
  lookup(uint32_t srcIp, uint32_t dstIp, uint8_t protocol, uint32_t srcPort, uint16_t dstPort) const;

  bool
  load(const std::string& file);

  void
  addRule(ACLTableEntry& entry);

private:
  std::list<ACLTableEntry> m_entries;

  friend std::ostream&
  operator<<(std::ostream& os, const ACLTable& table);
};

std::ostream&
operator<<(std::ostream& os, const ACLTableEntry& entry);

std::ostream&
operator<<(std::ostream& os, const ACLTable& table);

} // namespace simple_router

#endif // SIMPLE_ROUTER_ROUTING_TABLE_HPP