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

#include "acl-table.hpp"
#include "core/utils.hpp"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

std::vector<std::string> splitStr(const std::string& s, const std::string& delimiter) {
  int startp = 0;
  int split = 0;
  std::vector<std::string> res;
  while (1) {
    // split once per iteration
    split = s.find(delimiter, startp);
    if (split != -1) {
      // get a new segment
      if (split != startp)
        // non trivial string
        res.push_back(s.substr(startp, split - startp));

      split = split + delimiter.length();
      startp = split;
    }
    else {
      // get the last segment
      res.push_back(s.substr(startp, s.length() - startp));
      break;
    }
  }

  return res;
}

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THESE METHODS
ACLTableEntry
ACLTable::lookup(uint32_t srcIp, uint32_t dstIp, uint8_t protocol, uint32_t srcPort, uint16_t dstPort) const
{
  // FILL THIS IN

  throw std::runtime_error("ACL entry not found");
}

void
ACLTable::addRule(ACLTableEntry& entry)
{
  // FILL THIS IN
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

bool
ACLTable::load(const std::string& fileName)
{
  std::ifstream file;
  file.open(fileName.c_str());
  std::cerr << "Loading ACL Table from " << fileName << std::endl;

  if (file.is_open()) {
    std::string line;
    while (std::getline(file, line)){
      try
      {
        // each line is an ACL entry
        std::vector<std::string> fields = splitStr(line, std::string(" "));

        if (fields.size() == 7) {
          // get a valid entry
          std::vector<std::string> temp = splitStr(fields[0], "&");
          uint32_t dest = std::strtoul(temp[0].c_str(), NULL, 16);
          uint32_t destMask = std::strtoul(temp[1].c_str(), NULL, 16);

          temp = splitStr(fields[1], "&");
          uint32_t src = std::strtoul(temp[0].c_str(), NULL, 16);
          uint32_t srcMask = std::strtoul(temp[1].c_str(), NULL, 16);

          temp = splitStr(fields[2], "&");
          uint16_t destPort = std::strtoul(temp[0].c_str(), NULL, 16);
          uint16_t destPortMask = std::strtoul(temp[0].c_str(), NULL, 16);

          temp = splitStr(fields[3], "&");
          uint16_t srcPort = std::strtoul(temp[0].c_str(), NULL, 16);
          uint16_t srcPortMask = std::strtoul(temp[0].c_str(), NULL, 16);

          temp = splitStr(fields[4], "&");
          uint8_t protocol = std::strtoul(temp[0].c_str(), NULL, 16);
          uint8_t protocolMask = std::strtoul(temp[1].c_str(), NULL, 16);

          uint16_t priority = std::strtoul(fields[5].c_str(), NULL, 16);

          std::string action = fields[6];

          simple_router::ACLTableEntry entry = { dest, destMask, src, srcMask, destPort, destPortMask, srcPort, srcPortMask, protocol, protocolMask, priority, action};
          addRule(entry);
        }
      }
      catch(const std::exception& e)
      {
        std::cerr << "Error encountered in parsing ACL table" << std::endl;
        std::cerr << e.what() << '\n';
        return false;
      }
    }
  }

  return true;
}

std::ostream&
operator<<(std::ostream& os, const ACLTableEntry& entry)
{
  os << std::hex << entry.dest << "&" << entry.destMask << "\t"
     << entry.src << "&" << entry.srcMask << "\t"
     << entry.destPort << "&" << entry.destPortMask << "\t"
     << entry.srcPort << "&" << entry.srcPortMask << "\t"
     << (uint16_t)entry.protocol << "\t"
     << entry.priority << "\t"
     << entry.action << std::endl;
  return os;
}

std::ostream&
operator<<(std::ostream& os, const ACLTable& table)
{
  os << "DestIP\t" << "SrcIP\t" << "DestPort\t" << "SrcPort\t" << "Protocol\t" << "Priority\t" << "Action" << std::endl;
  std::list<ACLTableEntry>::const_iterator it = table.m_entries.begin();
  while (it != table.m_entries.end()) {
    os << *it;
    it++;
  }
  return os;
}

} // namespace simple_router