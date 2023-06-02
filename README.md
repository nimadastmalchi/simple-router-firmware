A simple router that handles forwarding of Ethernet frames, ARP packets, IPv4 packets with routing table.

<img width="722" alt="image" src="https://github.com/nimadastmalchi/simple-router-firmware/assets/60092567/e3a1834e-d628-4a8e-9ade-57bfffb3e836">

The default topology tested:

<img width="589" alt="image" src="https://github.com/nimadastmalchi/simple-router-firmware/assets/60092567/ad8ec237-c08c-4ef1-9b16-4a5379f37c6a">

Four main functionalities of this router:

1. Handle ethernet frames
2. Handle ARP packets
3. Handle IPv4 packets
4. Handle ICMP packets


The router implements all of these opearations on mininet:
1. ping from the client to the router's interfaces

```
  mininet> client ping 192.168.2.1
  mininet> client ping 172.64.3.1
  mininet> client ping 10.0.1.1
```

2. ping from the client to any servers through the router

```
  mininet> client ping server1      # or client ping 192.168.2.2
  mininet> client ping server2      # or client ping 172.64.3.10
```

