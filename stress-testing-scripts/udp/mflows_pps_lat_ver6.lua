local mg     = require "moongen"
local memory = require "memory"
local device = require "device"
local ts     = require "timestamping"
local filter = require "filter"
local hist   = require "histogram"
local stats  = require "stats"
local timer  = require "timer"
local arp    = require "proto.arp"
local log    = require "log"
local table  = require "table"


-- set addresses here
local DST_MAC = nil -- temporary placeholder for a resolved MAC
local DST_MAC_NIC1	= nil -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local SRC_IP_BASE_NIC1	= "10.0.0.10" -- source IP address tp use
local DST_IP_NIC1	= "10.1.0.10"

local DST_MAC_NIC2      = nil -- resolved via ARP on GW_IP or DST_IP, can be overriden with a string here
local SRC_IP_BASE_NIC2  = "11.0.0.10" -- actual address will be SRC_IP_BASE + random(0, flows)
local DST_IP_NIC2       = "11.1.0.10"

local SRC_PORT		= 1234
local DST_PORT		= 319
local MAX_QUEUE_COUNT_PORT_82599ES 	= 64
-- answer ARP requests for this IP on the rx port
-- change this if benchmarking something like a NAT device
local RX_IP		= nil
-- used to resolve DST_MAC
local GW_IP		= nil
-- used as source IP to resolve GW_IP to DST_MAC
local ARP_IP	= nil

-- Global variables to track the UDP port numbers (SRC and DST ports)
local SRC_PORT_GLOBAL = 1
local DST_PORT_GLOBAL = 1

--local QUEUE_PAIRS = nil

function configure(parser)
	parser:description("Generates UDP traffic and measure latencies. Edit the source to modify constants like IPs.")
	parser:argument("txDev0", "Device to transmit from (port 1)."):convert(tonumber)
	parser:argument("rxDev0", "Device to receive from (port 2)."):convert(tonumber)
	parser:argument("txDev1", "Device to transmit from (port 3)."):convert(tonumber)
        parser:argument("rxDev1", "Device to receive from (port 4)."):convert(tonumber)
	parser:option("-r --rate", "Transm4it rate in Mbit/s."):default(0):convert(tonumber)
	parser:option("--rate_pps", "Transmit rate in PPS."):default(1):convert(tonumber)
	parser:option("-s --size", "Packet size."):default(60):convert(tonumber)
	parser:option("--sport", "UDP source port number."):default(SRC_PORT):convert(tonumber)
	parser:option("--dport", "UDP destination port number."):default(DST_PORT):convert(tonumber)
	parser:option("--queue_pairs", "A queue pair number (TX/RX) to use on a NIC's port."):default(0):convert(tonumber)
	parser:option("--tstamp", "Enable(true=0)/Disable(false=1) packet hardware (NIC) timestamping"):default(1):convert(tonumber)
	parser:option("-f --flows", "The number of flows per PACKET RATE GROUP"):default(1):convert(tonumber)
	parser:option("-t --time", "Duration of the test run cycle"):default(0):convert(tonumber)

end

function rate_to_Mbps(rate, pk_size)
	local rate_mbps = 0.0

	rate_mbps = rate * (pk_size + 4) * 8 / 10^6

	if rate_mbps > 0.0 then
		return rate_mbps
	else
		log:info("Rate conversion (PPS -> Mbps) failed !!!")
		return 0
	end
end

-- A form of a "slice" function, since Lua doesn't have direct means of extracting a subrange of values from an array/table
function subrange(t, first, last)
     return table.move(t, first, last, 1, {})
end

 
function master(args)
	
	--Set the runtime of the experiment (duration)
	
	txDev0 = device.config{port = args.txDev0, rxQueues = 64, txQueues = 64}
	rxDev0 = device.config{port = args.rxDev0, rxQueues = 64, txQueues = 64}
	txDev1 = device.config{port = args.txDev1, rxQueues = 64, txQueues = 64}
        rxDev1 = device.config{port = args.rxDev1, rxQueues = 64, txQueues = 64}
	start_src_port = args.sport
	start_dst_port = args.dport
	--queue_count = 0

	log:info("Parsed argument: TxDev0=%d", args.txDev0)
	log:info("Parsed argument: RxDev0=%d", args.rxDev0)
	log:info("Parsed argument: TxDev1=%d", args.txDev1)
	log:info("Parsed argument: RxDev1=%d", args.rxDev1)
	log:info("Parsed argument: rate=%d Mbps", args.rate)
	log:info("Parsed argument: rate_pps=%d", args.rate_pps)
	log:info("Parsed argument: size=%d", args.size)
	log:info("Parsed argument: sport=%d", args.sport)
	log:info("Parsed argument: dport=%d", args.dport)
	log:info("Parsed argument: queue_pairs=%d", args.queue_pairs)
	log:info("Parsed argument: tstamp=%d", args.tstamp)	
	log:info("Parsed argument: flows per rate group=%d", args.flows)
	log:info("Parsed argument: Duration=%d (s)", args.time)

	device.waitForLinks()
	-- max 1kpps timestamping traffic timestamping
	-- rate will be somewhat off for high-latency links at low rates

	-- Perform ARP resolution procedure before traffic generation routines
	
	if args.queue_pairs <= MAX_QUEUE_COUNT_PORT_82599ES then
		RX_IP = DST_IP_NIC1
		ARP_IP = SRC_IP_BASE_NIC1
		arp.startArpTask{
                	-- run ARP on both ports
                	{ rxQueue = rxDev0:getRxQueue(0), txQueue = rxDev0:getTxQueue(0), ips = RX_IP },
               		-- we need an IP address to do ARP requests on this interface
               		{ rxQueue = txDev0:getRxQueue(0), txQueue = txDev0:getTxQueue(0), ips = ARP_IP }
             	}
	elseif args.queue_pairs > 0 and args.queue_pairs > MAX_QUEUE_COUNT_PORT_82599ES and args.queue_pairs < 2*MAX_QUEUE_COUNT_PORT_82599ES then
		RX_IP = DST_IP_NIC1
                ARP_IP = SRC_IP_BASE_NIC1
		arp.startArpTask{
                        -- run ARP on both ports
                        { rxQueue = rxDev0:getRxQueue(0), txQueue = rxDev0:getTxQueue(0), ips = RX_IP },
                        -- we need an IP address to do ARP requests on this interface
                        { rxQueue = txDev0:getRxQueue(0), txQueue = txDev0:getTxQueue(0), ips = ARP_IP }
                }
		
		RX_IP = DST_IP_NIC2
		ARP_IP = SRC_IP_BASE_NIC2 
		arp.startArpTask{
                	-- run ARP on both ports
                	{ rxQueue = rxDev1:getRxQueue(0), txQueue = rxDev1:getTxQueue(0), ips = RX_IP },
                	-- we need an IP address to do ARP requests on this interface
                	{ rxQueue = txDev1:getRxQueue(0), txQueue = txDev1:getTxQueue(0), ips = ARP_IP }
           	}
	else
		log:info(" Error !!! Wrong number [%d] of rate groups - port queues to use. Max allowed: [%d]", args.queue_pairs, MAX_QUEUE_COUNT_PORT_82599ES)
	end 


	local src_port = args.sport
	local dst_port = args.dport
	local pk_size = 0
	local total_flows = 0
	-- arrays of ports for flow creation per port per NIC
	src_ports_slice = {}
	dst_ports_slice = {}
	src_ports_slice_load = {}
	  
	if args.rate > 0 then
		
		-- Create a table/map of rate group IDs to rates in Mbps
                rate_groups = {}
                for i=1,args.queue_pairs do
                        rate_groups[i] = i * 0.05
                end
                flows_per_group = {}
                for i=1,args.queue_pairs do
                        flows_per_group[i] = args.flows
                end

		--txDev0:getTxQueue(args.queue_pair):setRate(args.rate - (args.size + 4) * 8 / 1000)
		--txDev0:getTxQueue(queue_pair):setRate(args.rate)
			
		if args.tstamp == 0 then
                        pk_size = args.size + 24
		else  
                        pk_size = args.size
		end

		-- Set the rates of all the used queues (Tx/RX pairs) in Mbps
		for i=1, args.queue_pairs do
			if queue_pair <= MAX_QUEUE_COUNT_PORT_82599ES then
				txDev0:getTxQueue(queue_pair):setRate(rate_groups[queue_pair])
			elseif queue_pair > 0 and queue_pair > MAX_QUEUE_COUNT_PORT_82599ES and queue_pair < 2*MAX_QUEUE_COUNT_PORT_82599ES then
				--txDev0:getTxQueue(queue_pair):setRate(rate_groups[queue_pair])
				txDev1:getTxQueue(queue_pair-MAX_QUEUE_COUNT_PORT_82599ES):setRate(rate_groups[queue_pair] - (args.size + 4) * 8 / 1000)
			end
		end

	elseif args.rate_pps then -- Note that the minumum resulting rate in Mbps must be >= 10Mbps to ensure accurate 
					-- packet generation in PPS
		-- Create a table/map of rate group IDs to rates in PPS
		rate_groups = {}
		for i=1,args.queue_pairs do
			rate_groups[i] = i * 50
			--print(rate_groups[i])
		end

		flows_per_group = {}
		for i=1,args.queue_pairs do
			flows_per_group[i] = args.flows
		end

		src_ports = {}
		dst_ports = {}
		
		src_ports[1] = src_port
		dst_ports[1]  = dst_port
		total_flows = args.flows * args.queue_pairs
		for i=2, total_flows do
			src_ports[i] = src_ports[i-1] + 1
		end 
		
		rate_group_to_dst_port_map = {}
		rate_group_to_dst_port_map[rate_groups[1]] = dst_port
		for i=2, args.queue_pairs do
			dst_ports[i] = dst_ports[i-1] + 1

                	--for i, group in ipairs(rate_groups) do
                        	--print(group)
                        	--table.insert(rate_group_to_dst_port_map, dst_ports[i])
                        rate_group_to_dst_port_map[rate_groups[i]] = dst_ports[i]
                       	--print("DST_PORT_nr:", dst_ports[i])
			--print("RG_map: value ", rate_group_to_dst_port_map[rate_groups[i]])
			--print("RG_map: key:value ", table.unpack(rate_group_to_dst_port_map))
                	--end
		end
		--print("RG_map: key:value ", rate_group_to_dst_port_map[50])

		--for i, port in ipairs(dst_ports) do
		--	print(port)
		--end
		
		--table.sort(rate_group_to_dst_port_map)
	  	print("RG_to_udp_port_map: ")
		rg_to_dst_port_map_keys = {}
		local temp_counter = 1
		for key,value in pairs(rate_group_to_dst_port_map) do
			rg_to_dst_port_map_keys[temp_counter] = key
			print("Key/Value pairs for the RG<->DPORT mapping:")
			print(key, value)
			temp_counter = temp_counter + 1
		end
		
		-- Set the rates of all the used queues (Tx/RX pairs) in PPS
		for index=1, args.queue_pairs do

			if args.tstamp == 0 then
				pk_size = args.size + 24
				--txDev0:getTxQueue(args.queue_pair):setRate(rate_to_Mbps(args.rate_pps, pk_size) - (args.size + 4) * 8 / 1000)
				local test_rate = rate_to_Mbps(rate_groups[index]*flows_per_group[index], pk_size)
				log:info("Rate in Mbps is: %f", test_rate)
			
				--txDev0:getTxQueue(args.queue_pair):setRate(rate_to_Mbps(args.rate_pps, pk_size) - (args.size + 4) * 8 / 1000)
				if index <= MAX_QUEUE_COUNT_PORT_82599ES -2 then

					txDev0:getTxQueue(index):setRate(rate_to_Mbps(rate_groups[index]*flows_per_group[index] , pk_size))
				elseif index > 0 and index > MAX_QUEUE_COUNT_PORT_82599ES - 2 and index < 2*MAX_QUEUE_COUNT_PORT_82599ES - 4 then
					--txDev1:getTxqueue(queue_pair):setRate(rate_to_Mbps(args.rate_pps, args.srate_groupize) - (args.size + 4) * 8 / 1000)
					txDev1:getTxqueue(index-MAX_QUEUE_COUNT_PORT_82599ES):setRate(rate_to_Mbps(rate_groups[index]*flows_per_group[index], pk_size))
				end
			else
				pk_size = args.size
				local test_rate = rate_to_Mbps(rate_groups[index]*flows_per_group[index], pk_size)
                        	log:info("Rate in Mbps is: %f", test_rate)
				if index <= MAX_QUEUE_COUNT_PORT_82599ES - 2 then
					--txDev0:getTxQueue(args.queue_pair):setRate(rate_to_Mbps(args.rate_pps, pk_size) - (args.size + 4) * 8 / 1000)
                        		txDev0:getTxQueue(index):setRate(rate_to_Mbps(rate_groups[index]*flows_per_group[index], pk_size))
				elseif index > 0 and index > MAX_QUEUE_COUNT_PORT_82599ES -2 and index < 2*MAX_QUEUE_COUNT_PORT_82599ES - 4 then
					--txDev1:getTxqueue(queue_pair):setRate(rate_to_Mbps(args.rate_pps, pk_size) - (args.size + 4) * 8 / 1000)
					txDev1:getTxqueue(index-MAX_QUEUE_COUNT_PORT_82599ES):setRate(rate_to_Mbps(rate_groups[index]*flows_per_group[index], pk_size))
				end
			end
		end
	else
		log:info("TxDev0, TxDev1: Flow rate is not specified!!!. Terminating... ")
		return
	end
	
	local remaining_queues = args.queue_pairs
	local queues_to_use = remaining_queues
	if args.queue_pairs <= MAX_QUEUE_COUNT_PORT_82599ES - 2 then
		src_ports_slice = subrange(src_ports, 1, total_flows)
		dst_ports_slice = subrange(dst_ports, 1, args.queue_pairs) 
		--print("Ranges of UDP SRC and DST ports to use on NIC1 (port0, port1):")
		--for i, src_port in ipairs(src_ports_slice) do
                --	print(table.getn(src_ports_slice))
		--	print(table.getn(dst_ports_slice))
		--	print(src_port)
                --end
		txDev0Queues = {}
		rxDev0Queues = {}
		
		local txDev0Queue_tstamp, rxDev0Queue_tstamp = nil, nil

		for i=1, queues_to_use do
                	txDev0Queues[i] = txDev0:getTxQueue(i)
                	--table.insert(txDevQueues, txDev:getTxQueue(i))
                	print("TX queue: ")
                	print(txDev0Queues[i])
        	end

		for i=1, queues_to_use do
                	rxDev0Queues[i] = rxDev0:getRxQueue(i)
                	--table.insert(rxDevQueues, rxDev:getRxQueue(i))
                	print("RX queue: ")
                	print(rxDev0Queues[i])
        	end

		-- Create a single thread for the timestamping activities:
		txDev0Queue_tstamp = txDev0:getTxQueue(queues_to_use + 1)
		rxDev0Queue_tstamp = rxDev0:getRxQueue(queues_to_use + 1) 
		--[[ 
		if args.tstamp then
			
			mg.startTask("timerSlave", txDev0, rxDev0, queues_to_use, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rate_group_to_dst_port_map)
		else
			mg.startTask("loadSlave", txDev0, rxDev0, queues_to_use, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rate_group_to_dst_port_map)
		end
		]]--
		local start = 1
		if args.tstamp then
			for queue_nr=1, queues_to_use do 
				src_ports_slice_load = subrange(src_ports_slice, start, start + flows_per_group[queue_nr]-1)
				mg.startTask("loadSlave", args.txDev0, args.rxDev0, txDev0Queues[queue_nr], rxDev0Queues[queue_nr], queue_nr, pk_size, src_ports_slice, dst_ports_slice[queue_nr], flows_per_group[queue_nr], rg_to_dst_port_map_keys[queue_nr], args.time)
				start = start + flows_per_group[queue_nr]
			end 
                        mg.startSharedTask("timerSlave", args.txDev0, args.rxDev0, txDev0Queue_tstamp, rxDev0Queue_tstamp, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rg_to_dst_port_map_keys, args.time)
                else
			for queue_nr=1, queues_to_use do
				src_ports_slice_load = subrange(src_ports_slice, start, start + flows_per_group[queue_nr]-1)
                        	mg.startTask("loadSlave", args.txDev0, args.rxDev0, txDev0Queues[queue_nr], rxDev0Queues[queue_nr], queue_nr, pk_size, src_ports_slice, dst_ports_slice[queue_nr], flows_per_group[queue_nr], rg_to_dst_port_map_keys[queue_nr], args.time)
				start = start + flows_per_group[queue_nr]
			end
                end
	

	elseif args.queue_pairs > MAX_QUEUE_COUNT_PORT_82599ES and args.queue_pairs < 2*MAX_QUEUE_COUNT_PORT_82599ES - 4 then
		remaining_queues = remaining_queues - MAX_QUEUE_COUNT_PORT_82599ES - 2 -- since we are reserving the (0) of each used port for ARP
		queues_to_use = MAX_QUEUE_COUNT_PORT_82599ES - 2

		src_ports_slice = subrange(src_ports, 1, args.flows * queues_to_use)
                dst_ports_slice = subrange(dst_ports, 1, queues_to_use)

		print("Ranges of UDP SRC and DST ports to use on NIC1 (port0, port1):")
                print(table.getn(src_ports_slice))
                print(table.getn(dst_ports_slice))

		txDev0Queues = {}
                rxDev0Queues = {}

		local txDev0Queue_tstamp, rxDev0Queue_tstamp = nil, nil

                for i=1, queues_to_use do
                        txDev0Queues[i] = txDev0:getTxQueue(i)
                        --table.insert(txDevQueues, txDev:getTxQueue(i))
                        print("TX queue: ")
                        print(txDev0Queues[i])
                end

                for i=1, queues_to_use do
                        rxDev0Queues[i] = rxDev0:getRxQueue(i)
                        --table.insert(rxDevQueues, rxDev:getRxQueue(i))
                        print("RX queue: ")
                        print(rxDev0Queues[i])
                end

		-- Create a single thread for the timestamping activities:
                txDev0Queue_tstamp = txDev0:getTxQueue(queues_to_use + 1)
                rxDev0Queue_tstamp = rxDev0:getRxQueue(queues_to_use + 1)
		--[[
		if args.tstamp then
                        mg.startTask("timerSlave", txDev0, rxDev0, queues_to_use, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rate_group_to_dst_port_map)
                else
                        mg.startTask("loadSlave", txDev0, rxDev0, queues_to_use, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rate_group_to_dst_port_map)
                end
		]]--
		local start = 1
		if args.tstamp then
			for queue_nr=1, queues_to_use do
				src_ports_slice_load = subrange(src_ports_slice, start, start + flows_per_group[queue_nr]-1)
				mg.startTask("loadSlave", args.txDev0, args.rxDev0, txDev0Queues[queue_nr], rxDev0Queues[queue_nr], queue_nr, pk_size, src_ports_slice, dst_ports_slice, flows_per_group[queue_nr], rg_to_dst_port_map_keys[queue_nr], args.time)
				if queue_nr ~= queues_to_use then
					start = start + flows_per_group[queue_nr]
				else
					-- do nothing
				end
			end
                        mg.startTask("timerSlave", args.txDev0, args.rxDev0, txDev0Queue_tstamp, rxDev0Queue_tstamp, pk_size, src_ports_slice, dst_ports_slice, flows_per_group[1], rg_to_dst_port_map_keys, args.time)
                else
			for queue_nr=1, queues_to_use do
				src_ports_slice_load = subrange(src_ports_slice, start, start + flows_per_group[queue_nr]-1)
                        	mg.startTask("loadSlave", args.txDev0, args.rxDev0, txDev0Queues[queue_nr], rxDev0Queues[queue_nr], queue_nr, pk_size, src_ports_slice, dst_ports_slice, flows_per_group[queue_nr], rg_to_dst_port_map_keys[queue_nr], args.time)
				if queue_nr ~= queues_to_use then
					start = start + flows_per_group[queue_nr]
				else
					-- do nothing
				end
			end
                end
		
		src_ports_slice = {}
		dst_ports_slice = {}
		src_ports_slice = subrange(src_ports, args.flows * queues_to_use + 1, total_flows)
                dst_ports_slice = subrange(dst_ports, queues_to_use + 1, args.queue_pairs)

		print("Ranges of UDP SRC and DST ports to use on NIC2 (port0, port1):")
                print(table.getn(src_ports_slice))
                print(table.getn(dst_ports_slice))

		txDev1Queues = {}
                rxDev1Queues = {}

		local txDev1Queue_tstamp, rxDev1Queue_tstamp = nil, nil

                for i=1, remaining_queues do
                        txDev1Queues[i] = txDev1:getTxQueue(i)
                        --table.insert(txDevQueues, txDev:getTxQueue(i))
                        print("TX queue: ")
                        print(txDev1Queues[i])
                end

                for i=1, remaining_queues do
                        rxDev1Queues[i] = rxDev1:getRxQueue(i)
                        --table.insert(rxDevQueues, rxDev:getRxQueue(i))
                        print("RX queue: ")
                        print(rxDev1Queues[i])
                end

		-- Create a single thread for the timestamping activities:
                txDev1Queue_tstamp = txDev1:getTxQueue(remaining_queues + 1)
                rxDev1Queue_tstamp = rxDev1:getRxQueue(remaining_queues + 1)

		--[[
		if args.tstamp then
        		mg.startTask("timerSlave", txDev1, rxDev1, remaining_queues, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rate_group_to_dst_port_map)
        	else
                	mg.startTask("loadSlave", txDev1, rxDev1, remaining_queues, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rate_group_to_dst_port_map)
        	end
		]]--
		if args.tstamp then
			for queue_nr=1, remaining_queues do
				src_ports_slice_load = subrange(src_ports_slice, start, start + flows_per_group[queue_nr]-1)
				mg.startTask("loadSlave", args.txDev1, args.rxDev1, txDev1Queues[queue_nr], rxDev1Queues[queue_nr], queue_nr, pk_size, src_ports_slice, dst_ports_slice, flows_per_group[queue_nr], rg_to_dst_port_map_keys[queues_to_use + queue_nr], time)
				if queue_nr ~= queues_to_use then
                                	start = start + flows_per_group[queue_nr]
                                else
                                        -- do nothing
                                end
			end
                        mg.startTask("timerSlave", args.txDev1, args.rxDev1, txDev1Queue_tstamp, rxDev1Queue_tstamp, pk_size, src_ports_slice, dst_ports_slice, flows_per_group, rg_to_dst_port_map_keys, time)
                else
			for queue_nr=1, remaining_queues do
				src_ports_slice_load = subrange(src_ports_slice, start, start + flows_per_group[queue_nr]-1)
                        	mg.startTask("loadSlave", args.txDev1, args.rxDev1, txDev1Queues[queue_nr], rxDev1Queues[queue_nr], queue_nr, pk_size, src_ports_slice, dst_ports_slice, flows_per_group[queue_nr], rg_to_dst_port_map_keys[queues_to_use + queue_nr], time)
				if queue_nr ~= queues_to_use then
                                        start = start + flows_per_group[queue_nr]
                                else
                                        -- do nothing
                                end
			end
                end
	end

	--mg.sleepMillis(20) -- introduce a small delay between the rate groups (each using a dedicated Tx/Rx queue pair. 

	mg.waitForTasks()
end

local function fillUdpPacket_nic1(queue, buf, len, src_port, dst_port)
	buf:getUdpPacket():fill{
		ethSrc = queue,
		ethDst = DST_MAC_NIC1,
		ip4Src = SRC_IP_NIC1,
		ip4Dst = DST_IP_NIC1,
		udpSrc = src_port,
		udpDst = dst_port,
		pktLength = len
	}
end

local function fillUdpPacket_nic2(queue, buf, len, src_port, dst_port)
        buf:getUdpPacket():fill{
                ethSrc = queue,
                ethDst = DST_MAC_NIC2,
                ip4Src = SRC_IP_NIC2,
                ip4Dst = DST_IP_NIC2,
                udpSrc = src_port,
                udpDst = dst_port,
                pktLength = len
        }
end

local function doArp()
	if not DST_MAC then
		log:info("Performing ARP lookup on %s", GW_IP)
		DST_MAC = arp.blockingLookup(GW_IP, 5)
		if not DST_MAC then
			log:info("ARP lookup failed, using default destination mac address")
			return
		end
	end
	log:info("Destination mac: %s", DST_MAC)
end


function counterSlave(queue, runtime)
        -- the simplest way to count packets is by receiving them all
        -- an alternative would be using flow director to filter packets by port and use the queue statistics
        -- however, the current implementation is limited to filtering timestamp packets
        -- (changing this wouldn't be too complicated, have a look at filter.lua if you want to implement this)
        -- however, queue statistics are also not yet implemented and the DPDK abstraction is somewhat annoying
        local bufs = memory.bufArray()
        local ctrs = {}

        while mg.running() do
                local rx = queue:recv(bufs)
                for i = 1, rx do
                        local buf = bufs[i]
                        local pkt = buf:getUdpPacket()
                        local port = pkt.udp:getDstPort()
                        local ctr = ctrs[port]
                        if not ctr then
                                ctr = stats:newPktRxCounter("Port " .. port, "plain")
                                ctrs[port] = ctr
                        end
                        ctr:countPacket(buf)
                end
                -- update() on rxPktCounters must be called to print statistics periodically
                -- this is not done in countPacket() for performance reasons (needs to check timestamps)
                for k, v in pairs(ctrs) do
                        v:update()
                end
		bufs:freeAll()
        end
        for k, v in pairs(ctrs) do
                v:finalize()
        end
        -- TODO: check the queue's overflow counter to detect lost packets
end


function loadSlave(txDev, rxDev, txQueue, rxQueue, queue_nr, size, src_ports, dst_port, flows_per_group, rg_to_dst_port_map_value, runtime)
	-- comment
	local mempool = nil
	if queue_nr <= MAX_QUEUE_COUNT_PORT_82599ES-2 then
		--log:info("queue number = %d", queue_nr)
		DST_MAC = nil
		GW_IP = DST_IP_NIC1 
		doArp()
		DST_MAC_NIC1 = DST_MAC
		
		local mempool_temp = memory.createMemPool(function(buf)
                	fillUdpPacket_nic1(txQueue, buf, size, src_ports[1], dst_port)
		end)
		mempool = mempool_temp
	else
		DST_MAC = nil
		GW_IP = DST_IP_NIC2
                doArp()
                DST_MAC_NIC2 = DST_MAC
		
		local mempool_temp = memory.createMemPool(function(buf)
                        fillUdpPacket_nic2(txQueue, buf, size, src_ports[1], dst_port)
                end)
		mempool = mempool_temp

	end 

	--local mempool = memory.createMemPool(function(buf)
		--fillUdpPacket(txQueue, buf, size, src_port, dst_port)
	--end)

	local bufs = mempool:bufArray()
	local counter = 0
	local flows = flows_per_group
	-- Create an array of filenames to store the tx/rx stats:
	local res_file_names = {}

	local tx_name = "tx_stats_"
	local rx_name = "rx_stats_"
        res_file_names[1] = tx_name .. tostring(rg_to_dst_port_map_value) .. ".csv"
	res_file_names[2] = rx_name .. tostring(rg_to_dst_port_map_value) .. ".csv"	

	for k,v in ipairs(res_file_names) do
        	log:info("The stats filename: %s", v)
	end

	local txCtr = stats:newDevTxCounter(txQueue, "CSV", res_file_names[1])
	local rxCtr = stats:newDevRxCounter(rxQueue, "CSV", res_file_names[2])
	--local baseIP = parseIPAddress(SRC_IP_BASE)
	--log:info("The number of flows to generate: [%d]", flows_per_group)
	while mg.running() do
		bufs:alloc(size)
		for i, buf in ipairs(bufs) do
			local pkt = buf:getUdpPacket()
			--pkt.eth.ethSrc:set(txQueue)
			--pkt.ip4.src:set(baseIP + counter)
			--pkt.ip4.src:set(baseIP)
			--counter = incAndWrap(counter, flows)
			--pkt.udp.src:set(src_port + counter)
			--pkt.udp.dst:set(dst_port + counter)
			--pkt:fill{
				--udpSrc = src_port + counter,
				--udpDst = dst_port + counter,
			--}
			--counter = incAndWrap(counter, flows)
			pkt.udp:setSrcPort(src_ports[1] + counter)
			counter = incAndWrap(counter, flows - 1)
		end
		-- UDP checksums are optional, so using just IPv4 checksums would be sufficient here
		bufs:offloadUdpChecksums()
		txQueue:send(bufs)
		txCtr:update()
		rxCtr:update()
	end
	txCtr:finalize()
	rxCtr:finalize()
end

--function timerSlave(txQueue, rxQueue, queue_nr, size, src_port, dst_port, flows)
function timerSlave(txDev, rxDev, txDevQueue, rxDevQueue, size, src_ports, dst_ports, flows_per_group, rg_to_dst_port_map_keys, time)

	if txDev == 0 and rxDev == 1 then
                DST_MAC = nil
                GW_IP = DST_IP_NIC1
                doArp()
                DST_MAC_NIC1 = DST_MAC
        elseif txDev == 2 and rxDev == 3 then
		--DST_MAC = nil
                --GW_IP = DST_IP_NIC1
                --doArp()
                --DST_MAC_NIC1 = DST_MAC

                DST_MAC = nil
                GW_IP = DST_IP_NIC2
                doArp()
                DST_MAC_NIC2 = DST_MAC
        end

	if size < 84 then
		log:warn("Packet size %d is smaller than minimum timestamp size 84. Timestamped packets will be larger than load packets.", size)
		size = 84
	end
	--print("Remaining queue pairs:", remain_queue_pairs)
	--[[	
	txDevQueues = {}
	for i=1, remain_queue_pairs do
		--txDevQueues[i] = txDev:getTxQueue(i)
		table.insert(txDevQueues, txDev:getTxQueue(i))
		print("TX queue: ")
		print(txDevQueues[i])
	end
	]]--
	--[[
	rxDevQueues = {}
	for i=1, remain_queue_pairs do
                --rxDevQueues[i] = rxDev:getRxQueue(i)
		table.insert(rxDevQueues, rxDev:getRxQueue(i))
		print("RX queue: ")
                print(rxDevQueues[i])
        end
	]]--

	--rxQueue = rxDev0:getRxQueue(0), txQueue = rxDev0:getTxQueue(0)
	--log.info("TEST_PRINTOUT: tx queue: ", txDevQueues[1])
	--log.info("TEST_PRINTOUT: rx queue: ", rxDevQueues[1])

	--log.info(txQueue)

	--local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
	--local timestamper = nil
	--local queue_set = {}
	--[[
	for i=1, remain_queue_pairs do
		--print("TxQueue, RxQueue:", txDevQueues[i], rxDevQueues[i])
		--timestampers[i] = ts:newUdpTimestamper(txDevQueues[i], rxDevQueues[i])
		--mg.sleepMillis(100)

		--timestampers[i] = ts:newUdpTimestamper(txDev:getTxQueue(1), rxDev:getRxQueue(1))
	end
	]]--

	local hists = {}
	for i=1, #dst_ports do
		hists[i] = hist:new()
	end
	
	-- RG-to-port-map keys of the table:
	--rg_to_dst_port_map_keys = {}
	--for i=1, #txDevQueues do
	--	rg_to_dst_port_map_keys[i] = dst_ports[i]
	--end
	--local hist = hist:new()
	mg.sleepMillis(1000) -- ensure that the load task is running
	local counter1 = 0
	local counter2 = 0
	local rateLimit = timer:new(0.001)
	--local baseIP = parseIPAddress(SRC_IP_BASE)
	local timestamper = ts:newUdpTimestamper(txQueue, rxQueue)
	log:info("Beginning the timestamping test...")	
	if txDev == 0 and rxDev == 1 then
	--if txDevQueues[1].dev == 0 and rxDevQueueus[1].dev == 1 then
		print("Tx0/Rx0 devices are used. !!!")
		while mg.running() do
				

					hists[i]:update(timestamper:measureLatency(size, function(buf)
 						fillUdpPacket_nic1(txDevQueue, buf, size, src_ports[1], dst_ports[i])
						local pkt = buf:getUdpPacket()
						--pkt.eth.ethSrc:set(txQueue)
						--pkt.ip4.src:set(baseIP + counter)
						--pkt.ip4.src:set(baseIP + 10) -- SRC IP is chosen for testing purposes (no valid reason)
						--counter = incAndWrap(counter, flows)
						--pkt.udp.src:set(src_port + counter)
                        			--pkt.udp.dst:set(dst_port + counter)
						--[[pkt:fill{
							pktLength = size,					
							ethSrc = txQueue,
               						ethDst = DST_MAC_NIC1,
                					ip4Src = SRC_IP_NIC1,
                					ip4Dst = DST_IP_NIC1,
                                			udpSrc = src_port + counter,
                                			udpDst = dst_port + counter,
                        			}
						]]
						--pkt.udp:setSrcPort(src_port + counter1)
						--pkt.udp:setDstPort(dst_port + counter2)
						pkt.udp:setSrcPort(src_ports[1])
                                                pkt.udp:setDstPort(dst_ports[i])

						--counter1 = incAndWrap(counter, flows_per_group)
						--counter1 = counter1 + 1
						end))
				--counter2 = incAndWrap(counter2, remain_queue_pairs-1)
				
			

			--counter1 = 0
			rateLimit:wait()
			rateLimit:reset()
		end
	elseif txDev == 2 and rxDev == 3 then
	--elseif txDevQueues[1].dev == 2 and rxDevQueueus[1].dev == 3 then
		while mg.running() do
			for i, timestamper in ipairs(timestampers) do

                        	hists[i]:update(timestamper:measureLatency(size, function(buf)
					fillUdpPacket_nic2(txDevQueues[i], buf, size, src_port, dst_port)
                                	local pkt = buf:getUdpPacket()
                                	--pkt.eth.ethSrc:set(txQueue)
                                	--pkt.ip4.src:set(baseIP + counter)
                                	--pkt.ip4.src:set(baseIP + 10) -- SRC IP is chosen for testing purposes (no valid reason)
                                	--counter = incAndWrap(counter, flows)
                                	--pkt.udp.src:set(src_port)
                                	--pkt.udp.dst:set(dst_port)
					--pkt:fill{
                                        	--udpSrc = src_port + counter,
                                        	--udpDst = dst_port + counter,
                                	--}
					--counter = incAndWrap(counter, flows)
					pkt.udp:setSrcPort(src_port + counter1)
                                        pkt.udp:setDstPort(dst_port + counter2)
					counter1 = counter1 + 1
                        		end))

			counter2 = incAndWrap(counter2, remain_queue_pairs-1)
			end

			counter1 = 0
                        rateLimit:wait()
                        rateLimit:reset()
                end
	end
	-- print the latency stats after all the other stuff
	mg.sleepMillis(300)
        for i, hist in ipairs(hists) do
		hist:print()
	end
	--hist:print()
	local res_file_names = {}
	for i, dport in ipairs(rg_to_dst_port_map_keys) do 
		--res_file_names[i] = "results/histogram_lat_" .. tostring(rg_to_dst_port_map[i]) .. ".csv"
		res_file_names[i] = "histogram_lat_" .. tostring(rg_to_dst_port_map_keys[i]) .. ".csv"
		log:info("The hist filename: %s", res_file_names[i]) 
	end

	
	for i, hist in ipairs(hists) do
		hist:save(res_file_names[i])
	end

end
