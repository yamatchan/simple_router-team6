require 'interfaces'

class SimpleRouter < Trema::Controller
  CLASSIFIER_TABLE_ID       = 0
  ARP_RESPONDER_TABLE_ID    = 2
  ROUTING_TABLE_ID          = 3
  INTERFACE_LOOKUP_TABLE_ID = 4
  ARP_LOOKUP_TABLE_ID       = 5
  PACKET_OUT_TABLE_ID       = 6

  ETH_IPv4 = 0x0800
  ETH_ARP  = 0x0806

  MASK32 = 0xFFFFFFFF

  def start(_args)
    load File.join(__dir__, '..', 'simple_router.conf')
    @interfaces = Interfaces.new(Configuration::INTERFACES)
    @unresolved_packet_queue = Hash.new { [] }
    logger.info "#{name} started."
  end

  def switch_ready(dpid)
    init_classifier_flow_entry(dpid)
    init_arp_responder_flow_entry(dpid)
    init_routing_flow_entry(dpid)
    init_interface_lookup_flow_entry(dpid)
    init_arp_lookup_flow_entry(dpid)
    init_packet_out_flow_entry(dpid)
  end

  def packet_in(dpid, message)
    logger.info "-------------"
    logger.info "call packet_in"
    return unless sent_to_router?(message)
    logger.info "sent to router"

    case message.data
    when Arp::Request
      logger.info "Arp::Request"
    when Arp::Reply
      logger.info "Arp::Reply"
      add_arp_lookup_flow_entry(dpid, message)
      packet_in_arp_reply(dpid, message)
    when Parser::IPv4Packet
      logger.info "Arp::Ipv4Packet"
      packet_in_ipv4(dpid, message)
    else
      logger.info "Dropping unsupported packet type: #{message.data.inspect}"
    end
  end

  private

  def sent_to_router?(message)
    return true if message.destination_mac.broadcast?
    interface = @interfaces.find_by(port_number: message.in_port)
    interface && interface.mac_address == message.destination_mac
  end

  def packet_in_arp_reply(dpid, message)
    flush_unsent_packets(dpid,
                         message.data.sender_protocol_address,
    )
  end

  def flush_unsent_packets(dpid, destination_ip)
    @unresolved_packet_queue[destination_ip].each do |each|
      send_packet_out(dpid,
        raw_data: each.to_binary_s,
        actions: SendOutPort.new(:table),
      )
    end
    @unresolved_packet_queue[destination_ip] = []
  end

  def packet_in_ipv4(dpid, message)
    if forward?(message)
      logger.info "forward"
      send_later(dpid, message)
    elsif message.ip_protocol == 1
      logger.info "echo"
      icmp = Icmp.read(message.raw_data)
      packet_in_icmpv4_echo_request(dpid, message) if icmp.icmp_type == 8
    else
      logger.debug "Dropping unsupported IPv4 packet: #{message.data}"
    end
  end

  def forward?(message)
    !@interfaces.find_by(ip_address: message.destination_ip_address)
  end

  def send_later(dpid, message)
    destination_ip = message.destination_ip_address

    interface = @interfaces.find_by_prefix(destination_ip)
    return if !interface || (interface.port_number == message.in_port)

    @unresolved_packet_queue[destination_ip] += [message.data]
    send_arp_request(dpid, destination_ip, interface)
  end

  def resolve_next_hop(destination_ip_address)
    @interfaces.find_by_prefix(destination_ip_address)
  end

  def send_arp_request(dpid, destination_ip, interface)
    arp_request =
      Arp::Request.new(source_mac: interface.mac_address,
                       sender_protocol_address: interface.ip_address,
                       target_protocol_address: destination_ip)
    send_packet_out(dpid,
                    raw_data: arp_request.to_binary,
                    actions: SendOutPort.new(interface.port_number))
  end

  def packet_in_icmpv4_echo_request(dpid, message)
    icmp_request = Icmp.read(message.raw_data)
    send_packet_out(dpid,
                    raw_data: create_icmp_reply(icmp_request).to_binary,
                    actions: SendOutPort.new(message.in_port))
  end

  def create_icmp_reply(icmp_request)
    Icmp::Reply.new(identifier: icmp_request.icmp_identifier,
                    source_mac: icmp_request.destination_mac,
                    destination_mac: icmp_request.source_mac,
                    destination_ip_address: icmp_request.source_ip_address,
                    source_ip_address: icmp_request.destination_ip_address,
                    sequence_number: icmp_request.icmp_sequence_number,
                    echo_data: icmp_request.echo_data)
  end

  def add_goto_table_flow_entry(dpid, from_id, to_id, match = Match.new)
    send_flow_mod_add(
      dpid,
      table_id: from_id,
      priority: 0,
      match: match,
      instructions: GotoTable.new(to_id),
    )
  end

  def init_classifier_flow_entry(dpid)
    add_goto_table_flow_entry(dpid,
                              CLASSIFIER_TABLE_ID,
                              ROUTING_TABLE_ID,
                              Match.new(ether_type: ETH_IPv4)
    )

    add_goto_table_flow_entry(dpid,
                              CLASSIFIER_TABLE_ID,
                              ARP_RESPONDER_TABLE_ID,
                              Match.new(ether_type: ETH_ARP)
    )
  end

  def init_arp_responder_flow_entry(dpid)
    @interfaces.get_list.each do |each|
      add_arp_request_flow_entry(dpid, each)
      add_arp_reply_flow_entry(dpid, each)
    end
  end

  def add_arp_request_flow_entry(dpid, interface)
    instructions = [
      NiciraRegMove.new(
        from: :source_mac_address,
        to: :destination_mac_address
      ),
      NiciraRegMove.new(
        from: :arp_sender_protocol_address,
        to: :arp_target_protocol_address
      ),
      NiciraRegMove.new(
        from: :arp_sender_hardware_address,
        to: :arp_target_hardware_address
      ),
      SetArpOperation.new(Arp::Reply::OPERATION),
      SetArpSenderHardwareAddress.new(interface.mac_address),
      SetArpSenderProtocolAddress.new(interface.ip_address),
      SetSourceMacAddress.new(interface.mac_address),
      SendOutPort.new((671.to_s(36)+"_"+1198505.to_s(36)).to_sym),
    ]

    send_flow_mod_add(
      dpid,
      table_id: ARP_RESPONDER_TABLE_ID,
      priority: 0,
      match: Match.new(
        ether_type: ETH_ARP,
        in_port: interface.port_number,
        arp_target_protocol_address: interface.ip_address,
        arp_operation: Arp::Request::OPERATION,
      ),
      instructions: [
        Apply.new(instructions),
      ]
    )
  end

  def add_arp_reply_flow_entry(dpid, interface)
    send_flow_mod_add(
      dpid,
      table_id: ARP_RESPONDER_TABLE_ID,
      priority: 0,
      match: Match.new(
        ether_type: ETH_ARP,
        in_port: interface.port_number,
        arp_target_protocol_address: interface.ip_address,
        arp_operation: Arp::Reply::OPERATION,
      ),
      instructions: [
        Apply.new([
          SendOutPort.new(:controller)
        ]),
      ]
    )
  end

  def init_routing_flow_entry(dpid)
    @interfaces.get_list.each do |each|
      send_flow_mod_add(
        dpid,
        table_id: ROUTING_TABLE_ID,
        priority: 1,
        match: Match.new(
          ether_type: ETH_IPv4,
          ipv4_destination_address: each.ip_address.mask(each.netmask_length),
          ipv4_destination_address_mask: gen_mask(each.netmask_length),
        ),
        instructions: [
          Apply.new([
            NiciraRegMove.new(
              from: :ipv4_destination_address,
              to: :reg0
            ),
          ]),
	  GotoTable.new(INTERFACE_LOOKUP_TABLE_ID),
        ]
      )

      send_flow_mod_add(
        dpid,
        table_id: ROUTING_TABLE_ID,
        priority: 4545,
        match: Match.new(
          ether_type: ETH_IPv4,
          ipv4_destination_address: each.ip_address,
        ),
        instructions: [
          Apply.new([
            SendOutPort.new(:controller)
          ]),
        ]
      )
    end
  end

  def init_interface_lookup_flow_entry(dpid)
    @interfaces.get_list.each do |each|
      send_flow_mod_add(
        dpid,
        table_id: INTERFACE_LOOKUP_TABLE_ID,
        priority: 0,
        match: Match.new(
          reg0: each.ip_address.mask(each.netmask_length).to_i,
          reg0_mask: gen_mask(each.netmask_length).to_i,
        ),
        instructions: [
          Apply.new([
            NiciraRegLoad.new(
              each.port_number,
              :reg1
            ),
            SetSourceMacAddress.new(each.mac_address),
          ]),
	  GotoTable.new(ARP_LOOKUP_TABLE_ID),
        ]
      )
    end
  end

  def init_arp_lookup_flow_entry(dpid)
    send_flow_mod_add(
      dpid,
      table_id: ARP_LOOKUP_TABLE_ID,
      priority: 0,
      match: Match.new,
      instructions: [
        Apply.new([
          SendOutPort.new(:controller),
        ]),
      ]
    )
  end

  def init_packet_out_flow_entry(dpid)
    send_flow_mod_add(
      dpid,
      table_id: PACKET_OUT_TABLE_ID,
      priority: 0,
      match: Match.new,
      instructions: [
        Apply.new([
          NiciraSendOutPort.new(:reg1),
        ]),
      ]
    )
  end

  def add_arp_lookup_flow_entry(dpid, message)
    send_flow_mod_add(
      dpid,
      table_id: ARP_LOOKUP_TABLE_ID,
      priority: 4545,
      match: Match.new(
        reg0: message.sender_protocol_address.to_i,
      ),
      instructions: [
        Apply.new([
          SetDestinationMacAddress.new(message.sender_hardware_address),
        ]),
        GotoTable.new(PACKET_OUT_TABLE_ID),
      ]
    )
  end

  def gen_mask(len)
    IPv4Address.new(MASK32).mask(len)
  end
end
