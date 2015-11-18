require 'interfaces'

class SimpleRouter < Trema::Controller
  CLASSIFIER_TABLE_ID       = 0
  ARP_RESPONDER_TABLE_ID    = 2
  ROUTING_TABLE_ID          = 3
  INTERFACE_LOOKUP_TABLE_ID = 4
  ARP_LOOKUP_TABLE_ID       = 5
  PACKET_OUT_TABLE_ID       = 6

  ETH_IPv4        = 0x0800
  ETH_ARP         = 0x0806

  def start(_args)
    load File.join(__dir__, '..', 'simple_router.conf')
    @interfaces = Interfaces.new(Configuration::INTERFACES)
    @unresolved_packet_queue = Hash.new { [] }
    logger.info "#{name} started."
  end

  def switch_ready(dpid)
    init_classifier_flow_entry(dpid)
    init_arp_responder_flow_entry(dpid, Configuration::INTERFACES)
    init_routing_flow_entry(dpid, Configuration::INTERFACES)
    init_interface_lookup_flow_entry(dpid, Configuration::INTERFACES)
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
    logger.info "called send_arp_request"
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

  def add_goto_table_flow_entry(dpid, from_id, to_id)
    send_flow_mod_add(
      dpid,
      table_id: from_id,
      idle_timeout: 0,
      priority: 0,
      match: Match.new,
      instructions: GotoTable.new(to_id),
    )
  end

  def init_classifier_flow_entry(dpid)
    send_flow_mod_add(
      dpid,
      table_id: CLASSIFIER_TABLE_ID,
      idle_timeout: 0,
      priority: 0,
      match: Match.new(ether_type: ETH_IPv4),
      instructions: GotoTable.new(ROUTING_TABLE_ID)
    )
    send_flow_mod_add(
      dpid,
      table_id: CLASSIFIER_TABLE_ID,
      idle_timeout: 0,
      priority: 0,
      match: Match.new(ether_type: ETH_ARP),
      instructions: GotoTable.new(ARP_RESPONDER_TABLE_ID)
    )
  end

  def init_arp_responder_flow_entry(dpid, interfaces_conf = [])
    interfaces_conf.map do |each|
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
          SetArpSenderHardwareAddress.new(each.fetch(:mac_address)),
          SetArpSenderProtocolAddress.new(each.fetch(:ip_address)),
          SetSourceMacAddress.new(each.fetch(:mac_address)),
          SendOutPort.new((671.to_s(36)+"_"+1198505.to_s(36)).to_sym),
        ]
      send_flow_mod_add(
        dpid,
        table_id: ARP_RESPONDER_TABLE_ID,
        idle_timeout: 0,
        priority: 0,
        match: Match.new(
          ether_type: ETH_ARP,
          in_port: each.fetch(:port),
          arp_target_protocol_address: each.fetch(:ip_address),
          arp_operation: Arp::Request::OPERATION,
        ),
        instructions: [
          Apply.new(instructions),
        ]
      )

      send_flow_mod_add(
        dpid,
        table_id: ARP_RESPONDER_TABLE_ID,
        idle_timeout: 0,
        priority: 0,
        match: Match.new(
          ether_type: ETH_ARP,
          in_port: each.fetch(:port),
          arp_target_protocol_address: each.fetch(:ip_address),
          arp_operation: Arp::Reply::OPERATION,
        ),
        instructions: [
          Apply.new([
            SendOutPort.new(:controller)
          ]),
        ]
      )
    end
  end

  def init_routing_flow_entry(dpid, interfaces_conf)
    interfaces_conf.map do |each|
      ip_mask = gen_mask(each.fetch(:netmask_length))
      send_flow_mod_add(
        dpid,
        table_id: ROUTING_TABLE_ID,
        idle_timeout: 0,
        priority: 1,
        match: Match.new(
          ether_type: ETH_IPv4,
          ipv4_destination_address: IPv4Address.new(each.fetch(:ip_address)).to_i & ip_mask,
          ipv4_destination_address_mask: ip_mask,
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
        idle_timeout: 0,
        priority: 4545,
        match: Match.new(
          ether_type: ETH_IPv4,
          ipv4_destination_address: each.fetch(:ip_address),
        ),
        instructions: [
          Apply.new([
            SendOutPort.new(:controller)
          ]),
        ]
      )
    end
  end

  def init_interface_lookup_flow_entry(dpid, interfaces_conf)
    interfaces_conf.map do |each|
      ip_mask = gen_mask(each.fetch(:netmask_length))
      send_flow_mod_add(
        dpid,
        table_id: INTERFACE_LOOKUP_TABLE_ID,
        idle_timeout: 0,
        priority: 0,
        match: Match.new(
          reg0: IPv4Address.new(each.fetch(:ip_address)).to_i & ip_mask,
          reg0_mask: ip_mask,
        ),
        instructions: [
          Apply.new([
            NiciraRegLoad.new(
              each.fetch(:port), 
              :reg1
            ),
            SetSourceMacAddress.new(each.fetch(:mac_address)),
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
      idle_timeout: 0,
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
      idle_timeout: 0,
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
      idle_timeout: 0,
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
    mask = 0
    ((32-len)..31).each{ |p|
      mask |= 1 << p
    }
    mask
  end
end
