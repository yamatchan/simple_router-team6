require 'arp_table'
require 'interfaces'
require 'routing_table'

# Simple implementation of L3 switch in OpenFlow1.0
# rubocop:disable ClassLength
class SimpleRouter < Trema::Controller
  def start(_args)
    load File.join(__dir__, '..', 'simple_router.conf')
    @interfaces = Interfaces.new(Configuration::INTERFACES)
    @arp_table = ArpTable.new
    @routing_table = RoutingTable.new(Configuration::ROUTES)
    @unresolved_packet_queue = Hash.new { [] }
    logger.info "#{name} started."
  end

  # rubocop:disable MethodLength
  # rubocop:disable AbcSize
  def switch_ready(dpid)
    send_flow_mod_delete(dpid, match: Match.new)

    send_flow_mod_add(
      dpid,
      table_id: 0,
      priority: 1,
      match: Match.new,
      instructions: Apply.new(SendOutPort.new(:controller))
    )

    @interfaces.each do |each|
      arp_request_match =
        Match.new(in_port: each.port_number,
                  ether_type: EthernetHeader::EtherType::ARP,
                  arp_operation: Arp::Request::OPERATION,
                  arp_target_protocol_address: each.ip_address)
      create_and_send_arp_reply_actions = [
        NiciraRegMove.new(from: :source_mac_address,
                          to: :destination_mac_address),
        SetSourceMacAddress.new(each.mac_address),
        SetArpOperation.new(Arp::Reply::OPERATION),
        NiciraRegMove.new(from: :arp_sender_hardware_address,
                          to: :arp_target_hardware_address),
        NiciraRegMove.new(from: :arp_sender_protocol_address,
                          to: :arp_target_protocol_address),
        SetArpSenderHardwareAddress.new(each.mac_address),
        SetArpSenderProtocolAddress.new(each.ip_address),
        SendOutPort.new(:in_port)
      ]
      send_flow_mod_add(
        dpid,
        table_id: 0,
        priority: 2,
        match: arp_request_match,
        instructions: Apply.new(create_and_send_arp_reply_actions)
      )
    end
  end
  # rubocop:enable MethodLength
  # rubocop:enable AbcSize

  def packet_in(dpid, message)
    return unless sent_to_router?(message)

    case message.data
    when Arp::Reply
      packet_in_arp_reply dpid, message
    when Parser::IPv4Packet
      packet_in_ipv4 dpid, message
    else
      logger.debug "Dropping unsupported packet type: #{message.data.inspect}"
    end
  end

  def packet_in_arp_reply(dpid, message)
    @arp_table.update(message.in_port,
                      message.sender_protocol_address,
                      message.source_mac)
    flush_unsent_packets(dpid,
                         message.data,
                         @interfaces.find_by(port_number: message.in_port))
  end

  def packet_in_ipv4(dpid, message)
    if forward?(message)
      forward(dpid, message)
    elsif message.ip_protocol == 1
      icmp = Icmp.read(message.raw_data)
      packet_in_icmpv4_echo_request(dpid, message) if icmp.icmp_type == 8
    else
      logger.debug "Dropping unsupported IPv4 packet: #{message.data}"
    end
  end

  # rubocop:disable MethodLength
  def packet_in_icmpv4_echo_request(dpid, message)
    icmp_request = Icmp.read(message.raw_data)
    if @arp_table.lookup(message.source_ip_address)
      send_packet_out(dpid,
                      raw_data: create_icmp_reply(icmp_request).to_binary,
                      actions: SendOutPort.new(message.in_port))
    else
      send_later(dpid,
                 interface: @interfaces.find_by(port_number: message.in_port),
                 destination_ip: message.source_ip_address,
                 data: create_icmp_reply(icmp_request))
    end
  end
  # rubocop:enable MethodLength

  private

  def sent_to_router?(message)
    return true if message.destination_mac.broadcast?
    interface = @interfaces.find_by(port_number: message.in_port)
    interface && interface.mac_address == message.destination_mac
  end

  def forward?(message)
    !@interfaces.find_by(ip_address: message.destination_ip_address)
  end

  # rubocop:disable MethodLength
  # rubocop:disable AbcSize
  def forward(dpid, message)
    next_hop = resolve_next_hop(message.destination_ip_address)

    interface = @interfaces.find_by_prefix(next_hop)
    return if !interface || (interface.port_number == message.in_port)

    arp_entry = @arp_table.lookup(next_hop)
    if arp_entry
      rewrite_mac = [SetSourceMacAddress.new(interface.mac_address),
                     SetDestinationMacAddress.new(arp_entry.mac_address),
                     SendOutPort.new(interface.port_number)]
      arp_match = Match.new(ether_type: message.ether_type,
                            source_mac_address: message.source_mac,
                            destination_mac_address: message.destination_mac)
      send_flow_mod_add(dpid,
                        priority: 2,
                        match: arp_match,
                        instructions: Apply.new(rewrite_mac))
      send_packet_out(dpid, raw_data: message.raw_data, actions: rewrite_mac)
    else
      send_later(dpid,
                 interface: interface,
                 destination_ip: next_hop,
                 data: message.data)
    end
  end
  # rubocop:enable AbcSize
  # rubocop:enable MethodLength

  def resolve_next_hop(destination_ip_address)
    interface = @interfaces.find_by_prefix(destination_ip_address)
    if interface
      destination_ip_address
    else
      @routing_table.lookup(destination_ip_address)
    end
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

  def send_later(dpid, options)
    destination_ip = options.fetch(:destination_ip)
    @unresolved_packet_queue[destination_ip] += [options.fetch(:data)]
    send_arp_request(dpid, destination_ip, options.fetch(:interface))
  end

  def flush_unsent_packets(dpid, arp_reply, interface)
    destination_ip = arp_reply.sender_protocol_address
    @unresolved_packet_queue[destination_ip].each do |each|
      rewrite_mac =
        [SetDestinationMacAddress.new(arp_reply.sender_hardware_address),
         SetSourceMacAddress.new(interface.mac_address),
         SendOutPort.new(interface.port_number)]
      send_packet_out(dpid, raw_data: each.to_binary_s, actions: rewrite_mac)
    end
    @unresolved_packet_queue[destination_ip] = []
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
end
# rubocop:enable ClassLength
