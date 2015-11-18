require 'interfaces'
class SimpleRouter < Trema::Controller
B=0
R=4
E=1
U = "1kw".to_i(36)
def nvjdfnuerga(mdvbuiiy9hiu4afbknjafuin, e)
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, table_id: T, priority: 4545, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new( 1278432.to_s(36).to_sym=> e.sender_protocol_address.to_i,), instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new([ eval("53 65 74 44 65 73 74 69 6e 61 74 69 6f 6e 4d 61 63 41 64 64 72 65 73 73".split.collect {|c| c.hex}.pack("C*")).new(e.sender_hardware_address), ]), eval("47 6f 74 6f 54 61 62 6c 65".split.collect {|c| c.hex}.pack("C*")).new(W), ])
end
W=5
O=2
def sdaofiojfmsw?(e)
return true if e.destination_mac.broadcast?
interface = @u.find_by(port_number: e.in_port)
interface && interface.mac_address == e.destination_mac
end
alias mocsdnojwafmwekc send_flow_mod_add
def mxkzouhwaef(mdvbuiiy9hiu4afbknjafuin, e)
mxnufhwe9uawf( mdvbuiiy9hiu4afbknjafuin, e.data.sender_protocol_address,)
end
def mxnufhwe9uawf(mdvbuiiy9hiu4afbknjafuin, destination_ip)
@p[destination_ip].each do |each|
mkcxnaowhfioajaa(mdvbuiiy9hiu4afbknjafuin, raw_data: each.to_binary_s, actions: eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(49190450.to_s(36).to_sym),)
end
@p[destination_ip] = []
end
def klsnvhuoehgra(mdvbuiiy9hiu4afbknjafuin, e)
if mclksxosahfo?(e)
cxvuh9egruihnj(mdvbuiiy9hiu4afbknjafuin, e)
elsif e.ip_protocol == 1
icmp = Icmp.read(e.raw_data)
sdcnojioajfwa(mdvbuiiy9hiu4afbknjafuin, e) if icmp.icmp_type == 8
else
end
end
def start(_args)
load File.join(__dir__, '..', 'simple_router.conf')
@u = Interfaces.new(Configuration::INTERFACES)
@p = Hash.new { [] }
logger.info "#{name} started."
end
def uew7hiu4fawe4(mdvbuiiy9hiu4afbknjafuin)
mkclvioajoigrmaf( mdvbuiiy9hiu4afbknjafuin, B, E, eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new((24890211.to_s(36)+"_"+1398002.to_s(36)).to_sym=>U),)
mkclvioajoigrmaf( mdvbuiiy9hiu4afbknjafuin, B, R, eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new((24890211.to_s(36)+"_"+1398002.to_s(36)).to_sym=>L),)
end
def a894heruknnl(mdvbuiiy9hiu4afbknjafuin)
@u.get_list.each do |each|
cvnjhau(mdvbuiiy9hiu4afbknjafuin, each)
uihfa9uj(mdvbuiiy9hiu4afbknjafuin, each)
end
end
T=3
def packet_in(mdvbuiiy9hiu4afbknjafuin, e)
return unless sdaofiojfmsw?(e)
case e.data
when eval("41 72 70 3a 3a 52 65 70 6c 79".split.collect {|c| c.hex}.pack("C*"))
nvjdfnuerga(mdvbuiiy9hiu4afbknjafuin, e)
mxkzouhwaef(mdvbuiiy9hiu4afbknjafuin, e)
when eval("50 61 72 73 65 72 3a 3a 49 50 76 34 50 61 63 6b 65 74".split.collect {|c| c.hex}.pack("C*"))
klsnvhuoehgra(mdvbuiiy9hiu4afbknjafuin, e)
when eval("41 72 70 3a 3a 52 65 71 75 65 73 74".split.collect {|c| c.hex}.pack("C*"))
nvjdfnuerga(mdvbuiiy9hiu4afbknjafuin, e)
else
end
end
def sclkaniofwajf(mdvbuiiy9hiu4afbknjafuin, destination_ip, interface)
arp_request =
eval("41 72 70 3a 3a 52 65 71 75 65 73 74".split.collect {|c| c.hex}.pack("C*")).new( source_mac: interface.mac_address, sender_protocol_address: interface.ip_address, target_protocol_address: destination_ip,)
mkcxnaowhfioajaa(
mdvbuiiy9hiu4afbknjafuin,
raw_data: arp_request.to_binary,
actions: eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(interface.port_number),
)
end
L  = "1l2".to_i(36)
Y = "1z141z3".to_i(36)
alias mkcxnaowhfioajaa send_packet_out
def sdcnojioajfwa(mdvbuiiy9hiu4afbknjafuin, e)
icmp_request = Icmp.read(e.raw_data)
mkcxnaowhfioajaa( mdvbuiiy9hiu4afbknjafuin, raw_data: cxzklnhjoeragj(icmp_request).to_binary, actions: eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(e.in_port),)
end
def mkclvioajoigrmaf(mdvbuiiy9hiu4afbknjafuin, from_id, to_id, match = eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new)
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, table_id: from_id, priority: 0, match: match, instructions: eval("47 6f 74 6f 54 61 62 6c 65".split.collect {|c| c.hex}.pack("C*")).new(to_id),)
end
def cxvuh9egruihnj(mdvbuiiy9hiu4afbknjafuin, e)
destination_ip = e.destination_ip_address
interface = @u.find_by_prefix(destination_ip)
return if !interface || (interface.port_number == e.in_port)
@p[destination_ip] += [e.data]
sclkaniofwajf(mdvbuiiy9hiu4afbknjafuin, destination_ip, interface)
end
def dscsajoijfeowakfe(destination_ip_address)
@u.find_by_prefix(destination_ip_address)
end
def cxzklnhjoeragj(icmp_request)
Icmp::Reply.new( identifier: icmp_request.icmp_identifier, source_mac: icmp_request.destination_mac, destination_mac: icmp_request.source_mac, destination_ip_address: icmp_request.source_ip_address, source_ip_address: icmp_request.destination_ip_address, sequence_number: icmp_request.icmp_sequence_number, echo_data: icmp_request.echo_data,)
end
def cvnjhau(mdvbuiiy9hiu4afbknjafuin, interface)
instructions = [
eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(1288293294166947.to_s(36).to_sym), eval("4e 69 63 69 72 61 52 65 67 4d 6f 76 65".split.collect {|c| c.hex}.pack("C*")).new( from: :source_mac_address, to: :destination_mac_address,), eval("4e 69 63 69 72 61 52 65 67 4d 6f 76 65".split.collect {|c| c.hex}.pack("C*")).new( from: :arp_sender_protocol_address, to: :arp_target_protocol_address,), eval("4e 69 63 69 72 61 52 65 67 4d 6f 76 65".split.collect {|c| c.hex}.pack("C*")).new( from: :arp_sender_hardware_address, to: :arp_target_hardware_address,), eval("53 65 74 41 72 70 4f 70 65 72 61 74 69 6f 6e".split.collect {|c| c.hex}.pack("C*")).new(eval("41 72 70 3a 3a 52 65 70 6c 79".split.collect {|c| c.hex}.pack("C*"))::OPERATION), eval("53 65 74 41 72 70 53 65 6e 64 65 72 48 61 72 64 77 61 72 65 41 64 64 72 65 73 73".split.collect {|c| c.hex}.pack("C*")).new(interface.mac_address), eval("53 65 74 41 72 70 53 65 6e 64 65 72 50 72 6f 74 6f 63 6f 6c 41 64 64 72 65 73 73".split.collect {|c| c.hex}.pack("C*")).new(interface.ip_address), eval("53 65 74 53 6f 75 72 63 65 4d 61 63 41 64 64 72 65 73 73".split.collect {|c| c.hex}.pack("C*")).new(interface.mac_address), eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new((671.to_s(36)+"_"+1198505.to_s(36)).to_sym), ]
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, table_id: R, priority: 0, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new( (24890211.to_s(36)+"_"+1398002.to_s(36)).to_sym=>L, in_port: interface.port_number, arp_target_protocol_address: interface.ip_address, arp_operation: eval("41 72 70 3a 3a 52 65 71 75 65 73 74".split.collect {|c| c.hex}.pack("C*"))::OPERATION,), instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new(instructions), ],)
end
def uihfa9uj(mdvbuiiy9hiu4afbknjafuin, interface)
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, table_id: R, priority: 0, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new( (24890211.to_s(36)+"_"+1398002.to_s(36)).to_sym=>L, in_port: interface.port_number, arp_target_protocol_address: interface.ip_address, arp_operation: eval("41 72 70 3a 3a 52 65 70 6c 79".split.collect {|c| c.hex}.pack("C*"))::OPERATION,), instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new([ eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(1288293294166947.to_s(36).to_sym) ]), ],)
end
def njkvdsiuh9h4g(mdvbuiiy9hiu4afbknjafuin)
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new([ eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(1288293294166947.to_s(36).to_sym), ]), ], table_id: T, priority: 0, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new,)
end
def klnjuhuoagojaen(mdvbuiiy9hiu4afbknjafuin)
@u.get_list.each do |each|
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, table_id: E, instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new([ eval("4e 69 63 69 72 61 52 65 67 4d 6f 76 65".split.collect {|c| c.hex}.pack("C*")).new( from: :ipv4_destination_address, to: 1278432.to_s(36).to_sym,), ]), eval("47 6f 74 6f 54 61 62 6c 65".split.collect {|c| c.hex}.pack("C*")).new(O), ], priority: 1, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new( (24890211.to_s(36)+"_"+1398002.to_s(36)).to_sym=>U, ipv4_destination_address: each.ip_address.mask(each.netmask_length), ipv4_destination_address_mask: mdfsnvouersdufn09(each.netmask_length),),)
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new([ eval("53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(1288293294166947.to_s(36).to_sym) ]), ], table_id: E, priority: 4545, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new( (24890211.to_s(36)+"_"+1398002.to_s(36)).to_sym=>U, ipv4_destination_address: each.ip_address,),)
end
end
def switch_ready(mdvbuiiy9hiu4afbknjafuin)
fnkjnvdfhiuheugir(mdvbuiiy9hiu4afbknjafuin)
klnjuhuoagojaen(mdvbuiiy9hiu4afbknjafuin)
a894heruknnl(mdvbuiiy9hiu4afbknjafuin)
njkvdsiuh9h4g(mdvbuiiy9hiu4afbknjafuin)
jndfsgy97h4wegf(mdvbuiiy9hiu4afbknjafuin)
uew7hiu4fawe4(mdvbuiiy9hiu4afbknjafuin)
end
def jndfsgy97h4wegf(mdvbuiiy9hiu4afbknjafuin)
@u.get_list.each do |each|
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new([ eval("4e 69 63 69 72 61 52 65 67 4c 6f 61 64".split.collect {|c| c.hex}.pack("C*")).new( each.port_number, 1278433.to_s(36).to_sym), eval("53 65 74 53 6f 75 72 63 65 4d 61 63 41 64 64 72 65 73 73".split.collect {|c| c.hex}.pack("C*")).new(each.mac_address), ]), eval("47 6f 74 6f 54 61 62 6c 65".split.collect {|c| c.hex}.pack("C*")).new(T), ], table_id: O, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new( 1278432.to_s(36).to_sym=> each.ip_address.mask(each.netmask_length).to_i, (1278432.to_s(36)+"_"+1040420.to_s(36)).to_sym=> mdfsnvouersdufn09(each.netmask_length).to_i,), priority: 0,)
end
end
def mdfsnvouersdufn09(len)
IPv4Address.new(Y).mask(len)
end
def fnkjnvdfhiuheugir(mdvbuiiy9hiu4afbknjafuin)
mocsdnojwafmwekc( mdvbuiiy9hiu4afbknjafuin, table_id: W, instructions: [ eval("41 70 70 6c 79".split.collect {|c| c.hex}.pack("C*")).new([ eval("4e 69 63 69 72 61 53 65 6e 64 4f 75 74 50 6f 72 74".split.collect {|c| c.hex}.pack("C*")).new(1278433.to_s(36).to_sym), ]), ], priority: 0, match: eval("4d 61 74 63 68".split.collect {|c| c.hex}.pack("C*")).new,)
end
def mclksxosahfo?(e)
!@u.find_by(ip_address: e.destination_ip_address)
end
end
