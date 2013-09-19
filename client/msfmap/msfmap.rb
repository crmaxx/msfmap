require 'rex/post/meterpreter/packet_response_waiter'
require 'rex/post/meterpreter/extensions/msfmap/tlv'
require 'rex/post/meterpreter/extensions/msfmap/constants'

module Rex
module Post
module Meterpreter
module Extensions
module MSFMap

###
#
# This meterpreter extension implements an in-memory portscanner with
# NMap like functionality.
#
###
class MSFMap < Extension

  attr_accessor :thread_holder_ptr, :number_of_threads

  def initialize(client)
    super(client, 'msfmap')
    client.register_extension_aliases(
      [
        {
          'name' => 'msfmap',
          'ext'	=> self
        },
      ])
    @thread_holder_ptr = nil
    @number_of_threads = 0
    @last_error = 0
  end

  def msfmap_init(opts = {})
    return if @thread_holder_ptr != nil
    @last_error = 0

    if opts.include?('ports')
      ports = opts['ports']
    elsif opts.include?('ports-top')
      ports = NMAP_TOP_1000_TCP_PORTS[0, opts['ports-top']]
    else
      ports = NMAP_TOP_1000_TCP_PORTS[0, 100]
    end
    if opts.include?('ping')
      ping = opts['ping']
    else
      ping = true
    end
    scan_type = opts['scan_type'] || 'tcp_connect'
    case scan_type
      when 'tcp_connect'
        scan_type = MSFMAP_OPTS_SCAN_TYPE_TCP_CONNECT
      when 'tcp_syn'
        scan_type = MSFMAP_OPTS_SCAN_TYPE_TCP_SYN
      when 'ping'
        scan_type = MSFMAP_OPTS_SCAN_TYPE_PING
    end

    timing_profile = opts['timing'] || 3	# get the timing profile 0-5 then translate it to the proper bit mask
    case timing_profile
      when 0	# DO NOT CHANGE THE NUMBER OF THREADS
        timing_profile = MSFMAP_OPTS_TIMING_0
        self.number_of_threads = 4
      when 1
        timing_profile = MSFMAP_OPTS_TIMING_1
        self.number_of_threads = 8
      when 2
        timing_profile = MSFMAP_OPTS_TIMING_2
        self.number_of_threads = 16
      when 3
        timing_profile = MSFMAP_OPTS_TIMING_3
        self.number_of_threads = 32
      when 4
        timing_profile = MSFMAP_OPTS_TIMING_4
        self.number_of_threads = 64
      when 5
        timing_profile = MSFMAP_OPTS_TIMING_5
        self.number_of_threads = 128
    end

    request = Packet.create_request('msfmap_init')
    portspacked = pack_ports(ports)
    request.add_tlv(TLV_TYPE_MSFMAP_PORTS_SPECIFICATION, portspacked)

    # configure option flags
    options = 0
    if ping
      options = (options | MSFMAP_OPTS_PING)
    end
    options = (options | timing_profile)
    options = (options | scan_type)

    request.add_tlv(TLV_TYPE_MSFMAP_SCAN_OPTIONS, options)

    response = client.send_request(request)
    thread_holder = response.get_tlv_value(TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION)
    error_flags = response.get_tlv_value(TLV_TYPE_MSFMAP_RETURN_FLAGS)

    if (error_flags & MSFMAP_RET_ERROR_FLAGS) == 0
      @thread_holder_ptr = thread_holder
      return true
    else
      @last_error = (error_flags & MSFMAP_RET_ERROR_FLAGS)
      return false
    end
  end

  def msfmap_core(rex_ip_range)
    return false if @thread_holder_ptr == nil
    @last_error = 0

    # build the first list of IPs to go
    ipaddrs = []
    ip_local_queue = []
    ip_info_holder = {}
    self.number_of_threads.times do |i|
      next_ip = rex_ip_range.next_ip
      if next_ip == nil
        break
      end
      ip_local_queue.push(next_ip)
      ipaddrs.push(Rex::Socket.addr_aton(next_ip))
    end
    ipaddrs = pack_ips(ipaddrs)

    ips_in_remote_queue = ((ipaddrs.length / 4) - 1)	# minus one for the null trailer
    while ips_in_remote_queue > 0
      if ip_info_holder.keys.include?(ip_local_queue[0])
        host_result = ip_info_holder.delete(ip_local_queue[0])
        ip_local_queue.shift
        if host_result
          yield [ host_result ]
        end
        next
      end

      begin
        request = Packet.create_request('msfmap_core')
        request.add_tlv(TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION, @thread_holder_ptr)
        request.add_tlv(TLV_TYPE_MSFMAP_IPADDRESSES, ipaddrs)

        response = client.send_request(request)
        ipaddrs = "\x00\x00\x00\x00" # don't resend the IP to be processed
      end until response.has_tlv?(TLV_TYPE_MSFMAP_IPADDRESSES) or (response.get_tlv_value(TLV_TYPE_MSFMAP_RETURN_FLAGS) & MSFMAP_RET_ERROR_FLAGS) != 0

      return_flags = response.get_tlv_value(TLV_TYPE_MSFMAP_RETURN_FLAGS)
      if not response.has_tlv?(TLV_TYPE_MSFMAP_IPADDRESSES) and ((return_flags & MSFMAP_RET_ERROR_FLAGS) != 0)
        @last_error = (return_flags & MSFMAP_RET_ERROR_FLAGS)
        return false
      end

      ips_in_remote_queue -= 1
      next_ip = rex_ip_range.next_ip
      if next_ip == nil
        ipaddrs = "\x00\x00\x00\x00"
      else
        ip_local_queue.push(next_ip)
        ipaddrs = pack_ips( [ Rex::Socket.addr_aton(next_ip) ] )
        ips_in_remote_queue += 1
      end

      host = response.get_tlv_value(TLV_TYPE_MSFMAP_IPADDRESSES)
      host = unpack_ips(host)
      host = Rex::Socket.addr_ntoa(host[0])
      if ((return_flags & MSFMAP_RET_HOST_UP) == 0) or ((return_flags & MSFMAP_RET_ERROR_FLAGS) != 0)
        if (return_flags & MSFMAP_RET_ERROR_FLAGS) != 0
          @last_error = (return_flags & MSFMAP_RET_ERROR_FLAGS)
          return false
        end
        if host == ip_local_queue[0]
          ip_local_queue.shift
        else
          ip_info_holder[host] = nil
        end
        next	# host isn't up
      end
      open_ports = (response.get_tlv_value(TLV_TYPE_MSFMAP_PORTS_OPEN) or "")
      open_ports = unpack_ports(open_ports)
      client.framework.db.report_host(:host => host)
      open_ports.each do |port|
        client.framework.db.report_service(:host => host, :port => port)
      end
      host_result =	{	'host' => host,
                'open_ports' => open_ports,
              }
      if host == ip_local_queue[0]
        ip_local_queue.shift
      else
        ip_info_holder[host] = host_result
        next
      end
      yield [ host_result ]
    end

    while ip_local_queue.length > 0
      ip_addr = ip_local_queue.shift
      if ip_info_holder.keys.include?(ip_addr)
        host_result = ip_info_holder.delete(ip_addr)
        if host_result
          yield [ host_result ]
        end
      end
    end
    return true
  end

  def msfmap_cleanup()
    return if @thread_holder_ptr == nil
    @last_error = 0

    request = Packet.create_request('msfmap_cleanup')
    request.add_tlv(TLV_TYPE_MSFMAP_THREAD_HOLDER_LOCATION, @thread_holder_ptr)
    response = client.send_request(request)
    @thread_holder_ptr = nil
    return
  end

  def msfmap_get_last_error()
    return @last_error
  end

  def pack_ips(ips)
    ips.push("\x00\x00\x00\x00")
    ipspacked = ips.join('')
    ips.pop()
    return ipspacked
  end

  def unpack_ips(ips)
    ipsunpacked = Array.new
    (0..(ips.length - 4)).step(4) do |i|
      ipsunpacked.push( ips[i..i + 4] )
    end
    return ipsunpacked
  end

  def pack_ports(ports)
    # DONT GET RID OF THIS LINE
    ports.push(0)	# Must be null terminated for the C side of the code
    portspacked = ports.pack("S" * ports.length)
    ports.pop()		# Remove the trailing 0 so the original array is un altered
    return portspacked
  end

  def unpack_ports(ports)
    return ports.unpack("S" * (ports.length / 2))
  end
end

end; end; end; end; end
