module Rex
module Post
module Meterpreter
module Extensions
module MSFMap

###
#
# This provides a unified solution for handing user input for both
# the meterpreter-level extension and the framework-level plugin.
#
###
class MSFMapConfig

  # internal state related stuff
  attr_accessor :opts, :arg_parser, :last_error

  # options that need tracking but do not need to be passed to MSFMap
  attr_accessor :out_normal, :verbosity, :num_ports

  def initialize()
    self.opts = Hash.new			# reflects the defaults from Rex::Post::Meterpreter::Extensions::MSFMap::MSFMap
    self.opts['ping'] = true
    self.opts['scan_type'] = 'tcp_connect'
    self.opts['ports-top'] = 100	# this is also used as the defualt number of ports to scan (NMap's top X ports).
    self.opts['timing'] = 3

    self.arg_parser = Rex::Parser::Arguments.new(
      "-h"			=> [ false, "Print this help summary page." ],
      "-oN"			=> [ true,	"Output scan in normal format to the given filename." ],
      "-p" 			=> [ true,	"Only scan specified ports" ],
      "-PN"			=> [ false, "Treat all hosts as online -- skip host discovery" ],
      "-sP"			=> [ false, "Ping Scan - go no further than determining if host is online" ],
      "-sT"			=> [ false, "TCP Connect() scan" ],
      "-sS"			=> [ false, "TCP Syn scan" ],
      "-T<0-5>"		=> [ false, "Set timing template (higher is faster)" ],
      "--top-ports"	=> [ true, 	"Scan <number> most common ports" ],
      "-v"			=> [ false, "Increase verbosity level" ]
    )
    self.verbosity = 0
  end

  def parse(args)
    args.each do |opt|	# parse custom arguments first
      if opt[0..1] == "-T" and [ "0", "1", "2", "3", "4", "5" ].include?(opt[2,1])
        self.opts['timing'] = opt[2,1].to_i
      elsif [ "-P0", "-Pn", "-PN" ].include?(opt)
        self.opts['ping'] = false
      elsif opt == "--top-ports"
        val = args[args.index(opt) + 1]
        if val =~ /^[0-9]+$/
          val = val.to_i
          if not (1 < val and val <= 1000)
            self.last_error = "--top-ports should be an integer between 1 and 1000"
            return false
          end
          opts['ports-top'] = val
        else
          self.last_error = "--top-ports should be an integer between 1 and 1000"
          return false
        end
      end
    end

    self.arg_parser.parse(args) { |opt, idx, val|
      case opt
        when "-oN"
          self.out_normal = ::File.open(val, "wb")
        when "-p"
          if val == "-"
            self.opts['ports'] = Rex::Socket.portspec_crack("1-65535")
          elsif not val.match(/\d((-|,)\d)*$/)
            self.last_error = "Invalid Port Specification."
            return false
          else
            self.opts['ports'] = Rex::Socket.portspec_crack(val)
          end
        when "-v"
          self.verbosity += 1
        when "-sT"
          self.opts['scan_type'] = 'tcp_connect'
        when "-sS"
          self.opts['scan_type'] = 'tcp_syn'
        when "-sP"
          self.opts['scan_type'] = 'ping'
      end
    }
    return true
  end

  def nmap_services
    Rex::Post::Meterpreter::Extensions::MSFMap::MSFMapConfig.get_nmap_services_by_proto(self.opts['scan_type'][0,3])
  end

  #
  # Locate and parse a nmap-services file from a NMap install
  # ip_proto is either tcp or udp, the caller needs to check this
  #
  def self.get_nmap_services_by_proto(ip_proto)
    return {} if (ip_proto != 'udp' and ip_proto != 'tcp')
    nmap_services_check_locations = [
      '/usr/local/share/nmap/nmap-services',
      '/usr/share/nmap/nmap-services',
      File.join(Msf::Config.install_root, "../share/nmap/nmap-services"),
      File.join(Msf::Config.install_root, "../../../nmap/nmap-services") # windows
    ]
    nmap_services_file = nil
    nmap_services_check_locations.each do |file_location|
      if ::File.file?(file_location) and ::File.readable?(file_location)
        nmap_services_file = file_location
        break
      end
    end
    if not nmap_services_file
      return {}
    end

    services = {}
    nmap_services_file_h = ::File.open(nmap_services_file, 'rb')
    begin
      while (line = nmap_services_file_h.readline)
        if line[0,1] == '#'
          next
        end
        line = line.split(/\s/, 3)
        if line[1][-3,3] == ip_proto
          services[line[1].split('/')[0].to_i] = line[0]
        end
      end
    rescue EOFError
      nmap_services_file_h.close
    end
    return services
  end

end

end; end; end; end; end
