require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# MSFMap user interface.
#
###
class Console::CommandDispatcher::MSFMap

	Klass = Console::CommandDispatcher::MSFMap
	include Console::CommandDispatcher

	def initialize(shell)
		super
	end

	#
	# List of supported commands.
	#
	def commands
		{
			"msfmap" 		=> "Meterpreter Port Scanner",
		}
	end
		
	@@msfmap_opts = Rex::Parser::Arguments.new(
		"-h"	=> [ false, "Print this help summary page." ],
		"-p" 	=> [ true, "Only scan specified ports" ],
		"-PN"	=> [ false, "Treat all hosts as online -- skip host discovery" ],
		"-sP"	=> [ false, "Ping Scan - go no further than determining if host is online" ],
		"-sT"	=> [ false, "TCP Connect() scan" ],
		"-T0"	=> [ false, "Set timing template (higher is faster)" ],
		"-T1"	=> [ false, "Set timing template (higher is faster)" ],
		"-T2"	=> [ false, "Set timing template (higher is faster)" ],
		"-T3"	=> [ false, "Set timing template (higher is faster)" ],
		"-T4"	=> [ false, "Set timing template (higher is faster)" ],
		"-T5"	=> [ false, "Set timing template (higher is faster)" ],
		"-v"	=> [ false, "Increase verbosity level" ],
	)
	
	def cmd_msfmap(*args)
		# C taught me to define shit here
		# ports_spec = nil
		verbosity = 0
		opts = {}
		opts['ping'] = true
		opts['scan_type'] = 'tcp_connect'
		
		if args.length < 1 or args.include?("-h")
			print_line("MSFMap (v0.3) Meterpreter Base Port Scanner")
			print_line("Usage: msfmap [Options] {target specification}")
			print_line(@@msfmap_opts.usage)
			return true
		end

		ip_range_walker = Rex::Socket::RangeWalker.new(args.pop())
		@@msfmap_opts.parse(args) { |opt, idx, val|
			case opt
				when "-p"
					if not val.match(/\d((-|,)\d)*$/)
						print_error("Invalid Port Specification.")
						return true
					else
						opts['ports'] = Rex::Socket.portspec_crack(val)
					end
				when "-PN"
					opts['ping'] = false
				when "-v"
					verbosity += 1
				when "-T0"
					opts['timing'] = 0
				when "-T1"
					opts['timing'] = 1
				when "-T2"
					opts['timing'] = 2
				when "-T3"
					opts['timing'] = 3
				when "-T4"
					opts['timing'] = 4
				when "-T5"
					opts['timing'] = 5
				when "-sT"
					opts['scan_type'] = 'tcp_connect'
				when "-sP"
					opts['scan_type'] = 'ping'
			end
		}

		if not client.msfmap.msfmap_init(opts)
			print_error("Could Not Initialize MSFMap")
			return true
		end

		print_line("")
		print_line("Starting MSFMap 0.3")
		
		scan_results_length = 0
		if opts.include?('ports')
			total_ports = opts['ports'].length
		else
			total_ports = 100	# NMaps top 100
		end
		client.msfmap.msfmap_core(ip_range_walker) do |scan_results|
			scan_results_length += scan_results.length
			scan_results.each do |host_result|
				print_line("MSFMap scan report for #{host_result['host']}")
				print_line("Host is up.")
				if opts['scan_type'] == 'ping'
					next
				end
				
				not_shown_ports = (total_ports - host_result['open_ports'].length)
				if not_shown_ports != 0
					print_line("Not shown: #{not_shown_ports} closed ports")
				end
				host_result['open_ports'] = host_result['open_ports'].sort()
				
				largest_num_space = host_result['open_ports'][-1].to_s.length + 4 # plus 4 for the /tcp or /udp
				if host_result['open_ports'].length != 0
					print_line("PORT " + " " * (largest_num_space - 4) + "STATE SERVICE")
				end
				host_result['open_ports'].each do |port|
					print_line(port.to_s + "/tcp" + " " * (largest_num_space - port.to_s.length - 3) + "open")
				end
				print_line("")
			end
		end
		
		print_line("MSFMap done: #{ip_range_walker.length} IP address (#{scan_results_length} hosts up)")

		client.msfmap.msfmap_cleanup()
		return true
	end

	#
	# Name for this dispatcher
	#
	def name
		"MSFMap:"
	end

end

end
end
end
end
