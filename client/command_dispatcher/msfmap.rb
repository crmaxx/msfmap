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
	
	@@msfmap_version = '0.6'
	@@msfmap_default_num_of_ports = 100
	
	@@msfmap_opts = Rex::Parser::Arguments.new(
		"-h"			=> [ false, "Print this help summary page." ],
		"-oN"			=> [ true,	"Output scan in normal format to the given filename." ],
		"-p" 			=> [ true,	"Only scan specified ports" ],
		"-PN"			=> [ false, "Treat all hosts as online -- skip host discovery" ],
		"-sP"			=> [ false, "Ping Scan - go no further than determining if host is online" ],
		"-sT"			=> [ false, "TCP Connect() scan" ],
		"-T<0-5>"		=> [ false, "Set timing template (higher is faster)" ],
		"--top-ports"	=> [ true, 	"Scan <number> most common ports" ],
		"-v"			=> [ false, "Increase verbosity level" ]
	)
	
	def cmd_msfmap(*args)
		# C taught me to define shit here
		verbosity = 0
		out_normal = nil
		opts = {}	# next lines define scan defaults
		opts['ping'] = true
		opts['scan_type'] = 'tcp_connect'
		
		if args.length < 1 or args.include?("-h")
			print_line("MSFMap (v#{@@msfmap_version}) Meterpreter Base Port Scanner")
			print_line("Usage: msfmap [Options] {target specification}")
			print_line(@@msfmap_opts.usage)
			return true
		end

		ip_range_walker = Rex::Socket::RangeWalker.new(args.pop())
		args.each do |opt|	# parse custom arguments first
			if opt[0..1] == "-T" and [ "0", "1", "2", "3", "4", "5" ].include?(opt[2,1])
				opts['timing'] = opt[2,1].to_i
			elsif [ "-P0", "-Pn", "-PN" ].include?(opt)
				opts['ping'] = false
			elsif opt == "--top-ports"
				val = args[args.index(opt) + 1]
				if val =~ /^[0-9]+$/
					val = val.to_i
					if not (1 < val and val < 1000)
						print_error("--top-ports should be an integer between 1 and 1000")
						return true
					end
					opts['ports-top'] = val
				else
					print_error("--top-ports should be an integer between 1 and 1000")
				end
			end
		end
		@@msfmap_opts.parse(args) { |opt, idx, val|
			case opt
				when "-oN"
					out_normal = ::File.open(val, "w")
				when "-p"
					if not val.match(/\d((-|,)\d)*$/)
						print_error("Invalid Port Specification.")
						return true
					else
						opts['ports'] = Rex::Socket.portspec_crack(val)
					end
				when "-v"
					verbosity += 1
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

		# register a clean up routine to free memory on the server side in case the user issues a Ctrl-C
		trap("SIGINT") do
			print_line("Cleaning Up...")
			client.msfmap.msfmap_cleanup()
			print_line("Done.")
			return true
		end
		
		print_line("")
		print_line("Starting MSFMap #{@@msfmap_version}")
		if out_normal
			out_normal.write("Starting MSFMap #{@@msfmap_version}\n")
		end
		start_time = Time.now
		
		scan_results_length = 0
		if opts['scan_type'][0,3] == 'tcp' or opts['scan_type'][0,3] == 'udp'	# setup stuff for scans that include ports
			if opts.include?('ports')
				total_ports = opts['ports'].length
			elsif opts.include?('ports-top')
				total_ports = opts['ports-top']
			else
				total_ports = @@msfmap_default_num_of_ports
			end

			services = get_nmap_services(opts['scan_type'][0,3])	# services associated-array, indexed by port number
			if services.length == 0
				print_error("nmap-services Could Not Be Located, Service Name Resolution Has Been Disabled.")	# services will stay empty and every call to .include? will fail
			end
		end

		client.msfmap.msfmap_core(ip_range_walker) do |scan_results|
			scan_results_length += scan_results.length
			scan_results.each do |host_result|
				output_msg = "MSFMap scan report for #{host_result['host']}\n"
				output_msg << "Host is up.\n"

				if opts['scan_type'][0,3] == 'tcp' or opts['scan_type'][0,3] == 'udp'
					not_shown_ports = (total_ports - host_result['open_ports'].length)
					if not_shown_ports != 0
						output_msg << "Not shown: #{not_shown_ports} closed ports\n"
					end
					host_result['open_ports'] = host_result['open_ports'].sort()
					
					largest_num_space = host_result['open_ports'][-1].to_s.length + 4 # plus 4 for the /tcp or /udp
					if host_result['open_ports'].length != 0
						output_msg << "PORT " + " " * (largest_num_space - 4) + "STATE SERVICE\n"
					end
					host_result['open_ports'].each do |port|
						if services.include?(port)
							output_msg << port.to_s + "/tcp" + " " * (largest_num_space - port.to_s.length - 3) + "open  " + services[port] + "\n"
						else
							output_msg << port.to_s + "/tcp" + " " * (largest_num_space - port.to_s.length - 3) + "open  unknown\n"
						end
					end
				end
				print_line(output_msg)
				if out_normal
					out_normal.write(output_msg << "\n")	# trailing new line to compensate for print_line
				end
			end
		end
		
		end_time = Time.now
		elapsed_time = (end_time - start_time).round(2)
		print_line("MSFMap done: #{ip_range_walker.length} IP address (#{scan_results_length} hosts up) scanned in #{elapsed_time} seconds\n")
		if out_normal
			out_normal.write("MSFMap done: #{ip_range_walker.length} IP address (#{scan_results_length} hosts up) scanned in #{elapsed_time} seconds\n")
			out_normal.close
		end

		client.msfmap.msfmap_cleanup()
		return true
	end
	
	#
	# Locate and parse a nmap-services file from a NMap install
	#
	def get_nmap_services(ip_proto)
		nmap_services_check_locations = [
			'/usr/local/share/nmap/nmapblah-services',
			'/usr/share/nmap/nmapblah-services',
			File.join(Msf::Config.install_root, "../share/nmap/nmap-services")
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
		nmap_services_file_h = ::File.open(nmap_services_file, 'r')
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
