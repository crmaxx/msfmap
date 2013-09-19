require 'rex/post/meterpreter'
require 'rex/post/meterpreter/extensions/msfmap/config'
require 'rex/post/meterpreter/extensions/msfmap/constants'

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

  @@msfmap_version = '0.1.1'

  def cmd_msfmap(*args)
    verbosity = 0
    out_normal = nil
    opts = {}	# next lines define scan defaults
    opts['ping'] = true
    opts['scan_type'] = 'tcp_connect'

    msfmapConfig = Rex::Post::Meterpreter::Extensions::MSFMap::MSFMapConfig.new

    if args.length < 1 or args.include?("-h")
      print_line("MSFMap (v#{@@msfmap_version}) Meterpreter Base Port Scanner")
      print_line("Usage: msfmap [Options] {target specification}")
      print_line(msfmapConfig.arg_parser.usage)
      return true
    end

    ip_range_walker = Rex::Socket::RangeWalker.new(args.pop())
    if not msfmapConfig.parse(args)
      print_error(msfmapConfig.last_error)
      return true
    end

    if not client.msfmap.msfmap_init(msfmapConfig.opts)
      error = client.msfmap.msfmap_get_last_error()
      case error
        when Rex::Post::Meterpreter::Extensions::MSFMap::MSFMAP_RET_MEM_ERR
          print_error("Insufficient Memmory On Meterpreter Server")
        when Rex::Post::Meterpreter::Extensions::MSFMap::MSFMAP_RET_SCAN_TYPE_ERR
          print_error("The Desired Scan Type Is Not Supported")
        else
          print_error("Unknown Error Code: #{error}")
      end
      print_error("Could Not Initialize MSFMap")
      return true
    end

    # register a clean up routine to free memory on the server side in case the user issues a Ctrl-C
    trap("SIGINT") do
      print_line("Cleaning Up...")
      client.msfmap.msfmap_cleanup()
      print_line("Done.")
      trap("SIGINT") do
        "DEFAULT"
      end
      return true
    end

    print_line("")
    print_line("Starting MSFMap #{@@msfmap_version}")
    if msfmapConfig.out_normal
      msfmapConfig.out_normal.write("Starting MSFMap #{@@msfmap_version}\n")
    end
    start_time = Time.now

    scan_results_length = 0
    if msfmapConfig.opts['scan_type'][0,3] == 'tcp' or msfmapConfig.opts['scan_type'][0,3] == 'udp'	# setup stuff for scans that include ports
      if msfmapConfig.opts.include?('ports')
        total_ports = msfmapConfig.opts['ports'].length
      else # MSFMapConfig holds the default number of top ports to scan and leaves it here by default, it is overridden if the user sets it
        total_ports = msfmapConfig.opts['ports-top']
      end
      services = msfmapConfig.nmap_services
      if services.length == 0
        print_error("nmap-services Could Not Be Located, Service Name Resolution Has Been Disabled.")	# services will stay empty and every call to .include? will fail
      end
    end

    client.msfmap.msfmap_core(ip_range_walker) do |scan_results|
      scan_results_length += scan_results.length
      scan_results.each do |host_result|
        output_msg = "MSFMap scan report for #{host_result['host']}\n"
        output_msg << "Host is up.\n"

        if msfmapConfig.opts['scan_type'][0,3] == 'tcp' or msfmapConfig.opts['scan_type'][0,3] == 'udp'
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
            output_msg << port.to_s + "/tcp" + " " * (largest_num_space - port.to_s.length - 3) + "open  "
            if services.include?(port)
              output_msg << services[port] + "\n"
            else
              output_msg << "unknown\n"
            end
          end
        end
        print_line(output_msg)
        if msfmapConfig.out_normal
          msfmapConfig.out_normal.write(output_msg << "\n")	# trailing new line to compensate for print_line
        end
      end
    end
    if client.msfmap.msfmap_get_last_error != 0
      print_error("Scan Failed With Error Code: #{client.msfmap.msfmap_get_last_error}")
    end

    end_time = Time.now
    elapsed_time = (end_time - start_time).round(2)
    closing_msg = "MSFMap done: #{ip_range_walker.length} IP address"
    if ip_range_walker.length > 1
      closing_msg << "es"
    end
    closing_msg << " (#{scan_results_length} host"
    if scan_results_length > 1 or scan_results_length == 0
      closing_msg << "s"
    end
    closing_msg << " up) scanned in #{elapsed_time} seconds"
    print_line(closing_msg)
    print_line("")
    if msfmapConfig.out_normal
      closing_msg << "\n"
      msfmapConfig.out_normal.write(closing_msg)
      msfmapConfig.out_normal.close
    end

    client.msfmap.msfmap_cleanup()
    trap("SIGINT") do
      "DEFAULT"
    end
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
