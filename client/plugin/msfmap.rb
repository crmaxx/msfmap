require 'rex/socket'

module Msf
class Plugin::MSFMap < Msf::Plugin	
	class MSFMapCommandDispatcher
		include Msf::Ui::Console::CommandDispatcher

		def name
			"MSFMap"
		end

		def commands
			{
				"msfmap"	=> "Scan 'em All.",
			}
		end

		def cmd_msfmap(*args)
			sessionsToUse = get_sessions_from_common_networks
			print_status("Using #{sessionsToUse.length} Meterpreter Sessions To Scan...")
			# see lib/msf/core/auxiliary/scanner.rb lines 78 - 90 for an
			# example on msf-friendly multi threading
		end
		
		def get_sessions_attached_to_network(targetNetwork)
			# This will yeild a list of windows meterpreter sessions that
			# have interfaces directly attached to the target network.
			sessionsToUse = Array.new
			targetNetwork = Rex::Socket.addr_aton(targetNetwork)
			
			framework.sessions.each_sorted do |session_id|
				session = framework.sessions.get(session_id)
				next if session.type != "meterpreter"
				next if not session.platform =~ /win32|win64/
				session.core.use('stdapi') if not session.ext.aliases.include?('stdapi')
				session.core.use('msfmap') if not session.ext.aliases.include?('msfmap')

				session.net.config.each_interface do |interface|
					next if interface.ip == '127.0.0.1'
					sessionsToUse.push(session_id) if targetNetwork == (Rex::Socket.addr_aton(interface.ip) & Rex::Socket.addr_aton(interface.netmask))
				end
			end
			
			return sessionsToUse
		end
		
		def get_sessions_from_common_networks
			# This function checks all interfaces on windows meterpreter sessions
			# It then organizes the data to find which network has the most number
			# of compromised systmes directly attached.  This will return a list of
			# the sessions that are used by the most common network.  Using the systems
			# to scan from should yeild accurate and consistent results.
			networksToSessions = Hash.new
			networksCounter = Hash.new

			framework.sessions.each_sorted do |session_id|
				session = framework.sessions.get(session_id)
				next if session.type != "meterpreter"
				next if not session.platform =~ /win32|win64/
				session.core.use('stdapi') if not session.ext.aliases.include?('stdapi')
				session.core.use('msfmap') if not session.ext.aliases.include?('msfmap')

				session.net.config.each_interface do |interface|
					next if interface.ip == '127.0.0.1'
					network = (Rex::Socket.addr_aton(interface.ip) & Rex::Socket.addr_aton(interface.netmask))
					if not networksCounter.has_key?(network)
						networksCounter[network] = 0
						networksToSessions[network] = Array.new
					end
					networksCounter[network] += 1
					networksToSessions[network].push(session_id)
				end
			end
			
			highestCount = 0
			highestCountNetwork = nil
			networksCounter.each_pair do |key, value|
				if value > highestCount
					highestCountNetwork = key
				end
			end
			if not highestCountNetwork
				print_error("Found No Networks To Scan From.")
				return
			end
			return networksToSessions[highestCountNetwork]
		end
	end
	
	def initialize(framework, opts)
		super
		add_console_dispatcher(MSFMapCommandDispatcher)
	end

	def cleanup
		remove_console_dispatcher('MSFMap')
	end
	
	def name
		"msfmap"
	end
	
	def desc
		"MSFMap - Distributed Port Scanning"
	end

protected
end
end
