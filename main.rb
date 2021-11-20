require './websocket'
require 'socket'

APP_URL = "/echo/"
PORT = 0x6563

Socket.tcp_server_loop(nil, PORT) do |sock, client_addrinfo|
	pp client_addrinfo
	Thread.new do
		begin
			ws = WebSocket.new(sock, app_url: APP_URL)
			return if ws.do_handshake(['echo']).nil?

			loop do
				r = IO.select([sock])
				for s in r[0]
					if s == sock
						opcode, data = ws.resvdata
						next if data.nil? || data.empty?

						case opcode
						when 0x0  # continuation frame
						when 0x1  # text frame
							ws.close(1011) if ws.senddata(0x1, data).nil?
						when 0x2  # binary frame
							ws.close(1003)
						when 0x3, 0x4, 0x5, 0x6, 0x7  # reserved for further non-control frames
						when 0x8  # connection close
							ws.close(1000, data)
						when 0x9  # ping
							ws.sendpong(data)
						when 0xA  # pong
						when 0xB, 0xC, 0xD, 0xE, 0xF  # reserved for further control frames
						else
							ws.close(1011)
						end
					end
				end
			end
		rescue => e
			puts e.full_message
		ensure
			sock.close
		end
	end
end