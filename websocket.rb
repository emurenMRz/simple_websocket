require 'base64'
require 'digest/sha1'

class WebSocket
	def initialize(sock, origin: nil, app_url: '/')
		@sock = sock
		@key = nil
		@origin = origin
		@app_url = app_url
		@protocols = []
	end	

	def do_handshake(subprotocols)
		return send_bad_request('invalid subprotocol') if subprotocols.nil? || subprotocols.empty?
		return nil if !parse_header

		for protocol in subprotocols
			if support_subprotocol?(protocol)
				send_shakehand_response(protocol)
				return protocol
			end
		end
		send_bad_request('unsupported protocol ...')
	end

	def resvdata
		opcode = -1
		fin = false
		data = []

		while !fin
			octet = read(1)[0]
			fin	= (octet & 0x80) != 0
			opcode = (octet & 0xf) if opcode == -1
	
			octet = read(1)[0]
			mask = (octet & 0x80) != 0  # if from Browser then true
			if !mask
				close
				return nil
			end

			payload_len = octet & 0x7f
			if payload_len > 125
				len = read([2, 8][payload_len - 126])
				payload_len	= 0
				for l in len
					payload_len <<= 8
					payload_len	+= l
				end
			end
	
			masking_key = read(4)
	
			payload = read(payload_len)
			for i in 0...payload_len
				payload[i] ^= masking_key[i & 0x3]
			end

			data += payload
		end
	
		return opcode, data
	end

	def senddata(opcode, data)
		data = data.unpack('C*') if data.class == String
		header = build_header(opcode, data.length)
		return nil if header.nil?
		return write(header + data)
	end

	def close(status_code = 1002, reason = nil)
		return write([0x88, 0x02, (status_code >> 8) & 0xff, status_code & 0xff]) if reason.nil? || reason.empty?
	
		if status_code != 1000
			reason = "no reason." if reason.nil?
		end
		
		reason = reason.unpack('C*') if reason.class == String
		return senddata(0x8, [(status_code >> 8) & 0xff, status_code & 0xff] + reason)
	end

	def sendping; write([0x89, 0x04] + 'PING'.unpack('C*')); end
	def sendpong(data); senddata(0xa, data); end

	private

	def get_header_value(line, key)
		return nil unless line.start_with?(key)
		return line.split(':')[1].strip!
	end

	def parse_header
		header = @sock.gets.strip!
		m = header.match(/GET (?<path>\/.+?) HTTP\/1\.1$/) unless header.nil?
		return send_bad_request('invalid WebSocket connection ...') if m.nil?
		return send_bad_request("invalid application url: #{m[:path]}") unless m[:path] == @app_url

		loop do
			line = @sock.gets
			break if line.nil?
			break if line.strip!.empty?

			key, value = line.split(':')
			value.strip!
			case key.strip
			when 'Origin'
				return send_bad_request("invalid Origin: #{value}") unless @origin.nil? || value.casecmp(@origin) == 0
			when 'Upgrade'
				return send_bad_request("not WebSocket: #{value}") unless value.casecmp('Websocket') == 0
			when 'Connection'
				find = false
				for token in value.split(',')
					if token.strip.casecmp('Upgrade')
						find = true
						break
					end
				end
				return send_bad_request("failed connection type: #{value}") unless find
			when 'Sec-WebSocket-Version'
				return send_invalid_version_response("lower version: #{value}") if value.to_i < 13
			when 'Sec-WebSocket-Key'
				@key = value
			when 'Sec-WebSocket-Protocol'
				for token in value.split(',')
					@protocols.push(token.strip)
				end
			end
		end
		return true
	end

	def support_subprotocol?(subprotocol)
		for protocol in @protocols
			return true if protocol == subprotocol
		end
		return false
	end

	def send_message(code, reason, message)
		s = "HTTP/1.1 #{code} #{reason}\r\n"
		s << "Content-Type: text/plain; charset=utf-8\r\n"
		s << "Content-Length: #{message.length}\r\n"
		s << "Connection: close\r\n"
		s << "Sec-WebSocket-Version: 13\r\n"
		s << "\r\n"
		s << message
		write(s)
	end

	def send_bad_request(message); send_message(400, 'Bad Request', message); end
	def send_invalid_version_response(message); send_message(426, 'Upgrade Required', message); end

	def send_shakehand_response(protocol)
		sha1 = Digest::SHA1.new
		sha1.update("#{@key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
		enc = Base64.encode64(sha1.digest).strip
		s = "HTTP/1.1 101 Switching Protocols\r\n"
		s << "Upgrade: websocket\r\n"
		s << "Connection: Upgrade\r\n"
		s << "Sec-WebSocket-Accept: #{enc}\r\n"
		s << "Sec-WebSocket-Protocol: #{protocol}\r\n"
		s << "\r\n"
		write(s)
	end

	def build_header(opcode, length, fin = true, rsv1 = false, rsv2 = false, rsv3 = false)
		fin = fin ? 1 : 0
		rsv1 = rsv1 ? 1 : 0
		rsv2 = rsv2 ? 1 : 0
		rsv3 = rsv3 ? 1 : 0

		header = [(fin << 7) | (rsv1 << 6) | (rsv2 << 5) | (rsv3 << 4) | (opcode & 0xf)]
		if length <= 125
			header.push(length & 0x7f)
		elsif length <= 0xffff
			header += [
				126,
				(length >> 8) & 0xff,
				length & 0xff
			]
		else
			return nil if (length >> 63) == 0x1
			header += [
				127,
				(length >> 56) & 0xff,
				(length >> 48) & 0xff,
				(length >> 40) & 0xff,
				(length >> 32) & 0xff,
				(length >> 24) & 0xff,
				(length >> 16) & 0xff,
				(length >> 8) & 0xff,
				length & 0xff
			]
		end

		return header
	end

	def read(length)
		raise "read: nil or eof." if @sock.nil? || @sock.eof?
		dat = @sock.read(length)
		raise "read: Closing?" if dat.nil?
		return dat.unpack('C*')
	end

	def write(data)
		data = data.pack('C*') if data.class == Array
		raise "write: not String." unless data.class == String
		raise "write: nil." if @sock.nil?
		return @sock.write(data)
	end
end