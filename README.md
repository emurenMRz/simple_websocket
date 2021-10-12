# simple_websocket
WebSocket echo server for the Ruby language. Includes a simple client-side example.

## USAGE

1. Start up the echo server.

> ruby ./main.rb

2. Start up the HTTP server with the appropriate port. In this case, we have specified 8888.

> ruby -run -e httpd ./ui -p 8888

3. Launch a web browser and open a page with the specified port.

> chrome http://127.0.0.1:8888/
