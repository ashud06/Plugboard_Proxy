# Plugboard_Proxy
I have developed and implemented a plugboard proxy that adds an extra layer of encryption to connections towards TCP services. Instead of connecting directly to the service, the client will connect to the plugboard proxy that is running on the same server. This proxy will intern relay the traffic to the actual service. The proxy will always decrypt the traffic using a static symmetric key. Thus, if data from any connection towards the protected server is not properly encrypted, it will be dropped before reaching the protected service. Clients who want to access the protected server should proxy their traffic through a local instance of the plugboard proxy. This will encrypt the traffic using the same symmetric key used by the server. Thus, our proposed solution will be acting as both a client-side proxy and as a server-side reverse proxy. 
I have used AES-256 in GCM mode to encrypt and decrypt the data. The AES key will be derived from the secret shared passphrase using PBKDF2 algorithm.
 
To run the program, in the plugboard_proxy folder:

<prompt>$ sudo go run plugboard_proxy.go [-l listenport] -p pwdfile destination port
	
-l : Reverse-proxy mode: listen for inbound connections on listenport and relay them to destination:port
	
-p : Use the ASCII text passphrase contained in pwdfile

destination : reverse-proxy mode: hostname / IP address of the service to relay traffic to client mode: hostname / IP address of the plugboard_proxy-server
	
port : reverse-proxy mode: port of the service to relay traffic to client mode: port of the plugboard_proxy-server
	
EXAMPLES:
	
=> Reverse-Proxy Mode:
	
	go run plugboard_proxy.go -l <listenport> -p <pswd-file> <destination> <port>
  
=> Client Mode:
	
	go run plugboard_proxy.go -p <pswd-file> <destination> <port>
  
SSH EXAMPLE:
  
=> Proxy Server:
	
	sudo ./plugboard_proxy -p password -l 2223 192.168.100.20 22
  
=> Client 1:
  
	ssh -o "ProxyCommand go run plugboard_proxy.go -p password 192.168.100.5 2223" localhost
