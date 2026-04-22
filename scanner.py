import socket
import sys
import threading

# 1. Configuration & Argument Check
if len(sys.argv) != 3:
    print("Usage: python scanner.py <ip_or_domain>")
    sys.exit()

target = sys.argv[1]
start_port, end_port = sys.argv[2].split('-')
ports = range(int(start_port), int(end_port) + 1)

# Limits us to 50 active workers to avoid crashing your connection
thread_limiter = threading.BoundedSemaphore(value=50)

print(f"--- Starting Parallel Scan on {target} ---")

# 2. Define the worker function
def scan_port(port):
    thread_limiter.acquire()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1) # Connection timeout
        result = s.connect_ex((target, port))
        
        if result == 0:
            
            # 1. Translate the port number to a service name
            try:
                service_name = socket.getservbyport(port, "tcp")
            except:
                service_name = "unknown"
            banner_text = "No banner found"
  
            # ... [The Passive & Active Banner Grabbing Code Stays Here] ...
            
           
            
            # --- Passive Approach ---
            try:
                s.settimeout(2) # Give the server 2 seconds to speak first
                banner = s.recv(1024)
                if banner:
                    banner_text = banner.decode(errors='ignore').strip()
            except socket.timeout:
                # --- Active Approach (Fallback) ---
                try:
                    # Target common web ports for the active probe
                    if port in [80, 8080, 443]:
                        message = f"HEAD / HTTP/1.1\r\nHost: {target}\r\n\r\n"
                        s.sendall(message.encode())
                        banner = s.recv(1024)
                        # Look for the 'Server' header
                        for line in banner.decode(errors='ignore').splitlines():
                            if "Server:" in line:
                                banner_text = line.replace("Server:", "").strip()
                                break
                except:
                    pass
            
            
                        # Create the formatted string
            output_string = f"[+] Port {port:<5} ({service_name}) | {banner_text}\n"
            
            # Print it to the terminal (stripping the newline so it looks normal)
            print(output_string.strip()) 
            
            # Save it to our log file
            with open("scan_results.txt", "a") as file:
                file.write(output_string)
           

            s.close()
    finally:
        thread_limiter.release()

# 3. Create and start threads
try:
    threads = []
    for port in ports:
        t = threading.Thread(target=scan_port, args=(port,))
        threads.append(t)
        t.start()

# 4. Wait for all workers to finish
    for t in threads:
        t.join()

except KeyboardInterrupt:
    print("\n[!] Scan stopped by User.Exiting Gracefully....")
    sys.exit()
print("--- Scan Complete ---")
