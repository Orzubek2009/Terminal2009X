let messages = "import socket
import threading
import random
import ipaddress
import time

# Function to generate random IP addresses
def random_ip():
    return {}.format(..join(map(str, (random.randint(1, 255) for _ in range(4)))))

# Function to scan ports for a given IP
def port_scan(ip):
    print(fScanning ports on {ip}...)
    open_ports = []
    for port in range(1, 1025):  # Scans common ports
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    print(fOpen ports on {ip}: {open_ports})
    return open_ports

# Fake function to brute force login
def brute_force_login(ip, port):
    print(fAttempting brute force on {ip}:{port})
    usernames = [admin, user, root]
    passwords = [1234, password, admin]
    
    for user in usernames:
        for password in passwords:
            print(fTrying {user}:{password} on {ip}:{port})
            if random.choice([True, False]):  # Simulated success/failure
                print(f[SUCCESS] Credentials found: {user}:{password})
                return True
            time.sleep(0.1)
    print([FAILURE] Brute force failed.)
    return False

# Function to simulate DoS attack
def simulate_dos(ip, port):
    print(f[INFO] Initiating DoS attack on {ip}:{port})
    for _ in range(100):
        print(fSending packets to {ip}:{port})
        time.sleep(0.1)
    print(f[INFO] DoS attack simulation complete on {ip}:{port})

# Create fake packet for analysis
def create_fake_packet(ip):
    print(f[INFO] Generating fake packet to {ip})
    return {
        source_ip: random_ip(),
        destination_ip: ip,
        payload: random.choice([GET /, PING, EXPLOIT]),
        timestamp: time.time()
    }

# Analyze packets
def packet_analyzer(packet):
    print(f[INFO] Analyzing packet: {packet})
    if EXPLOIT in packet[payload]:
        print([WARNING] Malicious packet detected!)
    else:
        print([INFO] Packet is clean.)

# Simulate a firewall
def firewall(ip, block_list):
    if ip in block_list:
        print(f[BLOCKED] Traffic from {ip} is blocked by the firewall.)
        return True
    print(f[ALLOWED] Traffic from {ip} is allowed.)
    return False

# Fake exploit function
def simulate_exploit(ip, port):
    print(f[INFO] Simulating exploit on {ip}:{port})
    if random.choice([True, False]):
        print([SUCCESS] Exploit successful! Gained access to system.)
        return True
    else:
        print([FAILURE] Exploit failed.)
        return False

# Simulated botnet control
class Botnet:
    def __init__(self):
        self.bots = []

    def add_bot(self, ip):
        print(f[INFO] Adding bot: {ip})
        self.bots.append(ip)

    def command_bots(self, command):
        print(f[INFO] Commanding {len(self.bots)} bots to execute: {command})
        for bot in self.bots:
            print(f[BOT] {bot} executing {command})

# Threading example for parallel scanning
def thread_scan(ip_list):
    def scan_task(ip):
        ports = port_scan(ip)
        print(f[THREAD] Scan complete for {ip}: {ports})

    threads = []
    for ip in ip_list:
        t = threading.Thread(target=scan_task, args=(ip,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

# Main simulation
if __name__ == __main__:
    banner()
    
    block_list = [random_ip() for _ in range(5)]
    print(f[FIREWALL] Blocklist: {block_list})

    # Simulate network activity
    for _ in range(5):
        ip = random_ip()
        if not firewall(ip, block_list):
            ports = port_scan(ip)
            if ports:
                brute_force_login(ip, random.choice(ports))

    # Packet analysis
    for _ in range(10):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Simulate botnet control
    botnet = Botnet()
    for _ in range(10):
        botnet.add_bot(random_ip())
    botnet.command_bots(ping google.com)

    # Multithreading example
    ip_list = [random_ip() for _ in range(10)]
    thread_scan(ip_list)

    print([SIMULATION COMPLETE])
Pull down action image ghcr.io/actions/jekyll-build-pages:v1.0.13
  /usr/bin/docker pull ghcr.io/actions/jekyll-build-pages:v1.0.13
  v1.0.13: Pulling from actions/jekyll-build-pages
  efc2b5ad9eec: Pulling fs layer
  165b60d1bb48: Pulling fs layer
  2a328af1ca3a: Pulling fs layer
  32b58fa44788: Pulling fs layer
  590ab93c22d2: Pulling fs layer
  26ea96c4c14c: Pulling fs layer
  bd7e451dfea1: Pulling fs layer
  c209e9dadc51: Pulling fs layer
  a4925b5c711a: Pulling fs layer
  cd9459784e3c: Pulling fs layer
  32b58fa44788: Waiting
  590ab93c22d2: Waiting
  26ea96c4c14c: Waiting
  bd7e451dfea1: Waiting
  c209e9dadc51: Waiting
  a4925b5c711a: Waiting
  cd9459784e3c: Waiting
  2a328af1ca3a: Download complete
  165b60d1bb48: Verifying Checksum
  165b60d1bb48: Download complete
  590ab93c22d2: Download complete
  32b58fa44788: Download complete
  efc2b5ad9eec: Verifying Checksum
  efc2b5ad9eec: Download complete
  bd7e451dfea1: Verifying Checksum
  bd7e451dfea1: Download complete
  a4925b5c711a: Verifying Checksum
  a4925b5c711a: Download complete
  cd9459784e3c: Verifying Checksum
  cd9459784e3c: Download complete
  c209e9dadc51: Verifying Checksum
  c209e9dadc51: Download complete
  26ea96c4c14c: Verifying Checksum
  26ea96c4c14c: Download complete
  efc2b5ad9eec: Pull complete
  165b60d1bb48: Pull complete
  2a328af1ca3a: Pull complete
  32b58fa44788: Pull complete
  590ab93c22d2: Pull complete
  26ea96c4c14c: Pull complete
  bd7e451dfea1: Pull complete
  c209e9dadc51: Pull complete
  a4925b5c711a: Pull complete
  cd9459784e3c: Pull complete
  Digest: sha256:6791ebfd912185ed59bfb5fb102664fa872496b79f87ff8b9cfba292a7345041
  Status: Downloaded newer image for ghcr.io/actions/jekyll-build-pages:v1.0.13
  ghcr.io/actions/jekyll-build-pages:v1.0.13
  
1s
Run actions/checkout@v4
Syncing repository: Orzubek2009/Terminal2009X
Getting Git version info
Temporarily overriding HOME=/home/runner/work/_temp/75a4ea6a-041a-4bad-851c-f6d6a508a222 before making global git config changes
Adding repository directory to the temporary git global config as a safe directory
/usr/bin/git config --global --add safe.directory /home/runner/work/Terminal2009X/Terminal2009X
Deleting the contents of /home/runner/work/Terminal2009X/Terminal2009X
Initializing the repository
Disabling automatic garbage collection
Setting up auth
  /usr/bin/git config --local --name-only --get-regexp core\.sshCommand
  /usr/bin/git submodule foreach --recursive sh -c git config --local --name-only --get-regexp core\.sshCommand && git config --local --unset-all core.sshCommand || :
  /usr/bin/git config --local --name-only --get-regexp http\.https\:\/\/github\.com\/\.extraheader
  /usr/bin/git submodule foreach --recursive sh -c git config --local --name-only --get-regexp http\.https\:\/\/github\.com\/\.extraheader && git config --local --unset-all http.https://github.com/.extraheader || :
  /usr/bin/git config --local http.https://github.com/.extraheader AUTHORIZATION: basic ***
Fetching the repository
Determining the checkout info
    # Simulate Denial of Service (DoS) attack
    for _ in range(3):
        ip = random_ip()
        port = random.randint(1, 1025)
        simulate_dos(ip, port)

    # Simulate exploit attempts
    for _ in range(3):
        ip = random_ip()
        port = random.randint(1, 1025)
        simulate_exploit(ip, port)

    # Simulate creating and analyzing packets
    for _ in range(10):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Botnet controlling multiple bots
    botnet.command_bots(download malicious file)

    # Further port scanning and brute-forcing on randomly generated IPs
    for _ in range(5):
        ip = random_ip()
        ports = port_scan(ip)
        if ports:
            brute_force_login(ip, random.choice(ports))

    # Creating and analyzing fake packets in a loop
    for _ in range(5):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Simulate network traffic management
    for _ in range(5):
        ip = random_ip()
        if not firewall(ip, block_list):
            ports = port_scan(ip)
            if ports:
                brute_force_login(ip, random.choice(ports))

    # Randomly trigger firewall block/unblock actions
    for _ in range(3):
        ip = random_ip()
        if random.choice([True, False]):
            block_list.append(ip)
            print(f[INFO] {ip} added to blocklist.)
        else:
            block_list.remove(ip)
            print(f[INFO] {ip} removed from blocklist.)
    
    # Simulate command execution on bots
    botnet.command_bots(execute system command)

    # Adding more bots to the botnet
    for _ in range(5):
        botnet.add_bot(random_ip())

    # Simulating DoS attacks on various ports and IPs
    for _ in range(3):
        ip = random_ip()
        port = random.randint(1, 1025)
        simulate_dos(ip, port)

    # Analyzing network traffic with a fake packet generator
    for _ in range(5):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Further command execution via botnet
    botnet.command_bots(execute malicious payload)

    # Simulate random IPs and scan ports
    for _ in range(5):
        ip = random_ip()
        ports = port_scan(ip)
        if ports:
            brute_force_login(ip, random.choice(ports))

    # Final simulation log
    print([INFO] Simulation complete. All tasks executed.)
/usr/bin/git sparse-checkout disable
/usr/bin/git config --local --unset-all extensions.worktreeConfig
Checking out the ref
Setting up auth for fetching submodules
  /usr/bin/git config --global http.https://github.com/.extraheader AUTHORIZATION: basic ***
  /usr/bin/git config --global --unset-all url.https://github.com/.insteadOf
  /usr/bin/git config --global --add url.https://github.com/.insteadOf git@github.com:
  /usr/bin/git config --global --add url.https://github.com/.insteadOf org-196283092@github.com:
Fetching submodules
Persisting credentials for submodules
/usr/bin/git log -1 --format=%H
75e1b6bd1877a76d06b6eaa2a01b893c67e893e6
2s
Run actions/jekyll-build-pages@v1
/usr/bin/docker run --name ghcrioactionsjekyllbuildpagesv1013_d517bf --label a1d307 --workdir /github/workspace --rm -e INPUT_SOURCE -e INPUT_DESTINATION -e INPUT_FUTURE -e INPUT_BUILD_REVISION -e INPUT_VERBOSE -e INPUT_TOKEN -e HOME -e GITHUB_JOB -e GITHUB_REF -e GITHUB_SHA -e GITHUB_REPOSITORY -e GITHUB_REPOSITORY_OWNER -e GITHUB_REPOSITORY_OWNER_ID -e GITHUB_RUN_ID -e GITHUB_RUN_NUMBER -e GITHUB_RETENTION_DAYS -e GITHUB_RUN_ATTEMPT -e GITHUB_ACTOR_ID -e GITHUB_ACTOR -e GITHUB_WORKFLOW -e GITHUB_HEAD_REF -e GITHUB_BASE_REF -e GITHUB_EVENT_NAME -e GITHUB_SERVER_URL -e GITHUB_API_URL -e GITHUB_GRAPHQL_URL -e GITHUB_REF_NAME -e GITHUB_REF_PROTECTED -e GITHUB_REF_TYPE -e GITHUB_WORKFLOW_REF -e GITHUB_WORKFLOW_SHA -e GITHUB_REPOSITORY_ID -e GITHUB_TRIGGERING_ACTOR -e GITHUB_WORKSPACE -e GITHUB_ACTION -e GITHUB_EVENT_PATH -e GITHUB_ACTION_REPOSITORY -e GITHUB_ACTION_REF -e GITHUB_PATH -e GITHUB_ENV -e GITHUB_STEP_SUMMARY 
Configuration file: none
To use retry middleware with Faraday v2.0+, install `faraday-retry` gem
  Logging at level: debug
      GitHub Pages: github-pages v232
      GitHub Pages: jekyll v3.10.0
             Theme: jekyll-theme-primer
      Theme source: /usr/local/bundle/gems/jekyll-theme-primer-0.6.0
         Requiring: jekyll-github-metadata
         Requiring: jekyll-seo-tag
         Requiring: jekyll-coffeescript
         Requiring: jekyll-commonmark-ghpages
         Requiring: jekyll-gist
         Requiring: jekyll-github-metadata
         Requiring: jekyll-paginate
         Requiring: jekyll-relative-links
         Requiring: jekyll-optional-front-matter
         Requiring: jekyll-readme-index
         Requiring: jekyll-default-layout
         Requiring: jekyll-titles-from-headings
   GitHub Metadata: Initializing...
            Source: /github/workspace/.
       Destination: /github/workspace/./_site
 Incremental build: disabled. Enable with --incremental
      Generating... 
        Generating: JekyllOptionalFrontMatter::Generator finished in 0.000114744 seconds.
        Generating: JekyllReadmeIndex::Generator finished in 0.001411135 seconds.
        Generating: Jekyll::Paginate::Pagination finished in 3.978e-06 seconds.
        Generating: JekyllRelativeLinks::Generator finished in 2.2402e-05 seconds.
        Generating: JekyllDefaultLayout::Generator finished in 6.5923e-05 seconds.
        Generating: JekyllTitlesFromHeadings::Generator finished in 2.2822e-05 seconds.
         Rendering: assets/css/style.scss
  Pre-Render Hooks: assets/css/style.scss
  Rendering Markup: assets/css/style.scss
         Rendering: README.md
  Pre-Render Hooks: README.md
  Rendering Markup: README.md
         Requiring: kramdown-parser-gfm
  Rendering Layout: README.md
     Layout source: theme
   GitHub Metadata: Generating for Orzubek2009/Terminal2009X
   GitHub Metadata: Calling @client.repository(Orzubek2009/Terminal2009X, {:accept=>application/vnd.github.drax-preview+json})
   GitHub Metadata: Calling @client.pages(Orzubek2009/Terminal2009X, {})
           Writing: /github/workspace/_site/assets/css/style.css
           Writing: /github/workspace/_site/index.html
                    done in 1.305 seconds.
 Auto-regeneration: disabled. Use --watch to enable.
1s
Run actions/upload-pages-artifact@v3
  
Run echo ::group::Archive artifact
Archive artifact
Run actions/upload-artifact@v4
  
With the provided path, there will be 1 file uploaded
Artifact name is valid!
Root directory input is valid!
Beginning upload of artifact content to blob storage
Uploaded bytes 29339
Finished uploading artifact content to blob storage!
SHA256 hash of uploaded artifact zip is 5ed52ad36c2876cc529adce22109ab5914070afb05df4660f03e5b186ec6028e
Finalizing artifact upload
Artifact github-pages.zip successfully finalized. Artifact ID 2501339476
Artifact github-pages has been successfully uploaded! Final size is 29339 bytes. Artifact ID is 2501339476
Artifact download URL: https://github.com/Orzubek2009/Terminal2009X/actions/runs/13022673141/artifacts/2501339476
0s
Post job cleanup.
/usr/bin/git version
git version 2.48.1
Temporarily overriding HOME=/home/runner/work/_temp/050bafad-4569-4520-b866-ef6809829e4b before making global git config changes
Adding repository directory to the temporary git global config as a safe directory
/usr/bin/git config --global --add safe.directory /home/runner/work/Terminal2009X/Terminal2009X
/usr/bin/git config --local --name-only --get-regexp core\.sshCommand
/usr/bin/git submodule foreach --recursive sh -c git config --local --name-only --get-regexp core\.sshCommand && git config --local --unset-all core.sshCommand || :
/usr/bin/git config --local --name-only --get-regexp http\.https\:\/\/github\.com\/\.extraheader
http.https://github.com/.extraheader
/usr/bin/git config --local --unset-all http.https://github.com/.extraheader
/usr/bin/git submodule foreach --recursive sh -c git config --local --name-only --get-regexp http\.https\:\/\/github\.com\/\.extraheader && git config --local --unset-all http.https://github.com/.extraheader || :
    # Simulate additional network scanning on random IPs
    for _ in range(7):
        ip = random_ip()
        print(f[INFO] Starting network scan for {ip})
        ports = port_scan(ip)
        if ports:
            brute_force_login(ip, random.choice(ports))

    # Simulate sending different types of fake packets
    for _ in range(10):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Randomly simulate attacks and exploits
    for _ in range(5):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Triggering simulated DoS attack on {ip}:{port})
        simulate_dos(ip, port)

    # Simulate brute force attacks on multiple servers
    for _ in range(3):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Attempting brute force on {ip}:{port})
        brute_force_login(ip, port)

    # Generate fake packets for malicious payload detection
    for _ in range(7):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Simulate exploit attempts on multiple ports
    for _ in range(4):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Simulating exploit attempt on {ip}:{port})
        simulate_exploit(ip, port)

    # Continuing botnet operations by commanding bots
    botnet.command_bots(execute denial of service attack)

    # Simulate botnet adding new bots and executing commands
    for _ in range(5):
        ip = random_ip()
        botnet.add_bot(ip)
    botnet.command_bots(initiate file exfiltration)

    # Simulate network traffic with firewall checks and brute-forcing
    for _ in range(5):
        ip = random_ip()
        if not firewall(ip, block_list):
            ports = port_scan(ip)
            if ports:
                brute_force_login(ip, random.choice(ports))

    # Additional packet analysis
    for _ in range(6):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Simulate adding and removing IPs from the firewall blocklist
    for _ in range(4):
        ip = random_ip()
        if random.choice([True, False]):
            block_list.append(ip)
            print(f[INFO] {ip} added to blocklist.)
        else:
            block_list.remove(ip)
            print(f[INFO] {ip} removed from blocklist.)

    # Simulating exploits, attacks, and botnet commands in parallel
    for _ in range(5):
        ip = random_ip()
        port = random.randint(1, 1025)
        simulate_exploit(ip, port)
        simulate_dos(ip, port)
        botnet.command_bots(simulate packet sniffing)

    # Final packet generation and analysis loop
    for _ in range(5):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # End of simulation report
    print([SIMULATION COMPLETE] All network security tools and exploits have been executed.)
    # Simulating DoS attacks on multiple targets
    for _ in range(5):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Simulating DoS attack on {ip}:{port})
        simulate_dos(ip, port)

    # Randomly trigger brute force login attempts across different ports
    for _ in range(6):
        ip = random_ip()
        port = random.randint(1, 1025)
        brute_force_login(ip, port)

    # Botnet managing distributed attacks
    for _ in range(3):
        botnet.command_bots(launch DoS attack on target server)

    # Simulate adding fake packets to test network defense
    for _ in range(8):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Run random exploits across the simulated network
    for _ in range(4):
        ip = random_ip()
        port = random.randint(1, 1025)
        simulate_exploit(ip, port)

    # Botnet executes commands on compromised systems
    botnet.command_bots(exfiltrate sensitive data)

    # More simulated firewall actions with random IPs
    for _ in range(5):
        ip = random_ip()
        if not firewall(ip, block_list):
            print(f[INFO] {ip} passed firewall check.)
        else:
            print(f[INFO] {ip} blocked by firewall.)

    # Continual packet creation and analysis
    for _ in range(6):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Simulate random botnet actions with commands
    botnet.command_bots(deploy keylogger on target machine)

    # Continue firewall management and security checks
    for _ in range(5):
        ip = random_ip()
        if not firewall(ip, block_list):
            ports = port_scan(ip)
            if ports:
                brute_force_login(ip, random.choice(ports))

    # Triggering packet generation and exploitation on different IPs
    for _ in range(6):
        ip = random_ip()
        port = random.randint(1, 1025)
        simulate_exploit(ip, port)
        packet = create_fake_packet(ip)
        packet_analyzer(packet)

    # Simulating system-wide attack control via botnet
    botnet.command_bots(download and execute malicious payload)

    # Re-run firewall and port scanning on random IPs
    for _ in range(6):
        ip = random_ip()
        ports = port_scan(ip)
        if ports:
            brute_force_login(ip, random.choice(ports))

    # Concluding botnet operations with final commands
    botnet.command_bots(clean up and erase traces)

    # Simulate a closing network scan before exiting
    print([INFO] Final network scan before shutdown.)
    for _ in range(5):
        ip = random_ip()
        ports = port_scan(ip)
        if ports:
            brute_force_login(ip, random.choice(ports))

    # Packet analysis concluding phase
    for _ in range(4):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Finalize botnet actions before exit
    botnet.command_bots(shutdown all compromised systems)

    # End of simulation report
    print([SIMULATION COMPLETE] All tasks executed. Simulation finished.)
    # Final batch of DoS attacks on different servers
    for _ in range(5):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Executing DoS attack on {ip}:{port})
        simulate_dos(ip, port)

    # Run final brute force attempts across random ports
    for _ in range(6):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Brute force attempt on {ip}:{port})
        brute_force_login(ip, port)

    # Additional botnet command execution in parallel
    botnet.command_bots(initiate command and control phase)

    # More packet generation and analysis
    for _ in range(5):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # Simulate network exploit attempts on target systems
    for _ in range(4):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Simulating network exploit on {ip}:{port})
        simulate_exploit(ip, port)

    # Commanding botnet for final data exfiltration
    botnet.command_bots(perform data exfiltration to remote server)

    # Firewall checks for multiple random IPs
    for _ in range(7):
        ip = random_ip()
        if not firewall(ip, block_list):
            print(f[INFO] IP {ip} passed the firewall check.)
        else:
            print(f[INFO] IP {ip} blocked by the firewall.)

    # Execute final packet sniffing phase with botnet
    botnet.command_bots(execute packet sniffing on target network)

    # Perform last series of exploits across different ports
    for _ in range(6):
        ip = random_ip()
        port = random.randint(1, 1025)
        print(f[INFO] Executing final exploit attempt on {ip}:{port})
        simulate_exploit(ip, port)

    # Final round of brute force login attempts
    for _ in range(5):
        ip = random_ip()
        port = random.randint(1, 1025)
        brute_force_login(ip, port)

    # Run the last set of simulated DoS attacks across different targets
    for _ in range(4):
        ip = random_ip()
        port = random.randint(1, 1025)
        simulate_dos(ip, port)

    # Concluding the botnet operations before ending simulation
    botnet.command_bots(finalize botnet operations and clear logs)

    # Perform a final network scan before concluding
    print([INFO] Performing final network scan and clean up.)
    for _ in range(5):
        ip = random_ip()
        ports = port_scan(ip)
        if ports:
            brute_force_login(ip, random.choice(ports))

    # Perform a last set of packet analysis and check for malicious content
    for _ in range(6):
        packet = create_fake_packet(random_ip())
        packet_analyzer(packet)

    # End the simulation with a final message
    print([INFO] Simulation completed. All operations have been executed successfully.)
    print([INFO] Closing the security tool.)
Downloading Files..


Downloading Files 0% []
Downloading Files 1% []
Downloading Files 2% []
Downloading Files 3% []
Downloading Files 4% [#]
Downloading Files 5% [#]
Downloading Files 6% [#]
Downloading Files 7% [#]
Downloading Files 8% [##]
Downloading Files 9% [##]
Downloading Files 10% [##]
Downloading Files 11% [##]
Downloading Files 12% [###]
Downloading Files 13% [###]
Downloading Files 14% [###]
Downloading Files 15% [###]
Downloading Files 16% [####]
Downloading Files 17% [####]
Downloading Files 18% [####]
Downloading Files 19% [####]
Downloading Files 20% [#####]
Downloading Files 21% [#####]
Downloading Files 22% [#####]
Downloading Files 23% [#####]
Downloading Files 24% [######]
Downloading Files 25% [######]
Downloading Files 26% [######]
Downloading Files 27% [######]
Downloading Files 28% [#######]
Downloading Files 29% [#######]
Downloading Files 30% [#######]
Downloading Files 31% [#######]
Downloading Files 32% [########]
Downloading Files 33% [########]
Downloading Files 34% [########]
Downloading Files 35% [########]
Downloading Files 36% [#########]
Downloading Files 37% [#########]
Downloading Files 38% [#########]
Downloading Files 39% [#########]
Downloading Files 40% [##########]
Downloading Files 41% [##########]
Downloading Files 42% [##########]
Downloading Files 43% [##########]
Downloading Files 44% [###########]
Downloading Files 45% [###########]
Downloading Files 46% [###########]
Downloading Files 47% [###########]
Downloading Files 48% [############]
Downloading Files 49% [############]
Downloading Files 50% [############]
Downloading Files 51% [############]
Downloading Files 52% [#############]
Downloading Files 53% [#############]
Downloading Files 54% [#############]
Downloading Files 55% [#############]
Downloading Files 56% [##############]
Downloading Files 57% [##############]
Downloading Files 58% [##############]
Downloading Files 59% [##############]
Downloading Files 60% [###############]
Downloading Files 61% [###############]
Downloading Files 62% [###############]
Downloading Files 63% [###############]
Downloading Files 64% [################]
Downloading Files 65% [################]
Downloading Files 66% [################]
Downloading Files 67% [################]
Downloading Files 68% [#################]
Downloading Files 69% [#################]
Downloading Files 70% [#################]
Downloading Files 71% [#################]
Downloading Files 72% [##################]
Downloading Files 73% [##################]
Downloading Files 74% [##################]
Downloading Files 75% [##################]
Downloading Files 76% [###################]
Downloading Files 77% [###################]
Downloading Files 78% [###################]
Downloading Files 79% [###################]
Downloading Files 80% [####################]
Downloading Files 81% [####################]
Downloading Files 82% [####################]
Downloading Files 83% [####################]
Downloading Files 84% [#####################]
Downloading Files 85% [#####################]
Downloading Files 86% [#####################]
Downloading Files 87% [#####################]
Downloading Files 88% [######################]
Downloading Files 89% [######################]
Downloading Files 90% [######################]
Downloading Files 91% [######################]
Downloading Files 92% [#######################]
Downloading Files 93% [#######################]
Downloading Files 94% [#######################]
Downloading Files 95% [#######################]
Downloading Files 96% [########################]
Downloading Files 97% [########################]
Downloading Files 98% [########################]
Downloading Files 99% [########################]
Downloading Files 100% [#########################]

Download Success 100%

Downloading Configuration files..


Downloading Configuration files 0% []
Downloading Configuration files 1% []
Downloading Configuration files 2% []
Downloading Configuration files 3% []
Downloading Configuration files 4% [#]
Downloading Configuration files 5% [#]
Downloading Configuration files 6% [#]
Downloading Configuration files 7% [#]
Downloading Configuration files 8% [##]
Downloading Configuration files 9% [##]
Downloading Configuration files 10% [##]
Downloading Configuration files 11% [##]
Downloading Configuration files 12% [###]
Downloading Configuration files 13% [###]
Downloading Configuration files 14% [###]
Downloading Configuration files 15% [###]
Downloading Configuration files 16% [####]
Downloading Configuration files 17% [####]
Downloading Configuration files 18% [####]
Downloading Configuration files 19% [####]
Downloading Configuration files 20% [#####]
Downloading Configuration files 21% [#####]
Downloading Configuration files 22% [#####]
Downloading Configuration files 23% [#####]
Downloading Configuration files 24% [######]
Downloading Configuration files 25% [######]
Downloading Configuration files 26% [######]
Downloading Configuration files 27% [######]
Downloading Configuration files 28% [#######]
Downloading Configuration files 29% [#######]
Downloading Configuration files 30% [#######]
Downloading Configuration files 31% [#######]
Downloading Configuration files 32% [########]
Downloading Configuration files 33% [########]
Downloading Configuration files 34% [########]
Downloading Configuration files 35% [########]
Downloading Configuration files 36% [#########]
Downloading Configuration files 37% [#########]
Downloading Configuration files 38% [#########]
Downloading Configuration files 39% [#########]
Downloading Configuration files 40% [##########]
Downloading Configuration files 41% [##########]
Downloading Configuration files 42% [##########]
Downloading Configuration files 43% [##########]
Downloading Configuration files 44% [###########]
Downloading Configuration files 45% [###########]
Downloading Configuration files 46% [###########]
Downloading Configuration files 47% [###########]
Downloading Configuration files 48% [############]
Downloading Configuration files 49% [############]
Downloading Configuration files 50% [############]
Downloading Configuration files 51% [############]
Downloading Configuration files 52% [#############]
Downloading Configuration files 53% [#############]
Downloading Configuration files 54% [#############]
Downloading Configuration files 55% [#############]
Downloading Configuration files 56% [##############]
Downloading Configuration files 57% [##############]
Downloading Configuration files 58% [##############]
Downloading Configuration files 59% [##############]
Downloading Configuration files 60% [###############]
Downloading Configuration files 61% [###############]
Downloading Configuration files 62% [###############]
Downloading Configuration files 63% [###############]
Downloading Configuration files 64% [################]
Downloading Configuration files 65% [################]
Downloading Configuration files 66% [################]
Downloading Configuration files 67% [################]
Downloading Configuration files 68% [#################]
Downloading Configuration files 69% [#################]
Downloading Configuration files 70% [#################]
Downloading Configuration files 71% [#################]
Downloading Configuration files 72% [##################]
Downloading Configuration files 73% [##################]
Downloading Configuration files 74% [##################]
Downloading Configuration files 75% [##################]
Downloading Configuration files 76% [###################]
Downloading Configuration files 77% [###################]
Downloading Configuration files 78% [###################]
Downloading Configuration files 79% [###################]
Downloading Configuration files 80% [####################]
Downloading Configuration files 81% [####################]
Downloading Configuration files 82% [####################]
Downloading Configuration files 83% [####################]
Downloading Configuration files 84% [#####################]
Downloading Configuration files 85% [#####################]
Downloading Configuration files 86% [#####################]
Downloading Configuration files 87% [#####################]
Downloading Configuration files 88% [######################]
Downloading Configuration files 89% [######################]
Downloading Configuration files 90% [######################]
Downloading Configuration files 91% [######################]
Downloading Configuration files 92% [#######################]
Downloading Configuration files 93% [#######################]
Downloading Configuration files 94% [#######################]
Downloading Configuration files 95% [#######################]
Downloading Configuration files 96% [########################]
Downloading Configuration files 97% [########################]
Downloading Configuration files 98% [########################]
Downloading Configuration files 99% [########################]
Downloading Configuration files 100% [#########################]

Downloading Decoding packets


Decoding encrypted packets 0% []
Decoding encrypted packets 1% []
Decoding encrypted packets 2% []
Decoding encrypted packets 3% []
Decoding encrypted packets 4% [#]
Decoding encrypted packets 5% [#]
Decoding encrypted packets 6% [#]
Decoding encrypted packets 7% [#]
Decoding encrypted packets 8% [##]
Decoding encrypted packets 9% [##]
Decoding encrypted packets 10% [##]
Decoding encrypted packets 11% [##]
Decoding encrypted packets 12% [###]
Decoding encrypted packets 13% [###]
Decoding encrypted packets 14% [###]
Decoding encrypted packets 15% [###]
Decoding encrypted packets 16% [####]
Decoding encrypted packets 17% [####]
Decoding encrypted packets 18% [####]
Decoding encrypted packets 19% [####]
Decoding encrypted packets 20% [#####]
Decoding encrypted packets 21% [#####]
Decoding encrypted packets 22% [#####]
Decoding encrypted packets 23% [#####]
Decoding encrypted packets 24% [######]
Decoding encrypted packets 25% [######]
Decoding encrypted packets 26% [######]
Decoding encrypted packets 27% [######]
Decoding encrypted packets 28% [#######]
Decoding encrypted packets 29% [#######]
Decoding encrypted packets 30% [#######]
Decoding encrypted packets 31% [#######]
Decoding encrypted packets 32% [########]
Decoding encrypted packets 33% [########]
Decoding encrypted packets 34% [########]
Decoding encrypted packets 35% [########]
Decoding encrypted packets 36% [#########]
Decoding encrypted packets 37% [#########]
Decoding encrypted packets 38% [#########]
Decoding encrypted packets 39% [#########]
Decoding encrypted packets 40% [##########]
Decoding encrypted packets 41% [##########]
Decoding encrypted packets 42% [##########]
Decoding encrypted packets 43% [##########]
Decoding encrypted packets 44% [###########]
Decoding encrypted packets 45% [###########]
Decoding encrypted packets 46% [###########]
Decoding encrypted packets 47% [###########]
Decoding encrypted packets 48% [############]
Decoding encrypted packets 49% [############]
Decoding encrypted packets 50% [############]
Decoding encrypted packets 51% [############]
Decoding encrypted packets 52% [#############]
Decoding encrypted packets 53% [#############]
Decoding encrypted packets 54% [#############]
Decoding encrypted packets 55% [#############]
Decoding encrypted packets 56% [##############]
Decoding encrypted packets 57% [##############]
Decoding encrypted packets 58% [##############]
Decoding encrypted packets 59% [##############]
Decoding encrypted packets 60% [###############]
Decoding encrypted packets 61% [###############]
Decoding encrypted packets 62% [###############]
Decoding encrypted packets 63% [###############]
Decoding encrypted packets 64% [################]
Decoding encrypted packets 65% [################]
Decoding encrypted packets 66% [################]
Decoding encrypted packets 67% [################]
Decoding encrypted packets 68% [#################]
Decoding encrypted packets 69% [#################]
Decoding encrypted packets 70% [#################]
Decoding encrypted packets 71% [#################]
Decoding encrypted packets 72% [##################]
Decoding encrypted packets 73% [##################]
Decoding encrypted packets 74% [##################]
Decoding encrypted packets 75% [##################]
Decoding encrypted packets 76% [###################]
Decoding encrypted packets 77% [###################]
Decoding encrypted packets 78% [###################]
Decoding encrypted packets 79% [###################]
Decoding encrypted packets 80% [####################]
Decoding encrypted packets 81% [####################]
Decoding encrypted packets 82% [####################]
Decoding encrypted packets 83% [####################]
Decoding encrypted packets 84% [#####################]
Decoding encrypted packets 85% [#####################]
Decoding encrypted packets 86% [#####################]
Decoding encrypted packets 87% [#####################]
Decoding encrypted packets 88% [######################]
Decoding encrypted packets 89% [######################]
Decoding encrypted packets 90% [######################]
Decoding encrypted packets 91% [######################]
Decoding encrypted packets 92% [#######################]
Decoding encrypted packets 93% [#######################]
Decoding encrypted packets 94% [#######################]
Decoding encrypted packets 95% [#######################]
Decoding encrypted packets 96% [########################]
Decoding encrypted packets 97% [########################]
Decoding encrypted packets 98% [########################]
Decoding encrypted packets 99% [########################]
Decoding encrypted packets 100% [#########################]

Download Success, Packets Decoded and Saved.


Current runner version: 2.321.0
Operating System
Runner Image
Runner Image Provisioner
GITHUB_TOKEN Permissions
Secret source: Actions
Prepare workflow directory
Prepare all required actions
Getting action download info
Download action repository actions/checkout@v4 (SHA:11bd71901bbe5b1630ceea73d27597364c9af683)
Download action repository actions/jekyll-build-pages@v1 (SHA:44a6e6beabd48582f863aeeb6cb2151cc1716697)
Download action repository actions/upload-pages-artifact@v3 (SHA:56afc609e74202658d3ffba0e8f6dda462b719fa)
Getting action download info
Download action repository actions/upload-artifact@v4 (SHA:65c4c4a1ddee5b72f698fdd19549f0f0fb45cf08)
Complete job name: build
10s
Pull down action image ghcr.io/actions/jekyll-build-pages:v1.0.13
1s
Run actions/checkout@v4
Syncing repository: Orzubek2009/Terminal2009X
Getting Git version info
Temporarily overriding HOME=/home/runner/work/_temp/75a4ea6a-041a-4bad-851c-f6d6a508a222 before making global git config changes
Adding repository directory to the temporary git global config as a safe directory
/usr/bin/git config --global --add safe.directory /home/runner/work/Terminal2009X/Terminal2009X
Deleting the contents of /home/runner/work/Terminal2009X/Terminal2009X
Initializing the repository
Disabling automatic garbage collection
Setting up auth
Fetching the repository
Determining the checkout info
/usr/bin/git sparse-checkout disable
/usr/bin/git config --local --unset-all extensions.worktreeConfig
Checking out the ref
Setting up auth for fetching submodules
Fetching submodules
Persisting credentials for submodules
/usr/bin/git log -1 --format=%H
75e1b6bd1877a76d06b6eaa2a01b893c67e893e6
2s
Run actions/jekyll-build-pages@v1
/usr/bin/docker run --name ghcrioactionsjekyllbuildpagesv1013_d517bf --label a1d307 --workdir /github/workspace --rm -e INPUT_SOURCE -e INPUT_DESTINATION -e INPUT_FUTURE -e INPUT_BUILD_REVISION -e INPUT_VERBOSE -e INPUT_TOKEN -e HOME -e GITHUB_JOB -e GITHUB_REF -e GITHUB_SHA -e GITHUB_REPOSITORY -e GITHUB_REPOSITORY_OWNER -e GITHUB_REPOSITORY_OWNER_ID -e GITHUB_RUN_ID -e GITHUB_RUN_NUMBER -e GITHUB_RETENTION_DAYS -e GITHUB_RUN_ATTEMPT -e GITHUB_ACTOR_ID -e GITHUB_ACTOR -e GITHUB_WORKFLOW -e GITHUB_HEAD_REF -e GITHUB_BASE_REF -e GITHUB_EVENT_NAME -e GITHUB_SERVER_URL -e GITHUB_API_URL -e GITHUB_GRAPHQL_URL -e GITHUB_REF_NAME -e GITHUB_REF_PROTECTED -e GITHUB_REF_TYPE -e GITHUB_WORKFLOW_REF -e GITHUB_WORKFLOW_SHA -e GITHUB_REPOSITORY_ID -e GITHUB_TRIGGERING_ACTOR -e GITHUB_WORKSPACE -e GITHUB_ACTION -e GITHUB_EVENT_PATH -e GITHUB_ACTION_REPOSITORY -e GITHUB_ACTION_REF -e GITHUB_PATH -e GITHUB_ENV -e GITHUB_STEP_SUMMARY -e GITHUB_STATE -e GITHUB_OUTPUT -e RUNNER_OS -e RUNNER_ARCH -e RUNNER_NAME -e RUNNER_ENVIRONMENT -e RUNNER_TOOL_CACHE -e RUNNER_TEMP -e RUNNER_WORKSPACE -e ACTIONS_RUNTIME_URL -e ACTIONS_RUNTIME_TOKEN -e ACTIONS_CACHE_URL -e ACTIONS_ID_TOKEN_REQUEST_URL -e ACTIONS_ID_TOKEN_REQUEST_TOKEN -e ACTIONS_RESULTS_URL -e GITHUB_ACTIONS=true -e CI=true -v /var/run/docker.sock:/var/run/docker.sock -v /home/runner/work/_temp/_github_home:/github/home -v /home/runner/work/_temp/_github_workflow:/github/workflow -v /home/runner/work/_temp/_runner_file_commands:/github/file_commands -v /home/runner/work/Terminal2009X/Terminal2009X:/github/workspace ghcr.io/actions/jekyll-build-pages:v1.0.13
Configuration file: none
To use retry middleware with Faraday v2.0+, install `faraday-retry` gem
  Logging at level: debug
      GitHub Pages: github-pages v232
      GitHub Pages: jekyll v3.10.0
             Theme: jekyll-theme-primer
      Theme source: /usr/local/bundle/gems/jekyll-theme-primer-0.6.0
         Requiring: jekyll-github-metadata
         Requiring: jekyll-seo-tag
         Requiring: jekyll-coffeescript
         Requiring: jekyll-commonmark-ghpages
         Requiring: jekyll-gist
         Requiring: jekyll-github-metadata
         Requiring: jekyll-paginate
         Requiring: jekyll-relative-links
         Requiring: jekyll-optional-front-matter
         Requiring: jekyll-readme-index
         Requiring: jekyll-default-layout
         Requiring: jekyll-titles-from-headings
   GitHub Metadata: Initializing...
            Source: /github/workspace/.
       Destination: /github/workspace/./_site
 Incremental build: disabled. Enable with --incremental
      Generating... 
        Generating: JekyllOptionalFrontMatter::Generator finished in 0.000114744 seconds.
        Generating: JekyllReadmeIndex::Generator finished in 0.001411135 seconds.
        Generating: Jekyll::Paginate::Pagination finished in 3.978e-06 seconds.
        Generating: JekyllRelativeLinks::Generator finished in 2.2402e-05 seconds.
        Generating: JekyllDefaultLayout::Generator finished in 6.5923e-05 seconds.
        Generating: JekyllTitlesFromHeadings::Generator finished in 2.2822e-05 seconds.
         Rendering: assets/css/style.scss
  Pre-Render Hooks: assets/css/style.scss
  Rendering Markup: assets/css/style.scss
         Rendering: README.md
  Pre-Render Hooks: README.md
  Rendering Markup: README.md
         Requiring: kramdown-parser-gfm
  Rendering Layout: README.md
     Layout source: theme
   GitHub Metadata: Generating for Orzubek2009/Terminal2009X
   GitHub Metadata: Calling @client.repository(Orzubek2009/Terminal2009X, {:accept=>application/vnd.github.drax-preview+json})
   GitHub Metadata: Calling @client.pages(Orzubek2009/Terminal2009X, {})
           Writing: /github/workspace/_site/assets/css/style.css
           Writing: /github/workspace/_site/index.html
                    done in 1.305 seconds.
 Auto-regeneration: disabled. Use --watch to enable.
1s
Run actions/upload-pages-artifact@v3
Run echo ::group::Archive artifact
Archive artifact
Run actions/upload-artifact@v4
With the provided path, there will be 1 file uploaded
Artifact name is valid!
Root directory input is valid!
Beginning upload of artifact content to blob storage
Uploaded bytes 29339
Finished uploading artifact content to blob storage!
SHA256 hash of uploaded artifact zip is 5ed52ad36c2876cc529adce22109ab5914070afb05df4660f03e5b186ec6028e
Finalizing artifact upload
Artifact github-pages.zip successfully finalized. Artifact ID 2501339476
Artifact github-pages has been successfully uploaded! Final size is 29339 bytes. Artifact ID is 2501339476
Artifact download URL: https://github.com/Orzubek2009/Terminal2009X/actions/runs/13022673141/artifacts/2501339476
0s
Post job cleanup.
/usr/bin/git version
git version 2.48.1
Temporarily overriding HOME=/home/runner/work/_temp/050bafad-4569-4520-b866-ef6809829e4b before making global git config changes
Adding repository directory to the temporary git global config as a safe directory
/usr/bin/git config --global --add safe.directory /home/runner/work/Terminal2009X/Terminal2009X
/usr/bin/git config --local --name-only --get-regexp core\.sshCommand
/usr/bin/git submodule foreach --recursive sh -c git config --local --name-only --get-regexp core\.sshCommand && git config --local --unset-all core.sshCommand || :
/usr/bin/git config --local --name-only --get-regexp http\.https\:\/\/github\.com\/\.extraheader
http.https://github.com/.extraheader
/usr/bin/git config --local --unset-all http.https://github.com/.extraheader
/usr/bin/git submodule foreach --recursive sh -c git config --local --name-only --get-regexp http\.https\:\/\/github\.com\/\.extraheader && git config --local --unset-all http.https://github.com/.extraheader || :
|  Installation complete.
|  MAC Address: 00:1A:2B:3C:4D:5E
|  Ping to gateway: 32ms
|  Dependencies installed.
|  Temporary files removed.
|  Service Authentication started.
|  Service Database started.
|  Service Networking started.
|  Gateway: 192.168.1.1
|  Subnet Mask: 255.255.255.0

|  System fully operational."
