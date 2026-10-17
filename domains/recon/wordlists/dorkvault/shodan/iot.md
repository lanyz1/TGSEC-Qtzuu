# Shodan - IoT
A curated collection of Shodan search queries for discovering and researching publicly observable Internet of Things (IoT) devices and services during authorized security research and reconnaissance.

---

# IoT Device Discovery
## Generic IoT Search
IoT

## IoT by Country
country:US IoT

## IoT by Organization
org:"Example Organization" IoT

## IoT with Screenshots
IoT has_screenshot:true

---

# Cameras
## Camera Search
camera

## IP Cameras
"IP Camera"

## Network Cameras
"Network Camera"

## Webcam Search
webcam

## Cameras by Country
country:US camera

## Cameras with Screenshots
camera has_screenshot:true

---

# Routers
## Router Search
router

## Routers by Country
country:US router

## Routers by Organization
org:"Example Organization" router

---

# Network Devices
## Network Devices
"network device"

## Network Equipment
"network equipment"

## Switches
switch

## Access Points
"access point"

---

# Printers
## Network Printers
printer

## Printers by Country
country:US printer

## Printers with Screenshots
printer has_screenshot:true

---

# Industrial and Embedded Systems
## SCADA References
SCADA

## Industrial Control Systems
"industrial control system"

## PLC References
PLC

## Embedded Systems
embedded

---

# Smart Home Devices
## Smart Home
"smart home"

## Home Automation
"home automation"

## Smart Devices
"smart device"

---

# IoT Protocols
## MQTT
port:1883

## MQTT over TLS
port:8883

## CoAP
port:5683

## CoAP over DTLS
port:5684

---

# IoT Services
## MQTT Services
service:mqtt

## MQTT by Country
country:US service:mqtt

## MQTT by Organization
org:"Example Organization" service:mqtt

---

# Device Identification
## Device Product
product:"Product Name"

## Device Manufacturer
"Manufacturer Name"

## Device Version
product:"Product Name" version:"version"

---

# Geographic IoT Research
## IoT Devices by Country
country:US IoT

## IoT Devices by City
city:"New York" IoT

## Cameras by City
city:"New York" camera

## Printers by City
city:"New York" printer

---

# Organization-Based IoT Research
## IoT Devices
org:"Example Organization" IoT

## Cameras
org:"Example Organization" camera

## Network Devices
org:"Example Organization" ("network device" OR router OR switch)

## Industrial Devices
org:"Example Organization" (SCADA OR PLC OR "industrial control system")

---

# Screenshot-Based Research
## Devices with Screenshots
has_screenshot:true IoT

## Cameras with Screenshots
has_screenshot:true camera

## Printers with Screenshots
has_screenshot:true printer

## Web Interfaces with Screenshots
has_screenshot:true http

---

# Combined Searches
## IoT + HTTPS
IoT port:443

## Camera + HTTPS
camera port:443

## Router + HTTPS
router port:443

## IoT + Organization
org:"Example Organization" IoT

## IoT + Country + Port
country:US IoT port:443

---

# IoT Reconnaissance Workflow
1. Define the authorized target or organization.
2. Identify publicly observable IoT-related services.
3. Identify device types and manufacturers when possible.
4. Record exposed protocols and ports.
5. Correlate discovered devices with the authorized scope.
6. Validate findings without accessing protected resources.
7. Report unintended exposure according to the applicable security policy.

---

# Important Notes
- IoT device identification can produce false positives.
- Shodan data may be outdated.
- A publicly observable device does not automatically indicate a vulnerability.
- Do not access device interfaces without authorization.
- Do not attempt default credentials or authentication attacks.
- Do not change device configurations.
- Do not access camera feeds, private data or protected resources.
- Industrial and critical infrastructure requires additional caution and explicit authorization.
- Respect bug bounty scope and security policies.
- These queries are intended for educational purposes, OSINT and authorized security research.