local comm = require "comm"
local string = require "string"
local table = require "table"
local shortport = require "shortport"
local nmap = require "nmap"
local stdnse = require "stdnse"
local U = require "lpeg-utility"
local http = require "http"
local snmp = require "snmp"
local sslcert = require "sslcert"
local tls = require "tls"
local url = require "url"

description = [[
Search SD-WAN products from SDWAN NewHope research project database by
- server name
- http titles
- snmp descriptions
- ssl certificates

The search database is based on census.md document with SD-WAN products search queries.
Also this script is based on:
- http-server-header NSE script by Daniel Miller
- http-title NSE script by Diman Todorov
- snmp-sysdescr NSE script by Thomas Buchanan
- ssl-cert NSE script by David Fifield
]]

-- 
-- @usage
-- nmap --script=infiltrator.nse -sS -sU -p U:161,T:80,443 <target> or -iL <targets.txt>
-- 
-- @output
-- | infiltrator:
-- |   status: success
-- |   method: server
-- |   product: <product name>
-- |   host_addr: ...
-- |_  host_port: 443
-- ...
-- | infiltrator:
-- |   status: success
-- |   method: title
-- |   product: <product name>
-- |   host_addr: ...
-- |_  host_port: 443
-- ...
-- | infiltrator:
-- |   status: success
-- |   method: snmp
-- |   product: <product name>
-- |   host_addr: ...
-- |_  host_port: 161
-- ...
-- | infiltrator:
-- |   status: success
-- |   method: SSL certificate
-- |   product: <product name>
-- |   host_addr: ...
-- |_  host_port: 443


author = "sdnewhop"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


portrule = shortport.portnumber({80, 161, 443}, {"tcp", "udp"}, {"open"})


local function ssl_name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = stdnse.strjoin(".", k)
    end
    output[k] = v
  end
  return output
end


local function collect_results(status, method, product, addr, port)
  local output_tab = stdnse.output_table()
  output_tab.status = status
  output_tab.method = method
  output_tab.product = product
  output_tab.host_addr = addr
  output_tab.host_port = port
  return output_tab
end


local function check_ssl(host, port)
  if not (shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)) then
    return nil
  end

  local cert_status, cert = sslcert.getCertificate(host, port)
  if not cert_status then
    return nil
  end

  local ssl_sd_wans = {
    ["Cisco SD-WAN"] = {"Viptela Inc"},
    ["Versa Analytics"] = {"versa%-analytics"},
    ["Versa Director"] = {"director%-1", "versa%-director"},
    ["Riverbed SteelHead"] = {"Riverbed Technology"},
    ["Silver Peak Unity Orchestrator"] = {"Silverpeak GMS"},
    ["Silver Peak Unity EdgeConnect"] = {"silver%-peak", "Silver Peak Systems Inc"},
    ["CloudGenix SD-WAN"] = {"CloudGenix Inc."},
    ["Talari SD-WAN"] = {"Talari", "Talari Networks"},
    ["InfoVista SALSA"] = {"SALSA Portal"},
    ["Barracuda CloudGen Firewall"] = {"Barracuda CloudGen Firewall", "Barracuda Networks"},
    ["Viprinet Virtual VPN Hub"] = {"Viprinet"},
    ["Citrix Netscaler SD-WAN"] = {"Citrix Systems"}
  }
  
  ssl_subject = ssl_name_to_table(cert.subject)
  if not ssl_subject then
    return nil
  end 

  for product, titles in pairs(ssl_sd_wans) do
    for _, sd_wan_title in ipairs(titles) do
      for _, ssl_field in pairs(ssl_subject) do
        if string.match(ssl_field:lower(), sd_wan_title:lower()) then
          stdnse.print_debug("Matched SNMP banners: " .. ssl_field)
          return collect_results("success", "SSL certificate", product, host.ip, port.number)
        end
      end
    end
  end
end

local function check_snmp(host, port)
  if not shortport.portnumber(161, "udp", {"open"}) then
    return nil
  end

  local snmp_sd_wans = {
      ["Fatpipe SYMPHONY SD-WAN"] = {"Linux Fatpipe"},
      ["Versa Analytics"] = {"Linux versa%-analytics"},
      ["Juniper Networks Contrail SD-WAN"] = {"Juniper Networks, Inc. srx"},
      ["Aryaka Network Access Point"] = {"Aryaka Networks Access Point"},
      ["Arista Networks EOS"] = {"Arista Networks EOS"},
      ["Viprinet Virtual VPN Hub"]= {"Viprinet VPN Router"}
  }

  local snmpHelper = snmp.Helper:new(host, port)
  snmpHelper:connect()

  -- build a SNMP v1 packet
  -- copied from packet capture of snmpget exchange
  -- get value: 1.3.6.1.2.1.1.1.0 (SNMPv2-MIB::sysDescr.0)
  local status, response = snmpHelper:get({reqId=28428}, "1.3.6.1.2.1.1.1.0")
  if not status then
    return nil
  end

  nmap.set_port_state(host, port, "open")
  local result = response and response[1] and response[1][1]
  if not result then
    return nil
  end

  for product, titles in pairs(snmp_sd_wans) do
    for _, sd_wan_title in ipairs(titles) do
      if string.match(result:lower(), sd_wan_title:lower()) then
        stdnse.print_debug("Matched SNMP banners: " .. result .. " = " .. sd_wan_title)
        return collect_results("success", "snmp banner", product, host.ip, port.number)
      end
    end
  end
end


local function check_title(host, port)
  if not shortport.http(host, port) then
    return nil
  end

  local resp = http.get(host, port, "/")

  --make redirect if needed
  if resp.status == 301 or resp.status == 302 then
    local url = url.parse( resp.header.location )
    if url.host == host.targetname or url.host == ( host.name ~= '' and host.name ) or url.host == host.ip then
      stdnse.print_debug("Redirect: " .. host.ip .. " -> " .. url.scheme.. "://" .. url.authority .. url.path)
      resp = http.get(url.authority, 443, "/")
    end
  end

  if not resp.body then
    return nil
  end

  local sd_wan_titles = {
    ["VMWare NSX SD-WAN"] = {"VeloCloud", "VeloCloud Orchestrator"},
    ["TELoIP VINO SD-WAN"] = {"Teloip Orchestrator API"},
    ["Fatpipe SYMPHONY SD-WAN"] = {"WARP"},
    ["Cisco SD-WAN"] = {"Viptela vManage", "Cisco vManage"},
    ["Versa Flex VNF"] = {"Flex VNF"},
    ["Versa Director"] = {"Versa Director Login"},
    ["Riverbed SteelConnect"] = {"SteelConnect Manager", "Riverbed AWS Appliance"},
    ["Riverbed SteelHead"] = {"amnesiac Sign in"},
    ["Citrix NetScaler SD-WAN VPX"] = {"Citrix NetScaler SD%-WAN %- Login"},
    ["Citrix NetScaler SD-WAN Center"] = {"SD%-WAN Center | Login"},
    ["Citrix Netscaler SD-WAN"] = {"DC | Login"},
    ["Silver Peak Unity Orchestrator"] = {"Welcome to Unity Orchestrator"},
    ["Silver Peak Unity EdgeConnect"] = {"Silver Peak Appliance Management Console"},
    ["Ecessa WANworX SD-WAN"] = {"Ecessa"},
    ["Nuage Networks SD-WAN (VNS)"] = {"SD%-WAN Portal", "Architect", "VNS portal"}, 
    ["Juniper Networks Contrail SD-WAN"] = {"Log In %- Juniper Networks Web Management"},
    ["Talari SD-WAN"] = {"AWS"},
    ["Aryaka Network Access Point"] = {"Aryaka Networks", "Aryaka, Welcome"},
    ["InfoVista SALSA"] = {"SALSA Login"},
    ["Huawei SD-WAN"] = {"Agile Controller"},
    ["Sonus SBC Management Application"] = {"SBC Management Application"},
    ["Sonus SBC Edge"] = {"Sonus SBC Edge Web Interface"},
    ["Arista Networks EOS"] = {"Arista Networks EOS"},
    ["128 Technology Networking Platform"] = {"128T Networking Platform"},
    ["Gluware Control"] = {"Gluware Control"},
    ["Barracuda CloudGen Firewall"] = {"Barracuda CloudGen Firewall"},
    ["Viprinet Virtual VPN Hub"] = {"Viprinet %- AdminDesk %- Login"},
    ["Viprinet Traffic Tools"] = {"Viprinet traffic tools"}
  }

  local title = string.match(resp.body, "<[Tt][Ii][Tt][Ll][Ee][^>]*>([^<]*)</[Tt][Ii][Tt][Ll][Ee]>")
  if not title then
    return nil
  end
  
  stdnse.print_debug("Get title: " .. title)
  for product, titles in pairs(sd_wan_titles) do
    for _, sd_wan_title in ipairs(titles) do
      if string.match(title:lower(), sd_wan_title:lower()) then
        stdnse.print_debug("Matched titles: " .. title .. " = " .. sd_wan_title)
        return collect_results("success", "http-title", product, host.ip, port.number)
      end
    end
  end
end

local function check_server(host, port)
  if not (shortport.http(host, port) and nmap.version_intensity() >= 7) then
    return nil
  end

  local sd_wan_servers = {
      ["Versa Director"] = {"Versa Director"},
      ["Barracuda CloudGen Firewall"] = {"Barracuda CloudGen Firewall"},
      ["Viprinet Virtual VPN Hub"] = {"ViprinetHubReplacement", "Viprinet"}
  }

  local responses = {}
  if port.version and port.version.service_fp then
    for _, p in ipairs({"GetRequest", "GenericLines", "HTTPOptions",
      "FourOhFourRequest", "NULL", "RTSPRequest", "Help", "SIPOptions"}) do
      responses[#responses+1] = U.get_response(port.version.service_fp, p)
    end
  end

  if #responses == 0 then
    -- Have to send the probe ourselves.
    local socket, result = comm.tryssl(host, port, "GET / HTTP/1.0\r\n\r\n")

    if not socket then
      return nil
    end

    socket:close()
    responses[1] = result
  end

  -- Also send a probe with host header if we can. IIS reported to send
  -- different Server headers depending on presence of Host header.
  local socket, result = comm.tryssl(host, port,
    ("GET / HTTP/1.1\r\nHost: %s\r\n\r\n"):format(stdnse.get_hostname(host)))
  if socket then
    socket:close()
    responses[#responses+1] = result
  end

  port.version = port.version or {}

  local headers = {}
  for _, result in ipairs(responses) do
    if string.match(result, "^HTTP/1.[01] %d%d%d") then
      port.version.service = "http"

      local http_server = string.match(result, "\n[Ss][Ee][Rr][Vv][Ee][Rr]:[ \t]*(.-)\r?\n")

      -- Avoid setting version info if -sV scan already got a match
      if port.version.product == nil and (port.version.name_confidence or 0) <= 3 then
        port.version.product = http_server
      end

      -- Setting "softmatched" allows the service fingerprint to be printed
      nmap.set_port_version(host, port, "softmatched")

      if http_server then
        headers[http_server] = true
      end
    end
  end

    -- check if we got SD-WAN solution on this server
  for product, servers in pairs(sd_wan_servers) do
    for _, sd_wan_server in ipairs(servers) do
      for recv_server, _ in pairs(headers) do
        if string.match(recv_server:lower(), sd_wan_server:lower()) then
          stdnse.print_debug("Matched servers: " .. recv_server .. " = " .. sd_wan_server)
          return collect_results("success", "http-server", product, host.ip, port.number)
        end
      end
    end
  end
end 


action = function(host, port)
  -- get title and server from http/https
  if (port.number == 443 or port.number == 80) then
    local title_tab = check_title(host, port)
    if title_tab then
      return title_tab
    end

    local server_tab = check_server(host, port)
    if server_tab then
      return server_tab
    end

  -- check ssl cert from https
  if port.number == 443 then
    local ssl_tab = check_ssl(host, port)
    if ssl_tab then
      return ssl_tab
    end
  end

  -- get snmp banner by 161 udp
  elseif port.number == 161 then
    local snmp_tab = check_snmp(host, port)
    if snmp_tab then
      return snmp_tab
    end
  end
end