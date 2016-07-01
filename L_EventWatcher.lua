local ABOUT = {
  NAME          = "EventWatcher",
  VERSION       = "2016.07.01",
  DESCRIPTION   = "EventWatcher - variable and event reporting",
  AUTHOR        = "@akbooer",
  COPYRIGHT     = "(c) 2013-2016 AKBooer",
  DOCUMENTATION = "https://github.com/akbooer/EventWatcher",
}


------------------------------------------------------------------------
--
-- Event Watcher: does three things:
-- 1) functions as a local 'Alternate Event Server' for Vera notifications
-- 2) watches selected device categories and logs key variable changes
-- 3) generates reports of current device variable values and time last changed, etc.
-- 

--  2016

-- TODO: fix Alternate Event Server for UI7 ???

-- 2016.07.01  update set_failure for UI5/7 compatibility
--             Use fully qualified domain name, not just IP address (suggested by @Les F)
--             see: http://forum.micasaverde.com/index.php/topic,37627.0.html
--             ALSO, extra door and HVAC watches (suggested by @johnes)
--             see: http://forum.micasaverde.com/index.php/topic,37514.0.html

--[[
UI5:
Vera will send the event as a standard HTTPS (secure) GET to yourserver/alert 
with the arguments passed on the URL, like this (assuming your server is myserver.me.com):

 https://myserver.me.com/alert?
 PK_AccessPoint=[serial number of Vera; in Lua you can get it with luup.pk_accesspoint]
 &HW_Key=[hardware key of Vera; in Lua you can get it with luup.hw_key]
 &DeviceID=[device id that is associated with the alert]
 &LocalDate=[the time the alert happened as human readable text]
 &LocalTimestamp=[the time the alert happened as a unix timestamp in UTC]
 &AlertType=[one of the alert types below]
 &SourceType=[one of the source types below]
 &Argument=[an optional argument depending on the alert type]
 &Format=[a file format, not normally used]
 &Code=[a code for the alert, usually the variable that changed]
 &Value=[the value corresponding to the code above]
 &Description=[a human readable description of the event, or comments regarding it]
 &Users=[a comma separated list of user id's that should be notified of the event]
 

To set the alternate event server to this EventWatcher plugin, visit
   'http://[your Vera IP]:3480/data_request?id=variableset&Variable=AltEventServer&Value=127.0.0.1'

]]


local eventID = 0		  -- count the events
local HISTORY = {}		-- cache for events

local historyID	= 0		-- counter for history storage
local history = {}		-- cache for system statistics

local LuupRestart = os.time()			-- restart time

local socket 	= require "socket" 
local ssl    	= require "ssl"
local url	 	  = require "socket.url"
local library	= require "L_EventWatcher2"

local cli   	= library.cli()
local gviz  	= library.gviz()
local json  	= library.json() 


--local AlertType = {"Image", "Video", "Trigger", "Variable", "Logon", "Gateway Connected", 
--			 	"System Error", "Validate Email", "Validate SMS", "System Message"}
 
--local SourceType = {"User", "Timer", "Trigger", "Variable"}
 
--local FileFormat = {"JPEG", "MJPEG", "MP4"}


local EventWatcherSID	= "urn:akbooer-com:serviceId:EventWatcher1"
--local HTTPsData			= "HTTPsData"

---	
-- 'global' program variables assigned in init()
--

local debugOn 
local EventWatcherID				-- Luup device ID

local systemPollMinutes = 2	-- update system stats every X MINUTES
local pollInterval = 5			-- poll the HTTPS client queue every X SECONDS
local logDirectory          -- log file directory
local syslogInfo            -- syslog IP:PORT

local cacheSize             -- length of event storage cache
local watchCategories				-- which category of devices to watch
local extrasFile            -- file containing list of extra variables to watch ddd.srv.var (a la DataWatcher)
local excludeFile           -- file containing list of extra variables to watch ddd.srv.var (a la DataWatcher)

local symbol = {}					  -- lookup table from deviceNo to category symbol
local watching						  -- DataTable of devices being watched
local watchedDevice = {}    -- table of watched device numbers

local Server                -- HTTPS Alternate Event Server Server socket
local syslog                -- syslog server

------------------------------------------------------------------------
--
-- Luup utility routines
-- 

local function log (message)
  luup.log ('EventWatcher: '.. (message or '???') )
--  if syslog then syslog:send (message) end
end

local function debug (txt, ...)
  if debugOn then 
    local message = txt: format (...)
    log (message) 
    if syslog then syslog:send (message, 7) end   -- severity = debug
  end
end

local function get (name, service, device)
	return luup.variable_get (service or EventWatcherSID, name, device or EventWatcherID)
end

local function set (name, value, service, device)
  service = service or EventWatcherSID
  device = device or EventWatcherID
  local old = get (name, service, device)
  if tostring(value) ~= old then 
	 luup.variable_set (service, name, value, device)
	end
end

-- get and check UI variables
local function uiVar (name, default, lower, upper)
	local value = get (name) 
	local oldvalue = value
	if value and (value ~= "") then						-- bounds check if required
		if lower and (tonumber (value) < lower) then value = lower end
		if upper and (tonumber (value) > upper) then value = upper end
	else
		value = default
	end
	value = tostring (value)
	if value ~= oldvalue then set (name, value)	end		-- default or limits may have modified value
	return value
end


-- UI7 return status : {0 = OK, 1 = Device config error, 2 = Authorization error}
local function set_failure (status)
  if (luup.version_major < 7) then status = status ~= 0 end        -- fix UI5 status type
  luup.set_failure(status)
end

------------------------------------------------------------------------
--
-- Utility routines
-- 

local function devName (devNo)          -- format for "[devNo] Luup description"
  devNo = devNo or 0
  return (luup.devices[devNo] or {description = ''}).description
end

local function roomName (roomNo)          -- room name
  roomNo = roomNo or 0
  return luup.rooms[roomNo] or '-no room-'
end
  
local function weeknum (time)           -- returns week number of given time (or now)
  local weekSeconds = 7 * 24 * 60 * 60
    return math.floor((time or os.time() ) / weekSeconds)
end

local function event (time, devNo, name, var, arg)		-- constructor and formatter for event types
  local function format (e) 
    local ms = math.floor (1000 * (e.time % 1)) 
    return ('%s.%03d, %s, %3d, %s, %s, %s, %s\n'):format (os.date ("%Y-%m-%d %H:%M:%S",e.time), ms,
                                e.symbol, e.devNo or 0, devName(e.devNo,nil,'"'), e.name or '?', e.var or '?', e.arg or '') 
  end 
  local function syslogFormat (e) 
    return ('%s [%03d] %s, %s = %s (%s)'):format (e.symbol, e.devNo or 0, devName(e.devNo,nil,'"'), e.name or '?', e.var or '?', e.arg or '') 
  end 
	eventID = eventID + 1
  local index = eventID % cacheSize + 1
  HISTORY[index] = HISTORY[index] or {}     -- reuse table, or create new
  local e = HISTORY[index]
	e.id		= eventID
	e.time	= tonumber (time) or socket.gettime() or os.time()		--	millisecond resolution, for preference
	e.devNo	= tonumber (devNo) or 0
	e.symbol	= symbol[devNo] or 'E'
	e.name	= name or 'Event'
	e.var		= var or '?'
	e.arg   = arg or ''
  
  if syslog then   -- also log to syslog server
    syslog:send (syslogFormat (e)) 
  end
	
	if logDirectory ~= '' then               -- also log to file
    local weekNo = weeknum (e.time)
    local filename = logDirectory..weekNo..'.txt'
    local f = io.open(filename,'a') 
    if f then
      f:write (format (e))
      f:close ()
    end
	end
	
end

--blog events
function eventBlog (e)
--	local json_string  = json.encode (e)
--	set ('jsonString', json_string)
	local timestamp = e.LocalTimestamp or socket.gettime() or os.time()		-- gets either the provided time OR the current system time
	set ('Timestamp', os.date ("%a %H:%M", timestamp))						-- say when this happened
	event (timestamp, e.DeviceID, e.Description, e.Code, e.Argument) 
end

-- blog watched variables
--function watchBlog (lul_device, lul_service, lul_variable, lul_value_old, lul_value_new)
function watchBlog (lul_device, _, lul_variable, _, lul_value_new)
	event (nil, lul_device, lul_variable, lul_value_new) 
end


------------------------------------------------------------------------
--
-- Alternate Event Server routines
-- 
-- see: http://wiki.micasaverde.com/index.php/AlternateEventServer
-- 
local IP      	= "127.0.0.1"
local PORT    	= 443
local BACKLOG	= 32			-- max # of clients in the queue (should be enough!)
local TIMEOUT	= 0.01			-- don't block for too long!

local SSL_params = {
        key         = "",					-- set in init()
        certificate = "",					-- ditto
        mode        = "server",
        protocol    = "sslv3",
        verify      = {"none"},
        ciphers     = "ALL",
    }

local http_response

if luup.version_major == 7 then
  http_response = [[
HTTP/1.1 200 OK
Content-Length: 27
Connection: close

{"PK_Event": 0, "Key": "0"}]]
else
  http_response = [[
HTTP/1.1 200 OK
Content-Length: 10
Connection: close

PK_Alert:0]]
end

local function decode (s)	-- pull parameters pairs "A=B" out of argument string
  local cgi = {}
  for name, value in s:gfind "([^&=?%s]+)=([^&=?%s]+)" do
    local n,v  = url.unescape(name), url.unescape(value)
    cgi[n] = v
  end
  return cgi
end


local function accept_client()
  local client, rc, error

  client = Server:accept()
  if client == nil then return end
   
  local ip, port = client:getpeername()
  if ip == nil then return end

  local ip_port = string.format("%s:%s", ip, port)

  client, error = ssl.wrap(client, SSL_params) 
  if not client then
    log (ip_port .. " SSL wrap error: " .. tostring(error))
    return
  end

  rc, error = client:dohandshake()  -- remove unless SSL
  if not rc then
    log(ip_port .. " SSL handshake error: " .. tostring(error))
    return
  end
 
  client:settimeout(1)
  return client, ip_port
end

function pollClients()
  repeat
    local client, ip_port = accept_client()

	if client then   
    local data, error = client:receive('*l')
    if error then
      log(ip_port .. " receive error: " .. tostring(error))
      break
    end
     
    debug("HTTPS request = " .. (ip_port or '?') .. " " .. data)						-- log all requests
    
    if data:match "^(%u*)" == "GET" and data:match "/(%w+)?" == "alert" then		-- genuine notification
      local query_params = decode (data)
      eventBlog (query_params)
    end
          
		repeat 
			data = client:receive('*l') 
			if data then debug (ip_port .. ': ' .. data) end
		until not data	        -- consume remaining lines
      
    local bytes_sent, errmsg = client:send(http_response)
    if not bytes_sent then
        log(ip_port .. " error sending response: " .. tostring(errmsg))
    end

    client:close()
  end
  until not client
	luup.call_delay ('pollClients', pollInterval, "")					-- continue periodic poll for clients
end


local function syslog_server (ip_and_port, tag, hostname)
  local sock = socket.udp()
  local facility = 1    -- 'user'
--  local emergency, alert, critical, error, warning, notice, info, debug = 0,1,2,3,4,5,6,7
  local info = 6
  local ip, port = ip_and_port: match "^(%d+%.%d+%.%d+%.%d+):(%d+)$"
  if not ip or not port then return nil, "invalid IP or PORT" end
  local serialNo = luup.pk_accesspoint
  hostname = ("Vera-"..serialNo) or "Vera"
  if not tag or tag == '' then tag = "Plugin" end
  tag = tag: gsub("[^%w]","") or "EventWatcher"  -- only alphanumeric, no spaces or other
  local function send (self, content, severity)
    content  = tostring (content)
    severity = tonumber (severity) or info
    local priority = facility*8 + (severity%8)
    local msg = ("<%d>%s %s %s: %s\n"):format (priority, os.date "%b %d %H:%M:%S", hostname, tag, content)
    sock:send (msg) 
  end
  local ok, err = sock:setpeername(ip, port)
  if ok then ok = {send = send} end
  return ok, err
end

------------------------------------------------------------------------
--
-- Device Variable Watch routines
--

local Dsid = "urn:micasaverde-com:serviceId:DoorLock1" -- per: @Aaron, http://forum.micasaverde.com/index.php/topic,16984.msg178108.html#msg178108
local Hsid = "urn:micasaverde-com:serviceId:HumiditySensor1"
local Lsid = "urn:micasaverde-com:serviceId:LightSensor1"
local Tsid = "urn:upnp-org:serviceId:TemperatureSensor1"
local Msid = "urn:dcineco-com:serviceId:MSwitch1"   -- per: @RexBeckett, http://forum.micasaverde.com/index.php/topic,16984.msg160646.html#msg160646
local Vsid = "urn:upnp-org:serviceId:VSwitch1"

local function classTable (sym, srv, var, lbl) 				-- table constructor
	return {symbol = sym, service = srv, variable = var, label = lbl }
end
--[[
local HVAC = {
  srv = {
    "urn:upnp-org:serviceId:HVAC_UserOperatingMode1", 
    "urn:upnp-org:serviceId:TemperatureSetpoint1_Heat",
    "urn:upnp-org:serviceId:TemperatureSetpoint1_Cool",
    "urn:upnp-org:serviceId:TemperatureSensor1",
    "urn:upnp-org:serviceId:HouseStatus1",                -- per: @mda, http://forum.micasaverde.com/index.php/topic,16984.msg161698.html#msg161698
    "urn:micasaverde-com:serviceId:HVAC_OperatingState1", -- per: @aaron, http://forum.micasaverde.com/index.php/topic,16984.msg170399.html#msg170399
    "urn:upnp-org:serviceId:HVAC_FanOperatingMode1",      -- per: ditto
  },
  var = {
    "ModeStatus",
    "CurrentSetpoint",
    "CurrentSetpoint",
    "CurrentTemperature",
    "OccupancyState",
    "ModeState",
    "Mode",
  } }
]]

local HVAC_Services = {
  "urn:upnp-org:serviceId:HVAC_UserOperatingMode1",
  "urn:upnp-org:serviceId:TemperatureSetpoint1_Heat",
  "urn:upnp-org:serviceId:TemperatureSetpoint1_Cool",
  "urn:upnp-org:serviceId:TemperatureSensor1",
  "urn:micasaverde-com:serviceId:HVAC_OperatingState1",
  "urn:upnp-org:serviceId:HVAC_UserOperatingMode1",
  "urn:upnp-org:serviceId:HVAC_FanOperatingMode1",
  "urn:upnp-org:serviceId:TemperatureSetpoint1",
  "urn:upnp-org:serviceId:TemperatureSensor1",
}

local HVAC_Variables = {
  "ModeStatus",
  "CurrentSetpoint",
  "CurrentSetpoint",
  "CurrentTemperature",
  "ModeState",
  "EnergyModeStatus",
  "FanStatus",
  "CurrentSetpoint",
  "CurrentTemperature",
}

local Meter_Services = {
  "urn:micasaverde-com:serviceId:EnergyMetering1",  
  "urn:micasaverde-com:serviceId:EnergyMetering1"
}

local Meter_Variables = {
  "Watts",
  "KWH"
}

local Alarm_Partition_Services = {
  "urn:micasaverde-com:serviceId:AlarmPartition2",
  "urn:micasaverde-com:serviceId:AlarmPartition2",
  "urn:micasaverde-com:serviceId:AlarmPartition2",
}

local Alarm_Partition_Variables = {
  "ArmMode",
  "DetailedArmMode",
  "Alarm",
}

local AV_Services = {
  "urn:upnp-org:serviceId:SwitchPower1",
  "urn:micasaverde-com:serviceId:Volume1",
--  "urn:upnp-org:serviceId:RenderingControl",
--  "urn:micasaverde-com:serviceId:InputSelection1",
}

local AV_Variables = {
  "Status",
  "Volume",
}


--[[
  local DLock_Services = {
  Dsid, 
  Dsid,
}

local DLock_Variables = {
  "Status",
  "sl_UserCode",
}
--]]

local Door_Services = {Dsid, Dsid, Dsid, Dsid}

local Door_Variables = {
  "Status",
  "sl_UserCode",
  "sl_PinFailed",
  "sl_LockButton",
}
local MV_Switch_Services = {Vsid, Msid, Msid, Msid, Msid, Msid, Msid, Msid, Msid}

local MV_Switch_Variables = {"Status", "Status1", "Status2", "Status3", "Status4", "Status5", "Status6", "Status7", "Status8"}

local classes = {  -- table of the different types of devices and their various attributes
--            "E" is used for events
	classTable ("F",  nil,                                             nil, 	              "INTERFACE"),        -- 1
	classTable ("X", "urn:upnp-org:serviceId:SwitchPower1",				    "Status",	            "DIMMABLE_LIGHT"),   -- 2		
	classTable ("X", "urn:upnp-org:serviceId:SwitchPower1", 			    "Status",	            "SWITCH"),           -- 3	
	classTable ("S", "urn:micasaverde-com:serviceId:SecuritySensor1",	"Tripped",            "SECURITY_SENSOR"),  -- 4
	classTable ("K",	HVAC_Services,                                   HVAC_Variables,       "HVAC"),             -- 5
	classTable ("C",  nil,                                             nil,                 "CAMERA"),           -- 6
--	classTable ("D",  DLock_Services,                                  DLock_Variables,     "DOOR_LOCK"),        -- 7
  classTable ("D",  Door_Services,                                   Door_Variables,      "DOOR_LOCK"),        -- 7
  classTable ("W", "urn:upnp-org:serviceId:Dimming1",               "LoadLevelStatus",    "WINDOW_COV"),       -- 8
	classTable ("R",	nil,                                             nil,                 "REMOTE_CONTROL"),   -- 9
	classTable ("I",  nil,                                             nil,                 "IR_TX"),            -- 10
	classTable ("O",  nil,                                             nil,	                "GENERIC_IO"),       -- 11
	classTable ("G", "urn:micasaverde-com:serviceId:GenericSensor1", 	"CurrentLevel",       "GENERIC_SENSOR"),   -- 12
	classTable ("B",  nil,                                             nil,                 "SERIAL_PORT"),      -- 13
	classTable ("Y", "urn:micasaverde-com:serviceId:SceneController1","sl_SceneActivated",  "SCENE_CONTROLLER"), -- 14
	classTable ("V",  AV_Services,                                     AV_Variables,        "AV"),               -- 15
	classTable ("H",  Hsid,                                           "CurrentLevel",       "HUMIDITY"),         -- 16
	classTable ("T",  Tsid,                                        		"CurrentTemperature", "TEMPERATURE"),      -- 17
	classTable ("L",  Lsid,                                       		"CurrentLevel",       "LIGHT_SENSOR"),     -- 18
	classTable ("Z",  nil,                                             nil,                 "ZWAVE_INT"),        -- 19
	classTable ("J",  nil,                                             nil,                 "INSTEON_INT"),      -- 20
	classTable ("M",  Meter_Services,                                  Meter_Variables,     "POWER_METER"),      -- 21  
	classTable ("A",  nil,                                             nil,                 "ALARM_PANEL"),      -- 22
	classTable ("P",	Alarm_Partition_Services,                  Alarm_Partition_Variables, "ALARM_PARTITION"),  -- 23
} 
------- 'extra' uncategorised "class U" service/variables here:
classes[0] = 
  classTable ("U",  MV_Switch_Services,                              MV_Switch_Variables, "UNCATEGORISED")

local ClassLetterToCat = {}
for i,j in ipairs (classes) do
  ClassLetterToCat[j.symbol] = i
end


-- codeBlog (), list out the above codes
local function codeBlog (p)
  local options = p.options
  local data = gviz.DataTable ()
  data.addColumn ("number", "Cat. #")
  data.addColumn ("string", "Cat. Symbol")
  data.addColumn ("string", "Cat. Name")
  data.addColumn ("string", "ServiceId")
  data.addColumn ("string", "Variable")
  local title = "Device Category Codes"
  for i = 0, #classes do        -- don't use ipairs, because starting at 0 (sorry!)
    local class = classes[i]
    local srv = class.service  or "--- none ---"
    local var = class.variable or ' '
    if type (srv) ~= "table" then srv = {srv} end
    if type (var) ~= "table" then var = {var} end
    for j = 1, #srv do
      data.addRow {i, class.symbol, class.label, srv[j], var[j]}
    end
  end
  local chart = gviz.Table()
  options = {title = title, height = options.height or 700, width = options.width or 800} 
  return chart.draw (data, options) 
end


------------------------------------------------------------------------
--
-- Sensor blog routines
-- 

-- enviroBlog (), blog the list of environmental measurements to web 
local function enviroBlog (p)
	local options = p.options
	local blogCats = {'L', 'T', 'H', 'G'}								-- these are the sensor categories to blog 
	local data = gviz.DataTable ()
	data.addColumn ("string", "Sensor Type")
	data.addColumn ("string", "Value")
	data.addColumn ("number", "Device No.")
	data.addColumn ("string", "Device Name")
	local title = "Environmental sensors"
	for _, letter in ipairs (blogCats) do
	  local c = ClassLetterToCat[letter]
		local service = classes[c].service
		local srvName = service:match "%w+$" or '?'
		local var = classes[c].variable
		for devNo in pairs(luup.devices) do
			local value = get (var, service, devNo)
			if value then
			  data.addRow {srvName, value or '?', devNo, devName (devNo) }
		  end
		end
	end
	local chart = gviz.Table()
	options = {title = title, height = options.height or 500, width = options.width or 600}	
	return chart.draw (data, options)	
end


-- securityBlog ()
local function securityBlog (p) 
  local options = p.options
  local blogCats = {'D', 'S'}               -- these are the sensor categories to blog 
  local data = gviz.DataTable ()
  data.addColumn ("datetime", "Last Trip")
  data.addColumn ("number", "Device No.")
  data.addColumn ("string", "Name")
  data.addColumn ("string", "Current Status")
  local title = "Security sensors" 
  for _, letter in ipairs (blogCats) do
    local c = ClassLetterToCat[letter]
    local service = classes[c].service
    local var = classes[c].variable
    for devNo in pairs(luup.devices) do
      local value, lastSet = get (var, service, devNo)
      local lastTrip = tonumber ((get('LastTrip', service, devNo) )) or lastSet
      if value then
        data.addRow {lastTrip, devNo, devName (devNo), value or '?'}
      end
    end
  end
  data.sort {column = 1, desc = true}
  local chart = gviz.Table()
  options = {title = title, height = options.height or 500, width = options.width or 600} 
  return chart.draw (data, options) 
end

-- device blog
-- see http://forum.micasaverde.com/index.php/topic,15789.msg120635.html#msg120635
-- and http://forum.micasaverde.com/index.php/topic,15010.msg114135.html#msg114135
-- and http://forum.micasaverde.com/index.php/topic,18459.msg142797.html#msg142797
local function deviceBlog (p)
	local options = p.options
	local batterySID = "urn:micasaverde-com:serviceId:HaDevice1"
	local batteryVAR = "BatteryLevel"		
	local data = gviz.DataTable ()
	data.addColumn ("number", "Device Id.")
	data.addColumn ("number", "Parent")
  data.addColumn ("string", "Device Name")
  data.addColumn ("string", "Room")
	data.addColumn ("string", "Battery %")
	data.addColumn ("string", "Device Type")
	data.addColumn ("string", "Alt Id.")
	for deviceNo,d in pairs(luup.devices) do
		local dtype = (d.device_type: match ":(%w*):%d+$") or ''
		local battery = tonumber((luup.variable_get(batterySID, batteryVAR, deviceNo))) or ''
		local room = roomName(d.room_num)
		data.addRow {deviceNo, d.device_num_parent or 0, d.description or '', room, battery, dtype, d.id}
    end
    data.sort (1)
	local chart = gviz.Table()
	options = {title = 'Device List', height = options.height or 800, width = options.width or 750}	
	return chart.draw (data, options)	
end

-- sceneBlog (), build list of scenes with trigger devices and actioned devices
-- see http://forum.micasaverde.com/index.php/topic,15360.msg116759.html#msg116759
-- and http://forum.micasaverde.com/index.php/topic,15360.msg136415.html#msg136415

-- classic map utility - cf. pairs
local function map (Xs , fct)   -- map function to each item in table, returns {} if none
	local table = {}
	for i,x in pairs (Xs or {}) do table[i] = fct(x) end
	return table 
end

-- classic list flatten
local function flatten (array)
	local l = {}
	local function add_item (x) l[#l+1] = x; end
	for _,x in ipairs(array) do
		if type(x) == "table" then map(flatten(x), add_item ) else add_item (x) end
	end
	return l
end

-- formatting functions for displaying data structure

local br = '<br>'  -- or, for plain text, ', '
local function format_names(d) return map (d, function (x) return x.name or ''; end) end	

local function format_device(x) return ("[%03d] %s"):format (x, (luup.devices[tonumber(x)] or {description = ''}).description) end
local function format_devices(d) return map (d, format_device) end

local function format_timer(t) 
	local format = "Enabled: %s\nLast run: %s\nNext run: %s\nLua:\n%s"
	return format: format (t.enabled, os.date("%c",t.last_run), os.date("%c",t.next_run), t.lua or '-none-') 
end
local function format_timers (t) t = t or {}; return table.concat(format_names(t), br) end

local function format_triggers (t) return table.concat(format_devices(t), br) end
local function format_actions (t) return table.concat(format_devices(t), br) end


local function sceneInfo (sceneNo)
	-- set operations, only what we need here: add, list 
	local function set()								-- create new empty set
		local s = {}		-- holder for set
		return {
			add  = function (x) s[x] = x; end, 			-- add element to the set
			list = function ( ) 						-- return sorted list of set elements
				local l = {}; 
				for i in pairs(s) do l[#l+1] = i; end; 
				table.sort (l);
				return l; end
			}
	end
		
	-- functions to build data structure of devices triggering scenes, and actioned by scenes
	local function get_device (x) return x.device end
	
	local function trigger_devices (t)
		local trigger_set = set()  					-- create a new empty set (of device numbers)
		local device_list = map (t, get_device)		-- create list of device numbers
		map (device_list, trigger_set.add)			-- add elements to set
		return trigger_set.list ()					-- return sorted list of set members
	end
	
	local function action_devices (groups)
		local action_set = set() 					-- create a new empty set (of device numbers)
		local function actions (g) return map (g.actions, get_device) end
		local action_list = map (groups, actions)	-- create list of actions
		map (flatten(action_list), action_set.add)	-- mash together all the action device lists
		return action_set.list ()					-- return sorted list of set members
	end
	
	-- sceneInfo()
	local code, s = luup.inet.wget("http://127.0.0.1:3480/data_request?id=scene&action=list&scene=" .. sceneNo)
	if s == "ERROR" then log ("WGET error code: "..(code or '?')) return end		
	s = json.decode(s)
	s.triggers = trigger_devices (s.triggers)		-- restructure scenes and trigger to simple sorted, lists
	s.actions  = action_devices  (s.groups) 	
	return s
end


local function sceneBlog (p)
	local data = gviz.DataTable ()
	data.addColumn ("number", "Scene No.")
	data.addColumn ("string", "Name")
	data.addColumn ("string", "Schedules")
	data.addColumn ("string", "Triggers")
	data.addColumn ("string", "Actions")
	data.addColumn ("string", "Lua")

	local chart = gviz.Table()
	local options = {title = 'Scene List', allowHtml = true, 
						height = p.options.height or 700, width = p.options.width or 1000}	
	
	for i in pairs (luup.scenes) do
		local s = sceneInfo (i)
		if s then 
			data.addRow {s.id, s.name, format_timers(s.timers), format_triggers(s.triggers), format_actions(s.actions), 
--              (s.lua or ''): gsub ('\n', br)}
              table.concat {'<pre><div class="notranslate">',s.lua or '','</div></pre>'}}
		end
	end	
	data.sort (1)	
	return chart.draw (data, options)		
end


local function sceneBlog2 (p)		
	local d = gviz.DataTable ()
	local scene = p.actions.scene 					-- guaranteed by cli.parser to be an integer

	local s = sceneInfo (scene)
	if not s then return end
	
	d.addColumn ("string", "Item")
	d.addColumn ("string", "Parent")
	d.addColumn ("string", "ToolTip")

	local n, parent = 0
	local root = table.concat {"Scene #", scene, "<br>", s.name or ''}

	if s.timers and #s.timers > 0 then
		parent = "Schedules"
		d.addRow {parent, 	root, ''}
		for _,t in ipairs (s.timers or {}) do 
			n=n+1
			d.addRow {{v=n, f=t.name or ''}, parent, format_timer(t)}
			parent=n 
		end
	end
	
	if s.triggers and #s.triggers > 0 then
		parent = "Triggers"
		d.addRow {parent, 	root, ''}
		for _,t in ipairs (s.triggers or {}) do 
			n=n+1
			d.addRow {{v=n, f=format_device(t) or ''}, parent, ''}
			parent=n 
		end
	end
	
	if s.actions and #s.actions > 0 then
		parent = "Actions"
		local Na, Pa, Ca = 0, {}, 3		-- column counter, parent list, # columns
		for i = 1,Ca do Pa[i] = parent end
		d.addRow {parent, 	root, ''}
		for _,a in ipairs (s.actions or {}) do 
			n = n+1
			Na= (Na % Ca) + 1
			d.addRow {{v=n, f=format_device(a) or ''}, Pa[Na], ''}
			Pa[Na]=n 
		end
	end
	
	if s.lua then d.addRow {'Lua', root, s.lua or ''} end	-- Lua code is shown in tool tip

	local chart = gviz.OrgChart()
	local options = {title = 'Scene List', allowHtml = true, height = p.options.height, width = p.options.width}	
	return chart.draw (d, options)		
end

------------------------------------------------------------------------
--
-- System info blog 
--
-- thanks to @parkerc for the idea, and @futzle for the solution, to "watching the LEDs"
-- see: http://forum.micasaverde.com/index.php/topic,25217.msg177527.html#msg177527
-- # ls /sys/devices/platform/leds-gpio/leds/veralite:*/brightness
-- blue:power/brightness, orange:zwave/brightness, red:error/brightness, yellow:lan/brightness
--
local function getSystemFile (fname) 
  local line = ''
  local f = io.open (fname)  
  if f then line = f: read '*a' ; f: close() end
  return line
end

--local function getLED (x) 
--  local  path  = "/sys/devices/platform/leds-gpio/leds/veralite:%s/brightness"
--  local  value = tonumber (getSystemFile (path:format (x)))
--  return value or 0
--end

local function getSysinfo ()
	local x
	local info = {}

	x = getSystemFile "/proc/meminfo"									-- memory use
	for a,b in x:gmatch '(%w+):%s+(%d+)' do	info[a] = {val = b, class = 'memory'} end
  if info.MemTotal and info.MemFree and info.Cached then
    info.MemUsed  = {val = info.MemTotal.val - info.MemFree.val, class = 'memory'} 
    info.MemAvail = {val = info.Cached.val   + info.MemFree.val, class = 'memory'}
  else
    info.MemUsed  = 0
    info.MemAvail = 0
  end
	
	local n = 0
	x = getSystemFile "/proc/loadavg"									-- CPU use
	local label = {"cpuLoad01", "cpuLoad05", "cpuLoad15", "procRunning","procTotal"}
	for y in x:gmatch("[%d.]+") do n = n+1; if label[n] then info[label[n]] = {val = y, class = 'cpu'}; end; end
	
	n = 0
	x = getSystemFile "/proc/uptime"									-- process uptime
	label = {"uptimeTotal", "uptimeIdle"}
	for y in x:gmatch("[%d.]+") do n = n+1; if label[n] then info[label[n]] = {val = y, class = 'time'}; end; end
	info.LuupRestart = {val = os.date("%d-%b-%Y %X", LuupRestart), class = 'time'}
	local now = os.time()
	if info.uptimeTotal then info.VeraReboot = {val = os.date("%d-%b-%Y %X", now - info.uptimeTotal.val), class = 'time'} end
  
--  local power = getLED "blue:power"                 -- LED status lights
--  local zwave = getLED "orange:zwave"
--  local lan   = getLED "yellow:lan"                 -- it's actually green
--  local error = getLED "red:error"
--  info.ZwaveLED     = {val = zwave, class = 'system'}
--  info.NetworkLED   = {val = lan,   class = 'system'}
--  info.ErrorLED     = {val = error, class = 'system'}
--  info.VeraLiteLEDS = {val = error + 2*(lan + 2*(zwave + 2*power)) / 255, class = 'system'}     -- encode into one variable  
  
	return info, now
end
	
local function sysinfoBlog (p)					-- blog to web, three options: sysinfo table, cpu or memory plots 	
	local options = p.options
	local systemInfo = getSysinfo() 		  -- useful info
	local data = gviz.DataTable ()
	local chart
	local title = "System Information"
	local report = p.actions.report
	if report == "system" then							-- tabular parameter listing
		data.addColumn ("string", "Class")
		data.addColumn ("string", "Parameter")
		data.addColumn ("string", "Value")
		for name, x in pairs (systemInfo) do data.addRow {x.class, name, x.val} end
		chart = gviz.Table()
	else													-- graphics CPU or memory over 24 hours	
		data.addColumn ("datetime", "Time")
		if report == "memory" then								-- memory
			title = "System memory available (Mb)"
      data.addColumn ("number", "Avail (5 min avg)")    
      data.addColumn ("number", "Free (5 min avg)")    
			for _, item in pairs (history) do data.addRow {item.time, item.mem, item.free} end
		elseif report == "appmemory" then
      title = "Application memory used (Mb)"
      data.addColumn ("number", "App Memory")    
      for _, item in pairs (history) do data.addRow {item.time, item.app} end
		else	
			title = "CPU load (%)"								-- assume CPU
			data.addColumn ("number", "CPU (5 min avg)")
			for _, item in pairs (history) do data.addRow {item.time, item.cpu} end
		end
		data.sort (1)
		chart = gviz.AreaChart()
	end
	options = {title = title, legend = 'none', height = options.height or 600}	
	return chart.draw (data, options)	
end

------------------------------------------------------------------------
--
-- Battery-powered devices 
-- 

-- blog the list of battery levels to web 
local function batteryBlog (p)
	local options = p.options
	local batterySID = "urn:micasaverde-com:serviceId:HaDevice1"
	local batteryVAR = "BatteryLevel"		
	local batteryLevel
	local data = gviz.DataTable ()
	data.addColumn ("number", "Battery %")
	data.addColumn ("number", "Device No.")
	data.addColumn ("string", "Device Name")
	for deviceNo, d in pairs (luup.devices) do
		batteryLevel = tonumber ((luup.variable_get(batterySID, batteryVAR, deviceNo) ))
	    if batteryLevel then   
			data.addRow {batteryLevel, deviceNo or 0, d.description}
	    end
	end
    data.sort (1)
	local chart = gviz.Table()
	options = {title = 'Battery Levels', height = options.height or 600, width = options.width or 500}	

	return chart.draw (data, options)	
end


------------------------------------------------------------------------
--
-- Generic TreeMap DataTable
-- TreeTable {data = data, root = "Vera", branches = {heirarchyStringList}, leaves = {otherStringList} }
-- expects {_label = x, _size = y, _colour (or _color) = z} in each element of data, although there are defaults

local function TreeTable (tree)
  local N = 0
  local t = gviz.DataTable ()
  local function newLeaf (parent, x, level)
    N = tostring(N + 1)
    local row = {{v = N, f = x._label or N}, parent._id, x._size or 1, x._colour or x._color or 0, level}
    for i, leaf in ipairs (tree.leaves or {}) do row[i+5] = x[leaf] end
    t.addRow (row)
    return {_id = N}
  end

  t.addColumn ("string", "_id")
  t.addColumn ("string", "_parent")
  t.addColumn ("number", "_size")
  t.addColumn ("number", "_colour")
  t.addColumn ("number", "_level")
  
  for _,x in ipairs (tree.leaves or {}) do 
    local y = (tree.data or {})[1] or {}    -- pull type from first element (if there)
    t.addColumn (type(y[x] or "string"), x) 
  end

  local root = newLeaf ({}, {_label = tree.root or '', _size = 0}, 0)          -- tree root

  for _,d in ipairs (tree.data or {}) do
    local branch = root
    for i,f in ipairs (tree.branches or {}) do
      local index = d[f]
      if index then 
        branch[index] = branch[index] or newLeaf (branch, {_label = index, _size = 0}, i)
        branch = branch [index]
      end
    end
    newLeaf (branch, d)
  end
  return t
end

-- Switches - TreeMap for on/off and dimmer switch status
local function switches (p)
  local options = p.options
  local c = ClassLetterToCat['X']
  local service = classes[c].service
  local var = classes[c].variable
  local list = {}
  for devNo, d in pairs(luup.devices) do
    if d.category_num == c then
      local value = get (var, service, devNo)
      if value then
        list[#list+1] = {
          _label = devName(devNo),
          _colour = tonumber (value),
          room = roomName (d.room_num)}
      end
    end
  end
  local tree = TreeTable {data = list, root = "Switches and Dimmers", branches = {"room"}, leaves = {} }
  local chart = gviz.TreeMap()
  options = {
    height = options.height or 500, 
    width = options.width, 
    maxDepth = 2,
    minColorValue = 0, 
    maxColorValue = 1,
    minColor = "DarkGray", 
    maxColor = "Gold",
  } 
  return chart.draw (tree, options) 
end

-- TreeMap representation of devices
local function treeMap (p)
  local options = p.options
  local list = {}
  for deviceNo,d in pairs(luup.devices) do
    local watch = 0
    if watchedDevice[deviceNo] then watch = 1 end 
    local dtype = ((d.device_type or ''): match ":(%w*):%d+$") or ''
--    local room = roomName(d.room_num)
    local name = ("[%03d] %s"): format (deviceNo, d.description or '?')
    list[#list+1] = {
      _label = name,
      _colour = watch,
      room = roomName (d.room_num),
      type = dtype} 
  end
  local tree = TreeTable {data = list, root = "Watched Devices", branches = {"room"}, leaves = {"type"} }
  local chart = gviz.TreeMap()
  options = {
            height = options.height or 500, 
            width = options.width, 
            maxDepth = 2,
            minColorValue = 0, 
            maxColorValue = 1,
            generateTooltip = function () return "showFullTooltip" end,
            minColor = 'LightBlue',
            maxColor = 'Gold',
          } 
  local extras = [[
    function showFullTooltip(row, size, value) {
      return '<div style="background:#fd9; padding:10px">' +
             '<span style="font-family:Courier"><b>' + data.getFormattedValue(row, 0) +
             '</b> ' + '</span><br>' +
       'Type: ' + data.getValue(row, 5) + ' </div>';
  }
  ]]
  return chart.draw (tree, options, extras) 
end

------------------------------------------------------------------------
--
-- geoChart
-- 
local function geoChart (p)
  local data = gviz.DataTable ()
  data.addColumn ("number", "Latitude")
  data.addColumn ("number", "Longitude")
  data.addColumn ("string", "Location")
  data.addRow {luup.latitude or 0, luup.longitude or 0, "You Are Here"}
  local chart = gviz.Chart "GeoChart"
  local options = {title = "Where in the World am I?", 
        displayMode = 'markers', colorAxis = {colors = {'green', 'blue'} },
        height = p.options.height or 700, width = p.options.width or 1000} 
  return chart.draw (data, options) 
end


------------------------------------------------------------------------
--
-- Log/plot of watch/events activity
-- 

local function watchList (p)
	local chart = gviz.Table()
	local options = {allowHtml = true, title = 'Watch List', height = p.options.height or 700, width = p.options.width or 1000}	
	return chart.draw (watching, options)	
end


local function logBlog (p)		 	-- called by both 'log' and 'events' keywords
	local options = p.options
	local function DateTimeMilli(t) return ("%s.%03.0f"): format (os.date("%Y-%m-%d, %H:%M:%S",t), (1000*(t%1)) ) end
	local allEvents = not (p.actions.report == "events")
	local data = gviz.DataTable ()
	data.addColumn ("number", "#")
	data.addColumn ("string", "Date/Time")
	data.addColumn ("string", "Class")
	data.addColumn ("number", "Device No.")
	data.addColumn ("string", "Device Name")
	data.addColumn ("string", "Variable")
  data.addColumn ("string", "Value")
  data.addColumn ("string", "Argument")
	for _, x in pairs (HISTORY) do
	if allEvents or x.symbol == "E" then
			data.addRow {x.id, DateTimeMilli(x.time), x.symbol, x.devNo, devName(x.devNo), x.name, x.var, x.arg} 
		end
	end
	data.sort {column = 1, desc = true}		-- reverse time order for table display
	local chart = gviz.Table()
	options = {
    title = 'Event and Variable Watch log', 
    legend = 'none', 
    height = options.height or 700, 
    width = options.width or 1000
  }	
	return chart.draw (data, options)	
end

local function plotAnything (p)	
	local options = p.options
	local varname = p.actions.variable
	local device = tonumber (p.actions.plot) or 0
	debug ("plot = ".. device)
	local data = gviz.DataTable ()
	data.addColumn ("datetime", "Date/Time")
	data.addColumn ("number", devName (device))
	for _, item in pairs (HISTORY) do
		if item.devNo == device and (not varname or varname == item.name)
		  then data.addRow {item.time, item.var} end
	end
	data.sort (1)
	local chart = gviz.AreaChart()
	options = {title = devName (device), legend = 'none', height = options.height or 600, width = options.width}	
	return chart.draw (data, options)	
end

------------------------------------------------------------------------
--
-- Initialisation 
--

local function start_event_service ()
    Server = socket.bind (IP, PORT, BACKLOG)			-- create server socket and start listening for clients
	if Server then 
	    Server:settimeout (TIMEOUT)						-- don't block for too long!	
	    log ("Server listening on port " .. PORT)
		luup.call_delay ('pollClients', 10, "")			-- start periodic poll for clients
	else
		log "No server socket" 
	end	
	
end

local function start_watch_service ()
  local DevSrvVar = "^(%d+)%.([^%.]+)%.([%w%_]+)"
  local function watch (var, srv, devNo, description, room)
    local exists = get (var, srv, devNo)
    if exists then
      local link = table.concat { -- TODO: is this port_3480 required???
        "<a href='/port_3480/data_request?id=lr_EventWatcher&plot=", devNo, "&variable=", var, "' target='_blank'>", var, "</a>"}
      
      watching.addRow {devNo, devName(devNo), srv: match "%w+$" or '?', link, room} 
      luup.variable_watch ('watchBlog', srv, var, devNo)
      debug ("Watching: [%03d] %s", devNo, description )
      watchedDevice[devNo] = true
    end
  end
	local selected = {}
	local excluded = {}
	
	for i = 0, #classes do     -- going from 0, so can't use ipairs
	  local c = classes[i]
		selected[i] = c.symbol ~= "" and c.service and watchCategories:find (c.symbol) 		-- looking for these specific letters
	end
	watching = gviz.DataTable ()	
	watching.addColumn ("number", "Device No.")
	watching.addColumn ("string", "Device Name")
	watching.addColumn ("string", "Service")
  watching.addColumn ("string", "Variable")
  watching.addColumn ("string", "Room")
    
  if excludeFile ~= '' then
    local f = io.open(excludeFile,'r')
    if f then
      for l in f: lines () do
        local dev, srv, var = l: match (DevSrvVar)
        if var then excluded [table.concat{dev, '.', srv, '.', var}] = true end
      end
      f:close ()
    end
  end
  
	for devNo, d in pairs (luup.devices) do   		-- go through selected devices and set watch
		local n = d.category_num or 0
		local invisible = d.invisible or (d.invisible == '')
    if selected [n] and not invisible then 
			local info = classes[n]
			local room = roomName (d.room_num)
			local services, variables = info.service, info.variable
			if type (services)  ~= "table" then services  = {services} end
			if type (variables) ~= "table" then variables = {variables} end
			for i = 1, #variables do
			  if not excluded [table.concat{devNo, '.', services[i], '.', variables[i]}] then
			    watch (variables[i], services[i], devNo, d.description, room)
			  end
      end
    end
	end
	
	if extrasFile ~= '' then
	  local f = io.open(extrasFile,'r')
	  if f then
	    for l in f: lines () do
	      local dev, srv, var = l: match (DevSrvVar)
	      watch (var, srv, tonumber(dev), l, extrasFile)
	    end
	    f:close ()
	  end
	end
	watching.sort (1)			-- put devices into order
end

function sysinfoPulse ()
	luup.call_delay ('sysinfoPulse', systemPollMinutes * 60, "")						-- revisit every X minutes
	local systemInfo, now = getSysinfo() 	-- useful info
  local AppMemoryUsed =  math.floor(collectgarbage "count")           -- EventWatcher's own memory usage in kB

	local mem, cpu, free
	if systemInfo.MemAvail and systemInfo.cpuLoad05 then	
		mem, cpu, free = systemInfo.MemAvail.val, systemInfo.cpuLoad05.val, systemInfo.MemFree.val
		historyID = historyID % math.floor(24 * 60 / systemPollMinutes) + 1       -- 24 hours worth of history for these plots
		history[historyID] = history[historyID] or {}                   -- reuse table or create new
		local x = history[historyID]
		x.time = now                        -- save new history
    x.app  = AppMemoryUsed/1e3
		x.mem  = mem/1e3
		x.free = free/1e3
		x.cpu  = 100*cpu	
	end
	
  set ("AppMemoryUsed",  AppMemoryUsed)
  set ("MemAvail",  mem)
  set ("MemFree",  free)
	set ("CpuLoad05", cpu)

--  local LED = systemInfo.VeraLiteLEDS.val
--	set ("VeraLiteLEDS", LED)	
--	set ("IconSet", LED % 8)     -- only use lower three bits of status (ie. ignore powerlight) 

--  set ("ZwaveLED",   systemInfo.ZwaveLED.val)
--  set ("NetworkLED", systemInfo.NetworkLED.val)
--  set ("ErrorLED",   systemInfo.ErrorLED.val)
	
	collectgarbage ()
end

function AKB_eventWatcher (_, lul_parameters)
    local html, content
    local p, status = cli.parse (lul_parameters)
	local reports = {devices = deviceBlog, battery = batteryBlog, batteries = batteryBlog, scenes = sceneBlog, 
					system = sysinfoBlog, cpu = sysinfoBlog, memory = sysinfoBlog, appmemory = sysinfoBlog,
					security = securityBlog, environment = enviroBlog, treemap = treeMap, geochart = geoChart,
					log = logBlog, events = logBlog, watch = watchList, codes = codeBlog, switches = switches}

	html = status
	if p then
		local t = os.clock ()
		local a = p.actions
		if a.report and reports[a.report] then 
			html, content = reports[a.report] (p)
		elseif a.plot then 
			html, content = plotAnything (p)
		elseif a.scene then 
			html, content = sceneBlog2 (p)
    elseif a.event then
      event (nil, nil, "User", a.event)    -- user-generated event
      html = "OK"
    elseif a.variable then
      local name,value = a.variable: match "(%w+)%:(.+)"
      if value then
        event (nil, nil, "UserVariable", name, value)    -- user-generated event
        html = "OK"
      else
        html = table.concat{"invalid variable syntax: '", a.variable, "'"}
      end
    end
		t = (os.clock () - t) * 1e3
		debug (("request = %s, CPU = %.3f mS"): format (json.encode(p), t))
	end
	return html
end

-- convert fully qualified domain name (perhaps) into IP
local function dns_translate (addr)
  local info = ''
  local generic = "^(.+):(%d+)$"
  local numeric = "^%d+%.%d+%.%d+%.%d+$"
  local a, port = addr: match (generic)
  if port then
    if a: match (numeric) then
      info = addr                 -- all numeric, return unchanged
    else
      local ip, msg = socket.dns.toip
      if ip then
        info = ip .. ':' .. port
      else
        log ("DNS lookup for SYSLOG failed: " .. msg)
      end
    end
  end
  return info
end


function init (lul_device)
	log 'starting...'
	set ('Version', ABOUT.VERSION: sub(3,-1))							-- save code version number in UI variable
  set ('LuupRestart', os.date("%d-%b-%Y %X", LuupRestart))

  local uptime = ((getSystemFile "/proc/uptime"): match "%d+") or LuupRestart
  local LastReboot = LuupRestart - uptime
  set ('LastReboot', os.date("%d-%b-%Y %X", LastReboot))
 
	EventWatcherID = lul_device

	-- Get user-defined info, creating the variables in the UI with defaults and bounds check if required

  SSL_params.key          = uiVar ("ServerKeyFile",			    "/eventWatcher/EventWatcher.key")
  SSL_params.certificate  = uiVar ("ServerCertificateFile",	"/eventWatcher/EventWatcher.crt")
  syslogInfo              = uiVar ("Syslog",                "")
  logDirectory            = uiVar ("LogDirectory",          "")
  watchCategories			    = uiVar ("WatchCategories",			  "XYSM")					-- watch these by default
	cacheSize               = uiVar ("CacheSize",          1000, 200, 2000)
  debugOn                 = uiVar ("Debug", "0") ~= "0"
  extrasFile              = uiVar ("ExtraVariablesFile",   "")     -- list of extra variables to watch
  excludeFile             = uiVar ("ExcludeVariablesFile", "")     -- list of extra variables to exclude
      
--	gviz.setKey "|itsd>#iuuqt;00xxx/hpphmf/dpn0ktbqj#|ttfuPoMpbeDbmmcbdl|eEbubUbcmf|xDibsuXsbqqfs|uuzqf>#ufyu0kbwbtdsjqu#|hhpphmf|wwjtvbmj{bujpo"

	log 'defining CLI...'
	cli = cli.parser "&report=devices&width=1000"
	cli.parameter ("actions",   "report",	"report",    
		                  {"log","devices","events","scenes","security","environment","battery","batteries", "switches",
		                   "system","cpu","memory","watch","treemap","geochart","appmemory", "codes"}, "report types")
	cli.parameter ("actions", 	"plot", 	  "plot", "number", "plot specific device")
  cli.parameter ("actions",   "scene",    "scene", "number", "show specific scene")
  cli.parameter ("actions",   "event",    "event", "string", "write a user string to the event log")
  cli.parameter ("actions",   "variable", "variable", "string", "write a user variable (name:value) to the event log")

	cli.parameter ("options",	"width",	"width",   "number",    "HTML output width")
	cli.parameter ("options",	"height",	"height",  "number",    "HTML output height")

	for devNo, d in pairs (luup.devices) do				-- categorise the devices
		local c = d.category_num or 0
		classes[c] = classes[c] or {symbol = tostring (c)}
		symbol[devNo] = classes[c].symbol			-- create symbol lookup table
	end
	
  syslogInfo = dns_translate (syslogInfo)
  if syslogInfo ~= '' then
	  log 'Starting UDP syslog service...'	  
    local err
    local syslogTag = luup.devices[EventWatcherID].description or "EventWatcher" 
	  syslog, err = syslog_server (syslogInfo, syslogTag)
	  if not syslog then log ('UDP syslog service error: '..err) end
	end
  
  event (nil, nil, 'Vera', 'RESTART')         -- flag restart event
	
	log 'Starting Event service...'
	start_event_service ()
	log 'Starting Watch service...'
	start_watch_service ()	
	log 'Starting Sysinfo service...'
	sysinfoPulse() 						-- to collect memory and CPU usage, etc...

	luup.register_handler ("AKB_eventWatcher", "EventWatcher")
	log "...initialised"
  set_failure (0)
	return true, "OK", ABOUT.NAME
end

----------

