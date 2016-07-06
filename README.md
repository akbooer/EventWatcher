# EventWatcher
Web, file, and syslog reporting of Vera HA Controller variables, events, devices, scenes, and more.

The EventWatcher plugin does these things:

* watches selected device categories and logs key variable changes
* generates reports and plots of current device variable configurations and values
* lists scene configurations including schedules, triggers, actioned devices, and
Lua code
* graphic plots of CPU usage and memory resources
The whole point is to address the needs of those who want:
* access to events locally and independently of Mios.com
* much simpler and less cluttered logging
* simple reporting of Vera configuration and device status

EventWatcher is NOT a tool for detailed analysis of the Vera log, but contains higher level, and briefer, 
information which may be useful for analysing the operation of Vera scenes and devices. 
It’s also NOT a replacement for dataMine, since it doesn’t provide any analysis tools for long-term archived data.

EventWatcher responds to a variety of HTTP requests returning dynamic server pages for different report formats. 
All WATCH-ed variables and Vera notification EVENTS are stored in a memory buffer 
(holding, by default, the last 1000 events)available for ana- lysis, and also, optionally, 
written out to a weekly file (ideally stored on an external stor- age device like a USB or NAS.)
