local mg        = require "moongen"
local memory    = require "memory"
local device    = require "device"


function master()
	local port = 42
	local fgRate = 10
	local bgRate = 40
	local ratio = fgRate / (fgRate + bgRate)
	local test_port = 50
	while mg.running() do
		
		local port = math.random() <= ratio and port or test_port


		print("Selected value: port[%d]", port)
		mg.sleepMillis(500)
	end
	
end
