local mainapi = {
    ["Cached"] = {
        ["ScanReports"] = {};
        ["DetectedThreats"] = {};
        ["FlaggedScripts"] = {};
        ["LastScan"] = {};
        ["Statistics"] = {};
    };
    ["git"] = {
        ["project"] = "https://github.com/ProphecySkondo/project";
        ["misc"] = "https://github.com/ProphecySkondo/Misc";
    };
    ["Place"] = game.PlaceId;
    ["Version"] = "3.0.0 - Safe Edition";
    ["Hooks"] = {};
    ["DetectedThreats"] = {};
    ["ScanResults"] = {};
}

getgenv().cloneref = cloneref or function(obj) return obj end
getgenv().saveinstance = saveinstance or function() return "getbetter" end
getgenv().hookmetamethod = hookmetamethod or function() return function() end end
getgenv().hookfunction = hookfunction or function() return function() end end
getgenv().getrawmetatable = getrawmetatable or function(obj) return getmetatable(obj) end
getgenv().setrawmetatable = setrawmetatable or function(obj, mt) return setmetatable(obj, mt) end
getgenv().newcclosure = newcclosure or function(f) return f end
getgenv().islclosure = islclosure or function() return false end
getgenv().iscclosure = iscclosure or function() return true end
getgenv().getcallingscript = getcallingscript or function() return nil end
getgenv().getconnections = getconnections or function() return {} end
getgenv().decompile = decompile or function() return "-- Decompile not available" end
getgenv().getnamecallmethod = getnamecallmethod or function() return "" end

local function safeCall(func, ...)
    local success, result = pcall(func, ...)
    if not success then
        warn("[Advanced Scanner Error]: " .. tostring(result))
        return nil
    end
    return result
end

local function getScriptSource(script)
    if not script or not script:IsA("LuaSourceContainer") then
        return nil
    end
    
    return safeCall(function()
        if script.Source and #script.Source > 0 then
            return script.Source
        else
            local success, decompiled = pcall(decompile, script)
            if success and decompiled then
                return decompiled
            end
        end
        return nil
    end)
end

local function getSafeCallingScript()
    return safeCall(function()
        local calling = getcallingscript()
        if calling then
            return calling, "[Source unavailable for security]"
        end
        return nil, nil
    end)
end

local httpService = game:GetService("HttpService")
local insertService = game:GetService("InsertService")
local logService = game:GetService("LogService")
local runService = game:GetService("RunService")
local starterGui = game:GetService("StarterGui")

local function calculateEntropy(str)
    if not str or #str == 0 then return 0 end
    
    local counts = {}
    for i = 1, #str do
        local char = str:sub(i, i)
        counts[char] = (counts[char] or 0) + 1
    end
    
    local entropy = 0
    local length = #str
    for char, count in pairs(counts) do
        local probability = count / length
        entropy = entropy - (probability * math.log(probability, 2))
    end
    
    return entropy
end

local suspiciousPatterns = {
    critical_backdoors = {
        "require%s*%(%s*[%d]+%s*%)",
        "loadstring%s*%(%s*.+HttpGet",
        "loadstring%s*%(%s*.+HttpPost", 
        "loadstring%s*%(%s*game:HttpGet",
        "loadstring%s*%(%s*game%.HttpGet",
        "getfenv%s*%(%s*%d+%s*%)%.%w+%s*=%s*loadstring",
        "setfenv%s*%(%s*.+loadstring",
        "FireServer%s*%(%s*['\\\"]source['\\\"],",
        "InvokeServer%s*%(%s*['\\\"]source['\\\"],",
        "FireServer%s*%(%s*['\\\"]script['\\\"],",
        "InvokeServer%s*%(%s*['\\\"]script['\\\"],",
    },
    high_risk_infections = {
        "HttpGet.*loadstring",
        "HttpPost.*loadstring", 
        "spawn%s*%(%s*function%s*%(%s*%).*loadstring",
        "coroutine%.wrap%s*%(%s*function%s*%(%s*%).*HttpGet",
        "pcall%s*%(%s*loadstring.*HttpGet",
        "xpcall%s*%(%s*loadstring.*HttpGet",
        "InsertService:LoadAsset%s*%(%s*%d+.*loadstring",
        "require%s*%(%s*InsertService:LoadAsset",
    },
    suspicious_activity = {
        "getrawmetatable.*__namecall",
        "hookmetamethod.*__namecall", 
        "debug%.getregistry%s*%(%s*%)",
        "game%.Players%.LocalPlayer%.UserId",
        "MarketplaceService:GetProductInfo",
        "TeleportService:Teleport%s*%(%s*%d+",
    }
}

local function analyzeScript(source, obj, model)
    local findings = {}
    local riskScore = 0
    
    if not source or type(source) ~= "string" then
        return findings, riskScore
    end
    
    for riskLevel, patterns in pairs(suspiciousPatterns) do
        for _, pattern in ipairs(patterns) do
            local matches = {}
            local success, result = pcall(function()
                for match in source:gmatch(pattern) do
                    table.insert(matches, match)
                end
            end)
            
            if success and #matches > 0 then
                local risk = 0
                if riskLevel == "critical_backdoors" then risk = 25
                elseif riskLevel == "high_risk_infections" then risk = 15
                elseif riskLevel == "suspicious_activity" then risk = 5
                end
                
                riskScore = riskScore + (risk * #matches)
                table.insert(findings, {
                    pattern = pattern,
                    matches = matches,
                    risk = riskLevel,
                    count = #matches
                })
            end
        end
    end
    
    local sourceLength = #source
    local lineCount = select(2, source:gsub('\\n', '\\n')) + 1
    local entropy = calculateEntropy(source)
    
    if entropy > 8.5 then
        riskScore = riskScore + 10
        table.insert(findings, {pattern = "high_entropy", risk = "suspicious_activity", entropy = entropy})
    end
    
    if sourceLength > 25000 and lineCount < 20 then
        riskScore = riskScore + 10
        table.insert(findings, {pattern = "suspicious_compression", risk = "suspicious_activity"})
    end
    
    return findings, riskScore
end

local function attemptServersideAccess()
    local accessResults = {
        methods = {},
        successful = {},
        serverScripts = {},
        restrictedServices = {}
    }
    
    local serversideServices = {
        "ServerScriptService",
        "ServerStorage",
        "DataStoreService",
        "MessagingService",
        "HttpService",
        "TeleportService",
        "BadgeService",
        "GamePassService",
        "MarketplaceService"
    }
    
    local bypassMethods = {
        {
            name = "cloneref_direct",
            func = function(serviceName)
                return cloneref(game:GetService(serviceName))
            end
        },
        {
            name = "getservice_bypass",
            func = function(serviceName)
                local success, service = pcall(function()
                    return game:GetService(serviceName)
                end)
                return success and cloneref(service) or nil
            end
        },
        {
            name = "findservice_method",
            func = function(serviceName)
                local success, service = pcall(function()
                    return game:FindService(serviceName)
                end)
                return success and service and cloneref(service) or nil
            end
        },
        {
            name = "getchildren_search",
            func = function(serviceName)
                for _, child in ipairs(game:GetChildren()) do
                    if child.Name == serviceName or child.ClassName == serviceName then
                        return cloneref(child)
                    end
                end
                return nil
            end
        },
        {
            name = "rawget_bypass",
            func = function(serviceName)
                local success, service = pcall(function()
                    local mt = getrawmetatable(game)
                    local oldNamecall = mt.__namecall
                    mt.__namecall = function(self, ...)
                        local args = {...}
                        if args[1] == "GetService" and args[2] == serviceName then
                            return game[serviceName]
                        end
                        return oldNamecall(self, ...)
                    end
                    local result = game:GetService(serviceName)
                    mt.__namecall = oldNamecall
                    return cloneref(result)
                end)
                return success and service or nil
            end
        }
    }
    
    for _, serviceName in ipairs(serversideServices) do
        for _, method in ipairs(bypassMethods) do
            local success, service = pcall(method.func, serviceName)
            if success and service then
                accessResults.methods[serviceName] = method.name
                accessResults.successful[serviceName] = service
                accessResults.restrictedServices[#accessResults.restrictedServices + 1] = {
                    name = serviceName,
                    method = method.name,
                    accessible = true
                }
                break
            end
        end
        
        if not accessResults.successful[serviceName] then
            accessResults.restrictedServices[#accessResults.restrictedServices + 1] = {
                name = serviceName,
                method = "none",
                accessible = false
            }
        end
    end
    
    if accessResults.successful.ServerScriptService then
        local success, scripts = pcall(function()
            return accessResults.successful.ServerScriptService:GetDescendants()
        end)
        if success then
            for _, obj in ipairs(scripts) do
                if obj:IsA("Script") or obj:IsA("ModuleScript") then
                    accessResults.serverScripts[#accessResults.serverScripts + 1] = {
                        script = obj,
                        name = obj.Name,
                        fullName = obj:GetFullName(),
                        accessible = true
                    }
                end
            end
        end
    end
    
    return accessResults
end

local function getservices()
    local services = {
        Players = cloneref(game:GetService("Players")),
        Lighting = cloneref(game:GetService("Lighting")),
        TweenService = cloneref(game:GetService("TweenService")),
        UserInputService = cloneref(game:GetService("UserInputService")),
        TextService = cloneref(game:GetService("TextService")),
        GuiService = cloneref(game:GetService("GuiService")),
        RunService = cloneref(game:GetService("RunService")),
        HttpService = cloneref(game:GetService("HttpService")),
        ReplicatedStorage = cloneref(game:GetService("ReplicatedStorage")),
        StarterGui = cloneref(game:GetService("StarterGui")),
        CoreGui = cloneref(game:GetService("CoreGui")),
        Workspace = cloneref(game:GetService("Workspace")),
        Debris = cloneref(game:GetService("Debris")),
        StarterPack = cloneref(game:GetService("StarterPack")),
        SoundService = cloneref(game:GetService("SoundService")),
        TeleportService = cloneref(game:GetService("TeleportService")),
        ContextActionService = cloneref(game:GetService("ContextActionService")),
        Selection = cloneref(game:GetService("Selection")),
        Chat = cloneref(game:GetService("Chat")),
        AssetService = cloneref(game:GetService("AssetService")),
        InsertService = cloneref(game:GetService("InsertService")),
        UserGameSettings = cloneref(game:GetService("UserGameSettings")),
        Teams = cloneref(game:GetService("Teams")),
    }
    
    local serversideAccess = attemptServersideAccess()
    for serviceName, service in pairs(serversideAccess.successful) do
        services[serviceName] = service
    end
    
    mainapi.Cached.ServersideAccess = serversideAccess
    
    return services
end

local function getallscripts()
    local scripts = {}
    for _, obj in ipairs(game:GetDescendants()) do
        if obj:IsA("LocalScript") or obj:IsA("Script") then
            local success, source = pcall(decompile, obj)
            if success and source then
                scripts[#scripts+1] = {Instance = obj, Source = source}
            end
        end
    end
    return scripts
end

local function getallmodels()
    local flagged = {}
    for _, model in ipairs(game:GetDescendants()) do
        if model:IsA("Model") then
            for _, obj in ipairs(model:GetDescendants()) do
                if obj:IsA("Script") or obj:IsA("LocalScript") then
                    local success, source = pcall(decompile, obj)
                    if success and source then
                        local findings, riskScore = analyzeScript(source, obj, model)
                        if riskScore >= 15 then
                            flagged[#flagged + 1] = {
                                Model = model,
                                Script = obj,
                                Findings = findings,
                                RiskScore = riskScore,
                                Severity = riskScore >= 40 and "CRITICAL" or riskScore >= 25 and "HIGH" or "MEDIUM"
                            }
                        end
                    end
                end
            end
        end
    end
    return flagged
end

local config
local remoteInfo = {
    foundBackdoor = false,
    instance = nil,
    args = {"source"},
    argSrcIndex = 1,
    srcFunc = nil,
    redirection = {
        __testver = false,
        initialized = false,
    },
}

local function get_thread_identity()
    if syn and syn.get_thread_identity then
        return syn.get_thread_identity()
    elseif getthreadidentity then
        return getthreadidentity()
    else
        return 7
    end
end

local function set_thread_identity(id)
    if syn and syn.set_thread_identity then
        syn.set_thread_identity(id)
    elseif setthreadidentity then
        setthreadidentity(id)
    end
end

local _getDebugIdFunc = clonefunction(game.GetDebugId)
local function getDebugId(inst)
    local old = get_thread_identity()
    set_thread_identity(7)
    local id = _getDebugIdFunc(inst)
    set_thread_identity(old)
    return id
end

local scanStats = {
    scriptsScanned = 0,
    threatsFound = 0,
    startTime = 0,
    endTime = 0
}

local function newNotification(txt)
    return starterGui:SetCore("SendNotification", {Title = "[Advanced Backdoor Scanner]", Text = txt, Duration = 5 + (#txt/80)})
end

local function generateReport(flaggedScripts)
    local report = {
        timestamp = os.date("%c"),
        scanDuration = scanStats.endTime - scanStats.startTime,
        scriptsScanned = scanStats.scriptsScanned,
        threatsFound = scanStats.threatsFound,
        flaggedScripts = flaggedScripts,
        summary = {}
    }
    
    local criticalCount = 0
    local highCount = 0
    local mediumCount = 0
    
    for _, script in ipairs(flaggedScripts) do
        if script.Severity == "CRITICAL" then
            criticalCount = criticalCount + 1
        elseif script.Severity == "HIGH" then
            highCount = highCount + 1
        elseif script.Severity == "MEDIUM" then
            mediumCount = mediumCount + 1
        end
    end
    
    report.summary = {
        critical = criticalCount,
        high = highCount,
        medium = mediumCount
    }
    
    return report
end

local function getFullNameOf(obj)
    if not obj then return "nil" end
    local parts = {}
    local current = obj
    while current and current ~= game do
        local name = current.Name
        if name then
            if string.match(name, "^[%a_][%w_]*$") then
                table.insert(parts, 1, name)
            else
                table.insert(parts, 1, "[" .. string.format("%q", name) .. "]")
            end
        else
            break
        end
        current = current.Parent
    end
    return table.concat(parts, ".")
end

local function isRemoteAllowed(obj)
    if not (typeof(obj) == "Instance" and (obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction"))) then return false end
    for _, filter in pairs(config.remoteFilters) do
        if filter and not filter(obj) then return false end
    end
    return true
end

local function getRemotes()
    local remotes = {}
    local instancesList = {}
    for _, inst in ipairs(game:GetDescendants()) do table.insert(instancesList, inst) end
    if getinstances then
        for _, inst in ipairs(getinstances()) do table.insert(instancesList, inst) end
    end
    for _, obj in ipairs(instancesList) do
        if isRemoteAllowed(obj) then
            local id = getDebugId(obj)
            remotes[id] = obj
        end
    end
    return remotes
end

local function execScript(source, noRedirect)
    if not remoteInfo.foundBackdoor then return end
    local remoteFunc = remoteInfo.instance and (remoteInfo.instance:IsA("RemoteEvent") and remoteInfo.instance.FireServer or remoteInfo.instance:IsA("RemoteFunction") and remoteInfo.instance.InvokeServer)
    if config.redirectRemote and remoteInfo.redirection.initialized and not noRedirect then
    else
        if remoteInfo.srcFunc then source = remoteInfo.srcFunc(source) end
        remoteInfo.args[remoteInfo.argSrcIndex] = source
    end
    task.spawn(remoteFunc, remoteInfo.instance, unpack(remoteInfo.args))
end

local function onAttached(params)
    if remoteInfo.foundBackdoor and remoteInfo.instance then return end
    remoteInfo.foundBackdoor = true
    for k,v in pairs(params) do remoteInfo[k] = v end
    newNotification("Attached!")
end

local function createReadableReport(report, flaggedModels)
    local lines = {}
    
    table.insert(lines, "═══════════════════════════════════════════════════")
    table.insert(lines, "🛡️  ROBLOX BACKDOOR SCANNER REPORT")
    table.insert(lines, "═══════════════════════════════════════════════════")
    table.insert(lines, "")
    
    table.insert(lines, "📊 SCAN INFORMATION:")
    table.insert(lines, "  • Timestamp: " .. report.timestamp)
    table.insert(lines, "  • Place ID: " .. mainapi.Place)
    table.insert(lines, "  • Scan Duration: " .. string.format("%.2f seconds", report.scanDuration))
    table.insert(lines, "  • Scripts Scanned: " .. report.scriptsScanned)
    table.insert(lines, "  • Threats Found: " .. report.threatsFound)
    table.insert(lines, "")
    
    table.insert(lines, "📈 THREAT SUMMARY:")
    table.insert(lines, "  🔴 Critical: " .. report.summary.critical)
    table.insert(lines, "  🟠 High: " .. report.summary.high)
    table.insert(lines, "  🟡 Medium: " .. report.summary.medium)
    table.insert(lines, "")
    
    if mainapi.Cached.ServersideAccess then
        local access = mainapi.Cached.ServersideAccess
        table.insert(lines, "🔓 SERVERSIDE ACCESS RESULTS:")
        
        local successCount = 0
        for _, service in ipairs(access.restrictedServices) do
            if service.accessible then
                successCount = successCount + 1
                table.insert(lines, "  ✅ " .. service.name .. " (via " .. service.method .. ")")
            else
                table.insert(lines, "  ❌ " .. service.name .. " (blocked)")
            end
        end
        
        if #access.serverScripts > 0 then
            table.insert(lines, "  📜 Server Scripts Found: " .. #access.serverScripts)
            for i, script in ipairs(access.serverScripts) do
                if i <= 5 then
                    table.insert(lines, "    • " .. script.fullName)
                end
            end
            if #access.serverScripts > 5 then
                table.insert(lines, "    • ... and " .. (#access.serverScripts - 5) .. " more")
            end
        end
        
        table.insert(lines, "  🎯 Access Success Rate: " .. successCount .. "/" .. #access.restrictedServices)
        table.insert(lines, "")
    end
    
    if #flaggedModels == 0 then
        table.insert(lines, "✅ NO THREATS DETECTED - System is secure!")
    else
        table.insert(lines, "🚨 DETECTED THREATS:")
        table.insert(lines, "")
        
        for i, threat in ipairs(flaggedModels) do
            local severityIcon = threat.Severity == "CRITICAL" and "🔴" or threat.Severity == "HIGH" and "🟠" or "🟡"
            
            table.insert(lines, string.format("[%d] %s %s THREAT", i, severityIcon, threat.Severity))
            table.insert(lines, "  📍 Location: " .. getFullNameOf(threat.Script))
            table.insert(lines, "  📄 Script Type: " .. threat.Script.ClassName)
            table.insert(lines, "  ⚠️ Risk Score: " .. threat.RiskScore)
            
            if threat.Findings and #threat.Findings > 0 then
                table.insert(lines, "  🔍 Detected Patterns:")
                for _, finding in ipairs(threat.Findings) do
                    if finding.pattern == "high_entropy" then
                        table.insert(lines, "    • High Entropy (Obfuscation): " .. string.format("%.2f", finding.entropy or 0))
                    elseif finding.pattern == "suspicious_compression" then
                        table.insert(lines, "    • Suspicious Compression Detected")
                    else
                        table.insert(lines, "    • " .. finding.pattern .. " (" .. finding.count .. " matches)")
                        if finding.matches and #finding.matches > 0 then
                            for j, match in ipairs(finding.matches) do
                                if j <= 3 then
                                    table.insert(lines, "      ↳ " .. string.sub(match, 1, 50) .. (string.len(match) > 50 and "..." or ""))
                                end
                            end
                            if #finding.matches > 3 then
                                table.insert(lines, "      ↳ ... and " .. (#finding.matches - 3) .. " more")
                            end
                        end
                    end
                end
            end
            table.insert(lines, "")
        end
    end
    
    table.insert(lines, "═══════════════════════════════════════════════════")
    table.insert(lines, "Generated by Advanced Roblox Backdoor Scanner v" .. mainapi.Version)
    table.insert(lines, "═══════════════════════════════════════════════════")
    
    return table.concat(lines, "\r\n")
end

local function storeCachedResults(report, flaggedModels, readableReport)
    local scanData = {
        timestamp = report.timestamp,
        placeId = mainapi.Place,
        duration = report.scanDuration,
        scriptsScanned = report.scriptsScanned,
        threatsFound = report.threatsFound,
        summary = report.summary,
        threats = {},
        rawReport = report,
        readableReport = readableReport
    }
    
    for _, threat in ipairs(flaggedModels) do
        table.insert(scanData.threats, {
            severity = threat.Severity,
            location = getFullNameOf(threat.Script),
            scriptType = threat.Script.ClassName,
            riskScore = threat.RiskScore,
            patterns = {},
            scriptName = threat.Script.Name
        })
        
        local threatIndex = #scanData.threats
        for _, finding in ipairs(threat.Findings or {}) do
            table.insert(scanData.threats[threatIndex].patterns, {
                pattern = finding.pattern,
                risk = finding.risk,
                count = finding.count,
                examples = finding.matches
            })
        end
    end
    
    mainapi.Cached.LastScan = scanData
    table.insert(mainapi.Cached.ScanReports, scanData)
    
    if #mainapi.Cached.ScanReports > 10 then
        table.remove(mainapi.Cached.ScanReports, 1)
    end
    
    mainapi.Cached.Statistics = {
        totalScans = #mainapi.Cached.ScanReports,
        lastScanTime = report.timestamp,
        totalThreatsFound = 0
    }
    
    for _, scanReport in ipairs(mainapi.Cached.ScanReports) do
        mainapi.Cached.Statistics.totalThreatsFound = mainapi.Cached.Statistics.totalThreatsFound + scanReport.threatsFound
    end
    
    if setclipboard then
        setclipboard(readableReport)
        newNotification("📋 Scan report copied to clipboard!")
    else
        warn("📋 Clipboard not available - Results stored in mainapi.Cached")
    end
end

local function performAdvancedScan()
    scanStats.startTime = tick()
    newNotification("🔍 Starting advanced security scan...")
    
    local allScripts = getallscripts()
    local flaggedModels = getallmodels()
    local totalThreats = #flaggedModels
    
    scanStats.scriptsScanned = #allScripts
    scanStats.threatsFound = totalThreats
    scanStats.endTime = tick()
    
    local report = generateReport(flaggedModels)
    local readableReport = createReadableReport(report, flaggedModels)
    
    storeCachedResults(report, flaggedModels, readableReport)
    
    warn("📊 Scan completed - Check clipboard or mainapi.Cached for results")
    
    if totalThreats > 0 then
        newNotification(string.format("⚠️ SECURITY ALERT: %d threats detected!", totalThreats))
    else
        newNotification("✅ No threats detected. System is secure.")
    end
    
    return report
end

local function startRealTimeMonitoring()
    local monitoring = true
    local lastScan = tick()
    
    task.spawn(function()
        while monitoring and config.realTimeMonitoring do
            if tick() - lastScan > config.scanInterval then
                performAdvancedScan()
                lastScan = tick()
            end
            task.wait(5)
        end
    end)
    
    return function() monitoring = false end
end

local function scanBackdoors()
    if remoteInfo.foundBackdoor then return end
    local remotes = getRemotes()
    for id, remote in pairs(remotes) do
        if remoteInfo.foundBackdoor then break end
        newNotification("Scanning remote: "..getFullNameOf(remote))
        task.wait()
    end
    
    if not remoteInfo.foundBackdoor then
        newNotification("✅ No backdoored remote(s) found!")
        warn("Scan completed at: "..os.date("%c").." - No threats detected.")
        performAdvancedScan()
    end
end

config = {
    remoteFilters = {},
    redirectRemote = false,
    webhookUrl = nil,
    realTimeMonitoring = true,
    scanInterval = 30,
    detectionThreshold = 10
}

mainapi["scanBackdoors"] = scanBackdoors
mainapi["execScript"] = execScript
mainapi["onAttached"] = onAttached
mainapi["getRemotes"] = getRemotes
mainapi["getallmodels"] = getallmodels
mainapi["getallscripts"] = getallscripts
mainapi["getservices"] = getservices
mainapi["performAdvancedScan"] = performAdvancedScan
mainapi["startRealTimeMonitoring"] = startRealTimeMonitoring
mainapi["generateReport"] = generateReport
mainapi["config"] = config

local function setupAdvancedHooks()
    local originalMetas = {}
    
    originalMetas.__index = hookmetamethod(game, "__index", newcclosure(function(obj, key)
        local calling, source = getSafeCallingScript()
        if calling and source then
            if source:find("require%s*%(%s*%d+%s*%)") or source:find("loadstring") then
                mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                    type = "metamethod_hook",
                    method = "__index",
                    script = calling,
                    timestamp = tick(),
                    severity = "HIGH"
                }
                safeCall(function() newNotification("🔴 METAMETHOD HOOK DETECTED: __index manipulation!") end)
            end
        end
        return originalMetas.__index(obj, key)
    end))
    
    originalMetas.__newindex = hookmetamethod(game, "__newindex", newcclosure(function(obj, key, value)
        local calling, source = getSafeCallingScript()
        if calling and source then
            if source:find("getfenv") or source:find("setfenv") or source:find("rawset") then
                mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                    type = "metamethod_hook",
                    method = "__newindex",
                    script = calling,
                    timestamp = tick(),
                    severity = "CRITICAL"
                }
                safeCall(function() newNotification("🔴 CRITICAL: __newindex manipulation detected!") end)
            end
        end
        return originalMetas.__newindex(obj, key, value)
    end))
    
    originalMetas.__namecall = hookmetamethod(game, "__namecall", newcclosure(function(obj, ...)
        local method = getnamecallmethod()
        local calling, source = getSafeCallingScript()
        
        if method == "HttpGet" or method == "HttpPost" or method == "GetObjects" then
            if calling and source then
                mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                    type = "http_call",
                    method = method,
                    script = calling,
                    args = {...},
                    timestamp = tick(),
                    severity = "HIGH"
                }
                safeCall(function() newNotification("🟡 HTTP Call detected: " .. method) end)
            end
        elseif method == "FireServer" or method == "InvokeServer" then
            if calling and source then
                if source:find("loadstring") or source:find("require%s*%(%s*%d+%s*%)") then
                    mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                        type = "remote_execution",
                        method = method,
                        script = calling,
                        remote = obj,
                        timestamp = tick(),
                        severity = "CRITICAL"
                    }
                    safeCall(function() newNotification("🔴 BACKDOOR DETECTED: Remote execution with suspicious code!") end)
                end
            end
        end
        
        return originalMetas.__namecall(obj, ...)
    end))
    
    mainapi.Hooks = originalMetas
end

local function setupFunctionHooks()
    safeCall(function()
        if loadstring then
            local originalLoadstring = loadstring
            loadstring = newcclosure(function(source, ...)
                safeCall(function()
                    local calling, scriptSource = getSafeCallingScript()
                    if calling and scriptSource then
                        mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                            type = "loadstring_call",
                            script = calling,
                            source = source,
                            timestamp = tick(),
                            severity = "HIGH"
                        }
                        safeCall(function() newNotification("🔴 LOADSTRING DETECTED: Potential code injection!") end)
                    end
                end)
                return originalLoadstring(source, ...)
            end)
        end
        
        if require then
            local originalRequire = require
            require = newcclosure(function(asset, ...)
                safeCall(function()
                    if type(asset) == "number" or (type(asset) == "string" and tonumber(asset)) then
                        local calling, scriptSource = getSafeCallingScript()
                        if calling then
                            mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                                type = "suspicious_require",
                                script = calling,
                                asset = asset,
                                timestamp = tick(),
                                severity = "CRITICAL"
                            }
                            safeCall(function() newNotification("🔴 SUSPICIOUS REQUIRE: Asset ID " .. tostring(asset)) end)
                        end
                    end
                end)
                return originalRequire(asset, ...)
            end)
        end
        
        if getfenv then
            local originalGetfenv = getfenv
            getfenv = newcclosure(function(...)
                safeCall(function()
                    local calling, scriptSource = getSafeCallingScript()
                    if calling then
                        mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                            type = "getfenv_call",
                            script = calling,
                            timestamp = tick(),
                            severity = "HIGH"
                        }
                        safeCall(function() newNotification("🟡 GETFENV detected: Environment manipulation") end)
                    end
                end)
                return originalGetfenv(...)
            end)
        end
        
        if setfenv then
            local originalSetfenv = setfenv
            setfenv = newcclosure(function(...)
                safeCall(function()
                    local calling, scriptSource = getSafeCallingScript()
                    if calling then
                        mainapi.RealTimeDetections[#mainapi.RealTimeDetections + 1] = {
                            type = "setfenv_call",
                            script = calling,
                            timestamp = tick(),
                            severity = "CRITICAL"
                        }
                        safeCall(function() newNotification("🔴 SETFENV detected: Critical environment manipulation!") end)
                    end
                end)
                return originalSetfenv(...)
            end)
        end
    end)
end

local function monitorConnections()
    local suspiciousConnections = {}
    
    local function checkConnection(signal, connection)
        safeCall(function()
            if connection and connection.Function then
                local func = connection.Function
                if islclosure(func) then
                    local info = safeCall(function() return debug.getinfo(func, "S") end)
                    if info and info.source then
                        local source = info.source
                        if source:find("loadstring") or source:find("require%s*%(%s*%d+%s*%)") then
                            suspiciousConnections[#suspiciousConnections + 1] = {
                                signal = signal,
                                connection = connection,
                                timestamp = tick(),
                                severity = "HIGH"
                            }
                            safeCall(function() newNotification("🟡 Suspicious connection detected on " .. tostring(signal)) end)
                        end
                    end
                end
            end
        end)
    end
    
    safeCall(function()
        for _, obj in ipairs(game:GetDescendants()) do
            if obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction") or obj:IsA("BindableEvent") then
                local signal = obj.OnServerEvent or obj.OnClientEvent or obj.Event
                if signal then
                    local connections = safeCall(function() return getconnections(signal) end) or {}
                    for _, conn in ipairs(connections) do
                        checkConnection(obj, conn)
                    end
                end
            end
        end
    end)
    
    return suspiciousConnections
end

local function checkMetatableIntegrity()
    local compromised = {}
    local gameMetatable = getrawmetatable(game)
    
    if gameMetatable then
        local expectedMethods = {"__index", "__newindex", "__namecall"}
        for _, method in ipairs(expectedMethods) do
            if gameMetatable[method] and not iscclosure(gameMetatable[method]) then
                compromised[#compromised + 1] = {
                    object = "game",
                    method = method,
                    compromised = true,
                    timestamp = tick()
                }
                newNotification("🔴 METATABLE COMPROMISE: game." .. method .. " has been hooked!")
            end
        end
    end
    
    return compromised
end

local function initializeSafeSystems()
    task.spawn(function()
        while config.realTimeMonitoring do
            safeCall(function()
                local report = performAdvancedScan()
                if report.summary.critical > 0 then
                    newNotification("🚨 CRITICAL THREATS DETECTED!")
                end
            end)
            task.wait(config.scanInterval or 30)
        end
    end)
    
    newNotification("🛡️ Safe scanner initialized! Use .enableAdvancedHooks() for real-time protection.")
end

local function enableAdvancedHooks()
    warn("[SCANNER WARNING] Enabling advanced hooks. This may cause instability.")
    
    safeCall(function()
        setupAdvancedHooks()
        setupFunctionHooks()
        newNotification("⚠️ Advanced hooks enabled. Monitor for stability issues.")
    end)
end

mainapi["setupAdvancedHooks"] = setupAdvancedHooks
mainapi["setupFunctionHooks"] = setupFunctionHooks
mainapi["monitorConnections"] = monitorConnections
mainapi["checkMetatableIntegrity"] = checkMetatableIntegrity
mainapi["initializeSafeSystems"] = initializeSafeSystems
mainapi["enableAdvancedHooks"] = enableAdvancedHooks

initializeSafeSystems()

return mainapi
