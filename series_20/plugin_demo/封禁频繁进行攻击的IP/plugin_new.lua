local safeline = require "safeline"

match = {
    ip      = "0.0.0.0/0",
    host    = ".+",
    urlpath = ".+",
    target  = safeline.MATCH_TARGET_DETECT,
}

function clear(ip)
    safeline.db_del(safeline.DB_LOCAL, ip..":ts")
    safeline.db_del(safeline.DB_LOCAL, ip..":attack")
end

function reset(log, ip)
    safeline.db_set(safeline.DB_LOCAL, ip..":ts", tostring(log.timestamp))
    safeline.db_add(safeline.DB_LOCAL, ip..":attack", log.risk_level)
end

function process(ip, host, urlpath)
    local attack_limit = 10    -- 累积攻击次数
    local check_dur = 60 *10   -- 攻击次数统计时间，单位秒
    local duratio = 60 * 30    -- 封禁时间，单位秒
    local ban_risk = 1         -- 需要统计的威胁等级，3 代表只统计高危，2 代表统计中高危，1代表统计中高低危

    local log = safeline.get_detailed_info()

    if log.risk_level < ban_risk then
        return
    end

    local ts = safeline.db_get(safeline.DB_LOCAL, ip..":ts")

    if ts == nil then
        -- first time record
        reset(log, ip)
    else
        if log.timestamp - tonumber(ts) < check_dur then
            local attack = safeline.db_get(safeline.DB_LOCAL, ip..":attack")
            if attack ~= nil and tonumber(attack) >= attack_limit then
                -- exceed attack limit
                local key = {ip  = ip}
                safeline.action_ban(safeline.ACTION_SCOPE_ALL, key, duratio)
                safeline.log("信息", "因频繁触发攻击规则, 以下IP被封: "..ip)
                clear(ip)
            else
                -- normal record
        		safeline.db_add(safeline.DB_LOCAL, ip..":attack", log.risk_level)
            end
        else
            -- exceed check duration, reset record
            clear(ip)
            reset(log, ip)
        end
    end
end

safeline.register(safeline.TYPE_PROCESS, match, process)
