local log = {
   usecolor = true;
   level    = "warn";
   output   = io.stderr;
}

local modes = {
   { name = "trace", color = "\27[34m" };
   { name = "debug", color = "\27[36m" };
   { name = "info" , color = "\27[32m" };
   { name = "warn" , color = "\27[33m" };
   { name = "error", color = "\27[31m" };
   { name = "fatal", color = "\27[35m" };
}

local debug_getinfo = debug.getinfo
local string_format = string.format
local os_date = os.date
local _type = type

local msgformat = "%s[%-6s%s]%s %s:%d: %s\n"
local levels = {}

for i, v in ipairs(modes) do
   levels[v.name] = i
   local name_upper = v.name:upper()

   log[v.name] = function (fmtstring, arg1, ...)
      if i < levels[log.level] then
         return
      end

      local message
      if _type(arg1) == "function" then
         -- Arguments are retrieved by invoking the function
         message = string_format(fmtstring, arg1())
      else
         message = string_format(fmtstring, arg1, ...)
      end

      local dinfo = debug_getinfo(2, "Sl")

      log.output:write(string_format(msgformat,
                                     log.usecolor and v.color or "",
                                     name_upper,
                                     os_date("%H:%M:%S"),
                                     log.usecolor and "\27[0m" or "",
                                     dinfo.short_src,
                                     dinfo.currentline,
                                     message))
      log.output:flush()
   end
end

return log
