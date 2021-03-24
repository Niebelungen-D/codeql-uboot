import cpp

from MacroInvocation mi
where mi.getMacroName().regexpMatch("ntoh(s|l|ll)")
select mi
