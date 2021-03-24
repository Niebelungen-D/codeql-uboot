import cpp

from FunctionCall call, Function fc
where call.getTarget() = fc and
    fc.getName() = "memcpy"
select call
