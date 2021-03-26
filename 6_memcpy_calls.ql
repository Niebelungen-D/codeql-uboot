import cpp

from FunctionCall call, Function f
where call.getTarget() = f and
    f.getName() = "memcpy"
select f
