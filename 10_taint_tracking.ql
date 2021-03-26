/**
* @kind path-problem
*/

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(MacroInvocation mi |
            mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
            this = mi.getExpr()
        )
        }
    }
class Config extends TaintTracking::Configuration {
    Config() { this = "NetworkToMemFuncLength" }

    override predicate isSource(DataFlow::Node source) {
        source.asExpr() instanceof NetworkByteSwap
    }
    override predicate isSink(DataFlow::Node sink) {
        exists( FunctionCall call |
            call.getTarget().getName() = "memcpy" and
            sink.asExpr() = call.getArgument(2) and
            not call.getArgument(1).isConstant()
        )// TODO
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
