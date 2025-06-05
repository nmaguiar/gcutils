// Author: who

/**
 * <odoc>
 * <key>nattrmon.nInput_CollectAllGC(aMap)</key>
 * Provide some explanation of the objective of your input object.
 * On aMap expects:\
 * \
 *    - someVariable (Type) Description of variable.\
 *    - attrTemplate (String) The attribute template where to store the result.\
 * \
 * </odoc>
 */
var nInput_CollectAllGC = function(aMap) {
    if (!isNull(aMap) && isMap(aMap)) {
        this.params = aMap
    } else {
        this.params = {}
    }

    this.params.pid  = _$(global.pid, "pid").isNumber().default(__)
    this.params.path = _$(global.pidpath, "pidpath").isString().default(__)
    if (isDef(this.params.pid)) log("nInput_CollectAllGC | pid = " + this.params.pid)
    if (isDef(this.params.path)) log("nInput_CollectAllGC | path = " + this.params.path)

    if (isUnDef(this.params.attrTemplate)) this.params.attrTemplate = "gc4pid"
    ow.loadJava()

    nInput.call(this, this.input)
}
inherit(nInput_CollectAllGC, nInput)

/**
 * <odoc>
 * <key>nattrmon.nInput_CollectAllGC.get() : Map</key>
 * Get the current GC information.
 * </odoc>
 */
nInput_CollectAllGC.prototype._get = function(data) {
    data.__ts = new Date()

    var r = { max: 0, total: 0, used: 0, free: 0 }
    data.sun.gc.generation.forEach(gen => {
        gen.space.forEach(space => {
            r.max = (r.max < Number(space.maxCapacity)) ? Number(space.maxCapacity) : r.max
            r.used = r.used + Number(space.used)
            r.total = isNumber(space.capacity) ? r.total + Number(space.capacity) : r.total
            data.sun.gc["__percUsed_" + space.name] = (100 * space.used) / space.capacity
        })
    })
    data.sun.gc.__percUsed_meta = (100 * data.sun.gc.metaspace.used) / data.sun.gc.metaspace.capacity
    data.sun.gc.__percUsed_ccs = (100 * data.sun.gc.compressedclassspace.used) / data.sun.gc.compressedclassspace.capacity

    // Java 8
    var _ygc = $from(data.sun.gc.collector).equals("name", "PSScavenge").at(0)
    data.sun.gc.__ygc = isDef(_ygc) ? Number(_ygc.invocations) : 0
    data.sun.gc.__ygct = isDef(_ygc) ? Number(_ygc.time / 1000000000) : 0

    var _fgc = $from(data.sun.gc.collector).equals("name", "PSParallelCompact").orEquals("name", "").at(0)
    data.sun.gc.__fgc = isDef(_fgc) ? Number(_fgc.invocations) : 0
    data.sun.gc.__fgct = isDef(_fgc) ? Number(_fgc.time / 1000000000) : 0

    data.sun.gc.__gct = $from(data.sun.gc.collector).sum("time") / 1000000000

    data.java.__mem = {
        total: r.total,
        used: r.used,
        free: r.total - r.used,
        metaMax: data.sun.gc.metaspace.maxCapacity,
        metaTotal: data.sun.gc.metaspace.capacity,
        metaUsed: data.sun.gc.metaspace.used,
        metaFree: data.sun.gc.metaspace.capacity - data.sun.gc.metaspace.used
    }

    return data
}

nInput_CollectAllGC.prototype.get = function() {
    var _path = isDef(this.params.path) ? this.params.path : $from(ow.java.getLocalJavaPIDs()).equals("pid", this.params.pid).at(0)
    if (isDef(_path) && isDef(_path.path)) _path = _path.path
    if (isUnDef(_path) || !io.fileExists(_path)) throw "hsperfdata not found!"
    var res = this._get(ow.java.parseHSPerf(_path))

    return res
}

nInput_CollectAllGC.prototype.input = function(scope, args) {
    var ret = {}

    /*ret[templify(this.params.attrTemplate)] = {
        something: true
    };*/

	if (isDef(this.params.chKeys)) {
        var arr = []
        $ch(this.params.chKeys).forEach((k, v) => {
            arr.push(this.get(merge(k, v)))
        })
        ret[templify(this.params.attrTemplate, this.params)] = arr
    } else {
        ret[templify(this.params.attrTemplate, this.params)] = this.get()
    }

    return ret
}
