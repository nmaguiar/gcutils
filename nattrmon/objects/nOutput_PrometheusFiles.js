// Author: who

/**
 * <odoc>
 * <key>nattrmon.nOutput_PrometheusFiles(aMap)</key>
 * Provide some explanation of the objective of your output object.
 * \
 * On aMap expects:\
 * \
 *    - include        (Array)   Array of regex attributes/warnings to include on output.\
 *    - exclude        (Array)   Array of regex attributes/warnings to exclude from output.\
 *    - considerSetAll (Boolean) Should process attributes/warnings in bulk.\
 * \
 * </odoc>
 */
var nOutput_PrometheusFiles = function (aMap) {
	if (!isNull(aMap) && isMap(aMap)) {
		this.params = aMap
	} else {
		this.params = {}
	}

	this.params.prefix = _$(global.prefix).isString().default("java")

	this.include = aMap.include
	this.exclude = aMap.exclude

	if (isDef(this.include) && !isArray(this.include)) throw "Include needs to be an array"
	if (isDef(this.exclude) && !isArray(this.exclude)) throw "Exclude needs to be an array"
	this.considerSetAll = (isDef(aMap.considerSetAll)) ? aMap.considerSetAll : true

	ow.loadMetrics()

	nOutput.call(this, this.output)
};
inherit(nOutput_PrometheusFiles, nOutput)

nOutput_PrometheusFiles.prototype.output = function (scope, args) {
	if (args.op != "setall" && args.op != "set") return
	if (args.op == "setall" && !this.considerSetAll) return

	var k, v, ch = args.ch
	if (args.op == "set") {
		k = [args.k]
		v = [args.v]
	} else {
		k = args.k
		v = args.v
	}

	v.forEach(value => {
		var isok = isDef(this.include) ? false : true
		var isWarns = (ch == "nattrmon::warnings" || ch == "nattrmon::warnings::buffer")
		var kk = (isWarns) ? value.title : value.name

		if (isDef(this.include)) isok = this.include.filter(inc => kk.match(inc)).length > 0
		if (isDef(this.exclude)) isok = this.exclude.filter(exc => kk.match(exc)).length <= 0
		if (isok) {
			if (isDef(value) && value.name == "gc4pid") {
				var _ts = Math.round(new Date(value.val.__ts).getTime() / 1000)
				delete value.val.__ts
				var _data = ow.metrics.fromObj2OpenMetrics(value.val, this.params.prefix, _ts)

				var _f = io.createTempFile("data", ".openmetrics")
				io.writeFileString(_f, _data)

				var _r = $sh("/usr/bin/openmetrics2prom.sh " + _f).get(0)
				if (_r.exitcode != 0) {
					cprintErr(_r)
				} else {
					printnl(".")
				}
				io.rm(_f)
			}
		}
	})
}