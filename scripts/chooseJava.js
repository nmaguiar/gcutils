var params = processExpr(" ")

ow.loadJava()
ow.loadFormat()

var o = io.listFiles("/proc").files

o = o.filter(r => isNumber(r.filename) && r.isDirectory)
o = o.map(r => io.listFiles(r.filepath + "/root/tmp").files.filter(s => s.isDirectory && s.filename.startsWith("hsperfdata")).map(t => t.filepath) )
o = $path($path(o, "[][]").map(r => io.listFiles(r).files).filter(r => r.length > 0), "[][]").map(r => r.filepath)
o = o.filter(r => r.match(/\/proc\/(\d+)\/.+\/\1$/) )

var _res = o.map(r => {
    var j = ow.java.parseHSPerf(r).sun.rt.javaCommand
    return { pid: r.match(/\/proc\/(\d+)\/.+\/\1$/)[1], cmd: j }
})

__conConsole = true 
__initializeCon()
__con.getTerminal().settings.set("-icanon min 1 -echo")
var res = askChoose("Choose a Java process: ", _res.filter(r => r.pid != getPid()).map(r => r.pid + ": " + r.cmd.substring(0, 50)) )
__con.getTerminal().settings.set("icanon echo")

if (isDef(params.file)) 
    io.writeFileString(params.file, _res[res].pid)
else 
    print(_res[res].pid)