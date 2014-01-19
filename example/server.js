
var http = require('http')
var fs = require('fs')

var offlinify = require('../')({files:[
  {id: '/hello2.js', source: fs.readFileSync(__dirname + '/hello.js', 'utf8'), body: true}
]})

http.createServer(function (req, res) {
  console.error(req.method, req.url)
  offlinify(req, res)
}).listen(8006)
