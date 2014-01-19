var fs = require('fs')
var join = require('path').join
var crypto = require('crypto')

function p () {
  return [].join.call(arguments,'\n')
}

var index = fs.readFileSync(join(__dirname, 'static', 'index.html'))
var bootloader_js
var bootloader = 
  ';(function (exports) {\n'
  + fs.readFileSync(join(__dirname, 'bootloader.js'),'utf8')
  + '\n})({});'

//normal manifest
var manifest = fs.readFileSync(join(__dirname, 'static', 'manifest.appcache'))

// "secure" manifest that never updates.
// this is ALWAYS offline, once the app is "installed"
// to update the bootloader after this, you must update the cache.

var secure = fs.readFileSync(join(__dirname, 'static', 'secure.appcache'))

function sha256 (source) {
  return crypto.createHash('sha256').update(source, 'utf8').digest('hex')
}

module.exports = function (opts) {
  var sources = {}
  var sources_by_name = {}
  var files = JSON.stringify(
      (opts.files || []).map(function (e) {
      var hash = sha256(e.source)
      sources[hash] = e.source
      sources_by_name[e.id] = e.source
      return { id: e.id, hash: hash}
    })
  )

  return function (req, res, next) {
    console.error(req.url)
    if (req.url === '/' || req.url === '/index.html')
      return res.end(index)

    if(req.url === '/manifest.appcache') {
      console.error('manifest.appcache!')
    //  res.setHeader('Expires', 'Thu, 31 Dec 2037 23:55:55 GMT')
      res.setHeader('Content-Type', 'text/cache-manifest')
      return res.end(opts.secure ? secure : manifest)
    }
    if(req.url === '/bootloader.js') {
      res.setHeader('Content-Type', 'application/javascript')
      return res.end(bootloader)
    }
    if(req.url === '/manifest.json') {
//      res.setHeader('Content-Type', 'application/json')
      return res.end(files)
    }
    if(req.url === '/wtf') {
//      res.setHeader('Content-Type', 'application/json')
      return res.end(files)
    }
    var source = sources_by_name[req.url]
    if(source)
      return res.end(source)

    if(next) return next()

    res.statusCode = 404
    res.end('404 Not Found')

  }
}

