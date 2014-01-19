var sha256 = require('../sha256')
var assert = require('assert')
var crypto = require('crypto')

function hash (string) {
  return crypto.createHash('sha256').update(string, 'utf8').digest('hex')
}

//var tape = require('tape')

function test(input) {
  var expected = hash(input)
  var actual = sha256(input)
  var _input = JSON.stringify(input)
  if(_input.length <= 32)
    console.error(_input, '->', actual)
  else
    console.error(_input.substring(0, 32)+'(...)', '->', actual)

  assert.equal(actual, expected)
}

var fs   = require('fs')
var join = require('path').join

test('hello')
test('hello aceuharoeuaroechuraoeckabprcboairpciha')
test('')
test(fs.readFileSync(__filename, 'utf8'))
test(fs.readFileSync(join(__dirname, '..', 'sha256.js'), 'utf8'))


