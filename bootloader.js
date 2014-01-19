/**
 * A JavaScript implementation of the Secure Hash Algorithm, SHA-256, as defined
 * in FIPS 180-2
 * Version 2.2-beta Copyright Angel Marin, Paul Johnston 2000 - 2009.
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 *
 */

var safe_add = function(x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
};

var S = function(X, n) {
  return (X >>> n) | (X << (32 - n));
};

var R = function(X, n) {
  return (X >>> n);
};

var Ch = function(x, y, z) {
  return ((x & y) ^ ((~x) & z));
};

var Maj = function(x, y, z) {
  return ((x & y) ^ (x & z) ^ (y & z));
};

var Sigma0256 = function(x) {
  return (S(x, 2) ^ S(x, 13) ^ S(x, 22));
};

var Sigma1256 = function(x) {
  return (S(x, 6) ^ S(x, 11) ^ S(x, 25));
};

var Gamma0256 = function(x) {
  return (S(x, 7) ^ S(x, 18) ^ R(x, 3));
};

var Gamma1256 = function(x) {
  return (S(x, 17) ^ S(x, 19) ^ R(x, 10));
};

  var K = new Array(
      0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5
    , 0x3956C25B, 0x59F111F1 ,0x923F82A4, 0xAB1C5ED5
    , 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3
    , 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174
    , 0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC
    , 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA
    , 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7
    , 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967
    , 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13
    , 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85
    , 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3
    , 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070
    , 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5
    , 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3
    , 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208
    , 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
  );

var W = new Array(64);

var core_sha256 = function(m, l) {

  var a, b, c, d, e, f, g, h, _a, _b, _c, _d, _e, _f, _g, _h
  a = 0x6A09E667,
  b = 0xBB67AE85,
  c = 0x3C6EF372,
  d = 0xA54FF53A,
  e = 0x510E527F,
  f = 0x9B05688C,
  g = 0x1F83D9AB,
  h = 0x5BE0CD19

    var a, b, c, d, e, f, g, h, i, j;
    var T1, T2;
  /* append padding */
  m[l >> 5] |= 0x80 << (24 - l % 32);
  m[((l + 64 >> 9) << 4) + 15] = l;
  for (var i = 0; i < m.length; i += 16) {

    _a = a; _b = b; _c = c; _d = d;
    _e = e; _f = f; _g = g; _h = h;

    for (var j = 0; j < 64; j++) {
      if (j < 16) {
        W[j] = m[j + i];
      } else {
        W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
      }
      T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
      T2 = safe_add(Sigma0256(a), Maj(a, b, c));
      h = g; g = f; f = e; e = safe_add(d, T1); d = c; c = b; b = a; a = safe_add(T1, T2);
    }
    a = safe_add(a, _a);
    b = safe_add(b, _b);
    c = safe_add(c, _c);
    d = safe_add(d, _d);
    e = safe_add(e, _e);
    f = safe_add(f, _f);
    g = safe_add(g, _g);
    h = safe_add(h, _h);
  }

  return (
    intToHex(a) + intToHex(b) + intToHex(c) + intToHex(d)
  + intToHex(e) + intToHex(f) + intToHex(g) + intToHex(h)
  )
};

function intToHex(int) {
    return (
      (int >> 28 & 0x0f).toString(16)
    + (int >> 24 & 0x0f).toString(16)
    + (int >> 20 & 0x0f).toString(16)
    + (int >> 16 & 0x0f).toString(16)
    + (int >> 12 & 0x0f).toString(16)
    + (int >>  8 & 0x0f).toString(16)
    + (int >>  4 & 0x0f).toString(16)
    + (int       & 0x0f).toString(16)
  )
}

function toArray(string) {
  var binary = unescape(encodeURIComponent(string))
  var l = binary.length
  var array = new Array(Math.ceil(l/4))
  var L = Math.ceil(l/4)*4
  var i = 0, j = 0
  //it's okay to just go over the end, charCodeAt(outofbound) -> NaN
  //and NaN has no effect in bitwise op.

  for(; i < L; i += 4) {
    array[i/4]
      = binary.charCodeAt(    i) << 24
      | binary.charCodeAt(1 + i) << 16
      | binary.charCodeAt(2 + i) << 8
      | binary.charCodeAt(3 + i)
  }

  return [array, l]
}

var sha256 = exports.sha256 = SHA256 =function (string) {
  //this converts utf8 into a binary string.
  var p = toArray(string)
  return core_sha256(p[0], p[1]*8)
};


var get = exports.get = GET = function (url, cb) {
  var xhr = new XMLHttpRequest()
  xhr.onerror = cb
  xhr.ontimeout = function () {
    return cb(new Error('timeout'))
  }
  xhr.onload = function () {
    cb(null, xhr.responseText)
  }
  xhr.open('GET', url)
  xhr.send()
}

var load = exports.load = LOAD = function (url, hash, cb) {
  function next(err, content) {
    if(err) return cb(err)
    if(sha256(content) !== hash)
      return cb(new Error('expected sha256(' + url + ') == '+hash))
    cb(null, content)
  }

  // first, check if we already have it in localstorage.
  // otherwise, load it via xhr.
  var content = localStorage[hash]
  if(content) next(null, content)
  else        get(url, next)
}

function addTags (files) {
  files.forEach(function (file) {
    var source = localStorage[file.hash]
    var hash = sha256(source)
    if(file.hash !== hash) {
      var err = 'expected '+item.hash+' got '+ hash
      alert(err)
      throw err
    }
    var type = (
        file.type || /\.js$/.test(file.id) ? 'script'
      : /\.css$/.test(file.id) ? 'style' 
      : null
    )

    if(!type) return
    var tag = document.createElement(type)
    tag.textContent = source
    
    document.head.appendChild(tag)
  })
}


var KEY = '*BOOTLOADER_MANIFEST*'

get('/manifest.json', function (err, json) {
  if(err) throw err
  var files = JSON.parse(json), n = 0
  files.forEach(function (file) {
    n++
    load(file.id, file.hash, function (err, content) {
      if(err) return next(err)
      localStorage[file.hash] = content;
      next()
    })
  })

  function next(err, cont) {
    if(err) throw err
    if(--n) return
    var json = JSON.stringify(files), _json = localStorage[KEY]

    //check if we are already running this code, if so, do nothing.
    if(_json === json) return

    //we have already saved the sources in localstorage.
    //now save the manifest - since we only do this when
    //all the files where successfully loaded, this will be atomic!

    //if this is the very first time we have loaded the page,
    //we can add the tags now, otherwise, allow the user to refresh the page.
    if(!_json) {
      localStorage[KEY] = files
      addTags(files)
    }

    //notify the user in most annoying way javascript allows.
    else {
      localStorage[KEY] = JSON.stringify(files)
      alert('code updated, refresh to update')
    }
  }
})


//we just started, and there is already a manifest.
var files = localStorage[KEY]
if(files) addTags(JSON.parse(files))

