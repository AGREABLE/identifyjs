(function(window) {
  'use strict';
  var VERSION = "0.1";
  var defaultOptions = {
    WebRTC: false
  };
  var UARawString = "";
  var UA = {};
  var t = true;
  var platform;
  var isPlatform = true;

  function extend(Options) {
    for (var key in Options) {
      defaultOptions[key] = Options[key];
    }
    return defaultOptions;
  }

  /**
   *
   *  Secure Hash Algorithm (SHA1)
   *  http://www.webtoolkit.info/
   *
   **/
  function _SHA1(msg) {
    function rotate_left(n, s) {
      var t4 = (n << s) | (n >>> (32 - s));
      return t4;
    };

    function lsb_hex(val) {
      var str = "";
      var i;
      var vh;
      var vl;
      for (i = 0; i <= 6; i += 2) {
        vh = (val >>> (i * 4 + 4)) & 0x0f;
        vl = (val >>> (i * 4)) & 0x0f;
        str += vh.toString(16) + vl.toString(16);
      }
      return str;
    };

    function cvt_hex(val) {
      var str = "";
      var i;
      var v;
      for (i = 7; i >= 0; i--) {
        v = (val >>> (i * 4)) & 0x0f;
        str += v.toString(16);
      }
      return str;
    };

    function Utf8Encode(string) {
      string = string.replace(/\r\n/g, "\n");
      var utftext = "";
      for (var n = 0; n < string.length; n++) {
        var c = string.charCodeAt(n);
        if (c < 128) {
          utftext += String.fromCharCode(c);
        } else if ((c > 127) && (c < 2048)) {
          utftext += String.fromCharCode((c >> 6) | 192);
          utftext += String.fromCharCode((c & 63) | 128);
        } else {
          utftext += String.fromCharCode((c >> 12) | 224);
          utftext += String.fromCharCode(((c >> 6) & 63) | 128);
          utftext += String.fromCharCode((c & 63) | 128);
        }
      }
      return utftext;
    };
    var blockstart;
    var i, j;
    var W = new Array(80);
    var H0 = 0x67452301;
    var H1 = 0xEFCDAB89;
    var H2 = 0x98BADCFE;
    var H3 = 0x10325476;
    var H4 = 0xC3D2E1F0;
    var A, B, C, D, E;
    var temp;
    msg = Utf8Encode(msg);
    var msg_len = msg.length;
    var word_array = new Array();
    for (i = 0; i < msg_len - 3; i += 4) {
      j = msg.charCodeAt(i) << 24 | msg.charCodeAt(i + 1) << 16 |
        msg.charCodeAt(i + 2) << 8 | msg.charCodeAt(i + 3);
      word_array.push(j);
    }
    switch (msg_len % 4) {
      case 0:
        i = 0x080000000;
        break;
      case 1:
        i = msg.charCodeAt(msg_len - 1) << 24 | 0x0800000;
        break;
      case 2:
        i = msg.charCodeAt(msg_len - 2) << 24 | msg.charCodeAt(msg_len - 1) << 16 | 0x08000;
        break;
      case 3:
        i = msg.charCodeAt(msg_len - 3) << 24 | msg.charCodeAt(msg_len - 2) << 16 | msg.charCodeAt(msg_len - 1) << 8 | 0x80;
        break;
    }
    word_array.push(i);
    while ((word_array.length % 16) != 14) word_array.push(0);
    word_array.push(msg_len >>> 29);
    word_array.push((msg_len << 3) & 0x0ffffffff);
    for (blockstart = 0; blockstart < word_array.length; blockstart += 16) {
      for (i = 0; i < 16; i++) W[i] = word_array[blockstart + i];
      for (i = 16; i <= 79; i++) W[i] = rotate_left(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
      A = H0;
      B = H1;
      C = H2;
      D = H3;
      E = H4;
      for (i = 0; i <= 19; i++) {
        temp = (rotate_left(A, 5) + ((B & C) | (~B & D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B, 30);
        B = A;
        A = temp;
      }
      for (i = 20; i <= 39; i++) {
        temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B, 30);
        B = A;
        A = temp;
      }
      for (i = 40; i <= 59; i++) {
        temp = (rotate_left(A, 5) + ((B & C) | (B & D) | (C & D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B, 30);
        B = A;
        A = temp;
      }
      for (i = 60; i <= 79; i++) {
        temp = (rotate_left(A, 5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B, 30);
        B = A;
        A = temp;
      }
      H0 = (H0 + A) & 0x0ffffffff;
      H1 = (H1 + B) & 0x0ffffffff;
      H2 = (H2 + C) & 0x0ffffffff;
      H3 = (H3 + D) & 0x0ffffffff;
      H4 = (H4 + E) & 0x0ffffffff;
    }
    var temp = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);
    return temp.toLowerCase();
  }
  // https://github.com/lancedikson/bowser
  function _detect(ua) {

    function getFirstMatch(regex) {
      var match = ua.match(regex);
      return (match && match.length > 1 && match[1]) || '';
    }

    function getSecondMatch(regex) {
      var match = ua.match(regex);
      return (match && match.length > 1 && match[2]) || '';
    }

    var iosdevice = getFirstMatch(/(ipod|iphone|ipad)/i).toLowerCase(),
      likeAndroid = /like android/i.test(ua),
      android = !likeAndroid && /android/i.test(ua),
      nexusMobile = /nexus\s*[0-6]\s*/i.test(ua),
      nexusTablet = !nexusMobile && /nexus\s*[0-9]+/i.test(ua),
      chromeos = /CrOS/.test(ua),
      silk = /silk/i.test(ua),
      sailfish = /sailfish/i.test(ua),
      tizen = /tizen/i.test(ua),
      webos = /(web|hpw)os/i.test(ua),
      windowsphone = /windows phone/i.test(ua),
      samsungBrowser = /SamsungBrowser/i.test(ua),
      windows = !windowsphone && /windows/i.test(ua),
      mac = !iosdevice && !silk && /macintosh/i.test(ua),
      linux = !android && !sailfish && !tizen && !webos && /linux/i.test(ua),
      edgeVersion = getSecondMatch(/edg([ea]|ios)\/(\d+(\.\d+)?)/i),
      versionIdentifier = getFirstMatch(/version\/(\d+(\.\d+)?)/i),
      tablet = /tablet/i.test(ua) && !/tablet pc/i.test(ua),
      mobile = !tablet && /[^-]mobi/i.test(ua),
      xbox = /xbox/i.test(ua),
      result

    if (/opera/i.test(ua)) {
      //  an old Opera
      result = {
        name: 'Opera',
        opera: t,
        version: versionIdentifier || getFirstMatch(/(?:opera|opr|opios)[\s\/](\d+(\.\d+)?)/i)
      }
    } else if (/opr\/|opios/i.test(ua)) {
      // a new Opera
      result = {
        name: 'Opera',
        opera: t,
        version: getFirstMatch(/(?:opr|opios)[\s\/](\d+(\.\d+)?)/i) || versionIdentifier
      }
    } else if (/SamsungBrowser/i.test(ua)) {
      result = {
        name: 'Samsung Internet for Android',
        samsungBrowser: t,
        version: versionIdentifier || getFirstMatch(/(?:SamsungBrowser)[\s\/](\d+(\.\d+)?)/i)
      }
    } else if (/coast/i.test(ua)) {
      result = {
        name: 'Opera Coast',
        coast: t,
        version: versionIdentifier || getFirstMatch(/(?:coast)[\s\/](\d+(\.\d+)?)/i)
      }
    } else if (/yabrowser/i.test(ua)) {
      result = {
        name: 'Yandex Browser',
        yandexbrowser: t,
        version: versionIdentifier || getFirstMatch(/(?:yabrowser)[\s\/](\d+(\.\d+)?)/i)
      }
    } else if (/ucbrowser/i.test(ua)) {
      result = {
        name: 'UC Browser',
        ucbrowser: t,
        version: getFirstMatch(/(?:ucbrowser)[\s\/](\d+(?:\.\d+)+)/i)
      }
    } else if (/mxios/i.test(ua)) {
      result = {
        name: 'Maxthon',
        maxthon: t,
        version: getFirstMatch(/(?:mxios)[\s\/](\d+(?:\.\d+)+)/i)
      }
    } else if (/epiphany/i.test(ua)) {
      result = {
        name: 'Epiphany',
        epiphany: t,
        version: getFirstMatch(/(?:epiphany)[\s\/](\d+(?:\.\d+)+)/i)
      }
    } else if (/puffin/i.test(ua)) {
      result = {
        name: 'Puffin',
        puffin: t,
        version: getFirstMatch(/(?:puffin)[\s\/](\d+(?:\.\d+)?)/i)
      }
    } else if (/sleipnir/i.test(ua)) {
      result = {
        name: 'Sleipnir',
        sleipnir: t,
        version: getFirstMatch(/(?:sleipnir)[\s\/](\d+(?:\.\d+)+)/i)
      }
    } else if (/k-meleon/i.test(ua)) {
      result = {
        name: 'K-Meleon',
        kMeleon: t,
        version: getFirstMatch(/(?:k-meleon)[\s\/](\d+(?:\.\d+)+)/i)
      }
    } else if (windowsphone) {
      result = {
        name: 'Windows Phone',
        osname: 'Windows Phone',
        windowsphone: t
      }
      if (edgeVersion) {
        result.msedge = t
        result.version = edgeVersion
      } else {
        result.msie = t
        result.version = getFirstMatch(/iemobile\/(\d+(\.\d+)?)/i)
      }
    } else if (/msie|trident/i.test(ua)) {
      result = {
        name: 'Internet Explorer',
        msie: t,
        version: getFirstMatch(/(?:msie |rv:)(\d+(\.\d+)?)/i)
      }
    } else if (chromeos) {
      result = {
        name: 'Chrome',
        osname: 'Chrome OS',
        chromeos: t,
        chromeBook: t,
        chrome: t,
        version: getFirstMatch(/(?:chrome|crios|crmo)\/(\d+(\.\d+)?)/i)
      }
    } else if (/edg([ea]|ios)/i.test(ua)) {
      result = {
        name: 'Microsoft Edge',
        msedge: t,
        version: edgeVersion
      }
    } else if (/vivaldi/i.test(ua)) {
      result = {
        name: 'Vivaldi',
        vivaldi: t,
        version: getFirstMatch(/vivaldi\/(\d+(\.\d+)?)/i) || versionIdentifier
      }
    } else if (sailfish) {
      result = {
        name: 'Sailfish',
        osname: 'Sailfish OS',
        sailfish: t,
        version: getFirstMatch(/sailfish\s?browser\/(\d+(\.\d+)?)/i)
      }
    } else if (/seamonkey\//i.test(ua)) {
      result = {
        name: 'SeaMonkey',
        seamonkey: t,
        version: getFirstMatch(/seamonkey\/(\d+(\.\d+)?)/i)
      }
    } else if (/firefox|iceweasel|fxios/i.test(ua)) {
      result = {
        name: 'Firefox',
        firefox: t,
        version: getFirstMatch(/(?:firefox|iceweasel|fxios)[ \/](\d+(\.\d+)?)/i)
      }
      if (/\((mobile|tablet);[^\)]*rv:[\d\.]+\)/i.test(ua)) {
        result.firefoxos = t
        result.osname = 'Firefox OS'
      }
    } else if (silk) {
      result = {
        name: 'Amazon Silk',
        silk: t,
        version: getFirstMatch(/silk\/(\d+(\.\d+)?)/i)
      }
    } else if (/phantom/i.test(ua)) {
      result = {
        name: 'PhantomJS',
        phantom: t,
        version: getFirstMatch(/phantomjs\/(\d+(\.\d+)?)/i)
      }
    } else if (/slimerjs/i.test(ua)) {
      result = {
        name: 'SlimerJS',
        slimer: t,
        version: getFirstMatch(/slimerjs\/(\d+(\.\d+)?)/i)
      }
    } else if (/blackberry|\bbb\d+/i.test(ua) || /rim\stablet/i.test(ua)) {
      result = {
        name: 'BlackBerry',
        osname: 'BlackBerry OS',
        blackberry: t,
        version: versionIdentifier || getFirstMatch(/blackberry[\d]+\/(\d+(\.\d+)?)/i)
      }
    } else if (webos) {
      result = {
        name: 'WebOS',
        osname: 'WebOS',
        webos: t,
        version: versionIdentifier || getFirstMatch(/w(?:eb)?osbrowser\/(\d+(\.\d+)?)/i)
      };
      /touchpad\//i.test(ua) && (result.touchpad = t)
    } else if (/bada/i.test(ua)) {
      result = {
        name: 'Bada',
        osname: 'Bada',
        bada: t,
        version: getFirstMatch(/dolfin\/(\d+(\.\d+)?)/i)
      };
    } else if (tizen) {
      result = {
        name: 'Tizen',
        osname: 'Tizen',
        tizen: t,
        version: getFirstMatch(/(?:tizen\s?)?browser\/(\d+(\.\d+)?)/i) || versionIdentifier
      };
    } else if (/qupzilla/i.test(ua)) {
      result = {
        name: 'QupZilla',
        qupzilla: t,
        version: getFirstMatch(/(?:qupzilla)[\s\/](\d+(?:\.\d+)+)/i) || versionIdentifier
      }
    } else if (/chromium/i.test(ua)) {
      result = {
        name: 'Chromium',
        chromium: t,
        version: getFirstMatch(/(?:chromium)[\s\/](\d+(?:\.\d+)?)/i) || versionIdentifier
      }
    } else if (/chrome|crios|crmo/i.test(ua)) {
      result = {
        name: 'Chrome',
        chrome: t,
        version: getFirstMatch(/(?:chrome|crios|crmo)\/(\d+(\.\d+)?)/i)
      }
    } else if (android) {
      result = {
        name: 'Android',
        version: versionIdentifier
      }
    } else if (/safari|applewebkit/i.test(ua)) {
      result = {
        name: 'Safari',
        safari: t
      }
      if (versionIdentifier) {
        result.version = versionIdentifier
      }
    } else if (iosdevice) {
      result = {
        name: iosdevice == 'iphone' ? 'iPhone' : iosdevice == 'ipad' ? 'iPad' : 'iPod'
      }
      // WTF: version is not part of user agent in web apps
      if (versionIdentifier) {
        result.version = versionIdentifier
      }
    } else if (/googlebot/i.test(ua)) {
      result = {
        name: 'Googlebot',
        googlebot: t,
        version: getFirstMatch(/googlebot\/(\d+(\.\d+))/i) || versionIdentifier
      }
    } else {
      result = {
        name: getFirstMatch(/^(.*)\/(.*) /),
        version: getSecondMatch(/^(.*)\/(.*) /)
      };
    }

    // set webkit or gecko flag for browsers based on these engines
    if (!result.msedge && /(apple)?webkit/i.test(ua)) {
      if (/(apple)?webkit\/537\.36/i.test(ua)) {
        result.name = result.name || "Blink"
        result.blink = t
      } else {
        result.name = result.name || "Webkit"
        result.webkit = t
      }
      if (!result.version && versionIdentifier) {
        result.version = versionIdentifier
      }
    } else if (!result.opera && /gecko\//i.test(ua)) {
      result.name = result.name || "Gecko"
      result.gecko = t
      result.version = result.version || getFirstMatch(/gecko\/(\d+(\.\d+)?)/i)
    }

    // set OS flags for platforms that have multiple browsers
    if (!result.windowsphone && (android || result.silk)) {
      result.android = t
      result.osname = 'Android'
    } else if (!result.windowsphone && iosdevice) {
      result[iosdevice] = t
      result.ios = t
      result.osname = 'iOS'
    } else if (mac) {
      result.mac = t
      result.osname = 'macOS'
    } else if (xbox) {
      result.xbox = t
      result.osname = 'Xbox'
    } else if (windows) {
      result.windows = t
      result.osname = 'Windows'
    } else if (linux) {
      result.linux = t
      result.osname = 'Linux'
    }

    function getWindowsVersion(s) {
      switch (s) {
        case 'NT':
          return 'NT'
        case 'XP':
          return 'XP'
        case 'NT 5.0':
          return '2000'
        case 'NT 5.1':
          return 'XP'
        case 'NT 5.2':
          return '2003'
        case 'NT 6.0':
          return 'Vista'
        case 'NT 6.1':
          return '7'
        case 'NT 6.2':
          return '8'
        case 'NT 6.3':
          return '8.1'
        case 'NT 10.0':
          return '10'
        default:
          return undefined
      }
    }

    // OS version extraction
    var osVersion = '';
    if (result.windows) {
      osVersion = getWindowsVersion(getFirstMatch(/Windows ((NT|XP)( \d\d?.\d)?)/i))
    } else if (result.windowsphone) {
      osVersion = getFirstMatch(/windows phone (?:os)?\s?(\d+(\.\d+)*)/i);
    } else if (result.mac) {
      osVersion = getFirstMatch(/Mac OS X (\d+([_\.\s]\d+)*)/i);
      osVersion = osVersion.replace(/[_\s]/g, '.');
    } else if (iosdevice) {
      osVersion = getFirstMatch(/os (\d+([_\s]\d+)*) like mac os x/i);
      osVersion = osVersion.replace(/[_\s]/g, '.');
    } else if (android) {
      osVersion = getFirstMatch(/android[ \/-](\d+(\.\d+)*)/i);
    } else if (result.webos) {
      osVersion = getFirstMatch(/(?:web|hpw)os\/(\d+(\.\d+)*)/i);
    } else if (result.blackberry) {
      osVersion = getFirstMatch(/rim\stablet\sos\s(\d+(\.\d+)*)/i);
    } else if (result.bada) {
      osVersion = getFirstMatch(/bada\/(\d+(\.\d+)*)/i);
    } else if (result.tizen) {
      osVersion = getFirstMatch(/tizen[\/\s](\d+(\.\d+)*)/i);
    }
    if (osVersion) {
      result.osversion = osVersion;
    }
    // device type extraction
    var osMajorVersion = !result.windows && osVersion.split('.')[0];
    if (
      tablet ||
      nexusTablet ||
      iosdevice == 'ipad' ||
      (android && (osMajorVersion == 3 || (osMajorVersion >= 4 && !mobile))) ||
      result.silk
    ) {
      result.tablet = t
    } else if (
      mobile ||
      iosdevice == 'iphone' ||
      iosdevice == 'ipod' ||
      android ||
      nexusMobile ||
      result.blackberry ||
      result.webos ||
      result.bada
    ) {
      result.mobile = t
    }

    // Graded Browser Support
    // http://developer.yahoo.com/yui/articles/gbs
    if (result.msedge ||
      (result.msie && result.version >= 10) ||
      (result.yandexbrowser && result.version >= 15) ||
      (result.vivaldi && result.version >= 1.0) ||
      (result.chrome && result.version >= 20) ||
      (result.samsungBrowser && result.version >= 4) ||
      (result.firefox && result.version >= 20.0) ||
      (result.safari && result.version >= 6) ||
      (result.opera && result.version >= 10.0) ||
      (result.ios && result.osversion && result.osversion.split(".")[0] >= 6) ||
      (result.blackberry && result.version >= 10.1) ||
      (result.chromium && result.version >= 20)
    ) {
      result.a = t;
    } else if ((result.msie && result.version < 10) ||
      (result.chrome && result.version < 20) ||
      (result.firefox && result.version < 20.0) ||
      (result.safari && result.version < 6) ||
      (result.opera && result.version < 10.0) ||
      (result.ios && result.osversion && result.osversion.split(".")[0] < 6) ||
      (result.chromium && result.version < 20)
    ) {
      result.c = t
    } else result.x = t

    return result
  }

  function _getLocalIP() {
    return new Promise(function(resolve, reject) {
      var RTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection || window.msRTCPeerConnection;
      if (!RTCPeerConnection) {
        reject();
      }
      var rtc = new RTCPeerConnection();
      rtc.createDataChannel("TEMP");
      rtc.onicecandidate = function(iceevent) {
        if (iceevent && iceevent.candidate && iceevent.candidate.candidate) {
          var r = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
          var t = iceevent.candidate.candidate.match(r);
          resolve(t[0]);
        }
      }
      rtc.createOffer().then(offer => rtc.setLocalDescription(offer));
    });
  }

  function _getExternalIP() {
    return new Promise(function(resolve, reject) {
      var head = document.getElementsByTagName('head')[0];
      var script = document.createElement('script');
      window.getIP = function(json) {
        if (json && json.ip) {
          resolve(json.ip);
        } else {
          reject();
        }
        head.removeChild(script);
      };
      script.type = 'text/javascript';
      script.src = 'https://api.ipify.org?format=jsonp&callback=getIP';
      head.appendChild(script);
    });
  }

  function getWebglCanvas() {
    var canvas = document.createElement('canvas');
    var gl = null;
    try {
      gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    } catch (e) { /* squelch */ }
    if (!gl) {
      gl = null;
    }
    return gl;
  }


  function _getWebGL(self) {
    console.log(self);
    return new Promise(function(resolve, reject) {
      //https://github.com/Valve/fingerprintjs2/
      var gl;
      var fa2s = function(fa) {
        gl.clearColor(0.0, 0.0, 0.0, 1.0);
        gl.enable(gl.DEPTH_TEST);
        gl.depthFunc(gl.LEQUAL);
        gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
        return '[' + fa[0] + ', ' + fa[1] + ']';
      }
      var maxAnisotropy = function(gl) {
        var ext = gl.getExtension('EXT_texture_filter_anisotropic') || gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic') || gl.getExtension('MOZ_EXT_texture_filter_anisotropic');
        if (ext) {
          var anisotropy = gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT);
          if (anisotropy === 0) {
            anisotropy = 2;
          }
          return anisotropy;
        } else {
          return null;
        }
      }
      gl = getWebglCanvas();
      if (!gl) {
        return null;
      }
      // WebGL fingerprinting is a combination of techniques, found in MaxMind antifraud script & Augur fingerprinting.
      // First it draws a gradient object with shaders and convers the image to the Base64 string.
      // Then it enumerates all WebGL extensions & capabilities and appends them to the Base64 string, resulting in a huge WebGL string, potentially very unique on each device
      // Since iOS supports webgl starting from version 8.1 and 8.1 runs on several graphics chips, the results may be different across ios devices, but we need to verify it.
      var result = [];
      var vShaderTemplate = 'attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}';
      var fShaderTemplate = 'precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}';
      var vertexPosBuffer = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, vertexPosBuffer);
      var vertices = new Float32Array([-0.2, -0.9, 0, 0.4, -0.26, 0, 0, 0.732134444, 0]);
      gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
      vertexPosBuffer.itemSize = 3;
      vertexPosBuffer.numItems = 3;
      var program = gl.createProgram();
      var vshader = gl.createShader(gl.VERTEX_SHADER);
      gl.shaderSource(vshader, vShaderTemplate);
      gl.compileShader(vshader);
      var fshader = gl.createShader(gl.FRAGMENT_SHADER);
      gl.shaderSource(fshader, fShaderTemplate);
      gl.compileShader(fshader);
      gl.attachShader(program, vshader);
      gl.attachShader(program, fshader);
      gl.linkProgram(program);
      gl.useProgram(program);
      program.vertexPosAttrib = gl.getAttribLocation(program, 'attrVertex');
      program.offsetUniform = gl.getUniformLocation(program, 'uniformOffset');
      gl.enableVertexAttribArray(program.vertexPosArray);
      gl.vertexAttribPointer(program.vertexPosAttrib, vertexPosBuffer.itemSize, gl.FLOAT, !1, 0, 0);
      gl.uniform2f(program.offsetUniform, 1, 1);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, vertexPosBuffer.numItems);
      try {
        result.push(gl.canvas.toDataURL());
      } catch (e) {
        /* .toDataURL may be absent or broken (blocked by extension) */
      }
      result.push('extensions:' + (gl.getSupportedExtensions() || []).join(';'));
      result.push('webgl aliased line width range:' + fa2s(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)));
      result.push('webgl aliased point size range:' + fa2s(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)));
      result.push('webgl alpha bits:' + gl.getParameter(gl.ALPHA_BITS));
      result.push('webgl antialiasing:' + (gl.getContextAttributes().antialias ? 'yes' : 'no'));
      result.push('webgl blue bits:' + gl.getParameter(gl.BLUE_BITS));
      result.push('webgl depth bits:' + gl.getParameter(gl.DEPTH_BITS));
      result.push('webgl green bits:' + gl.getParameter(gl.GREEN_BITS));
      result.push('webgl max anisotropy:' + maxAnisotropy(gl));
      result.push('webgl max combined texture image units:' + gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS));
      result.push('webgl max cube map texture size:' + gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE));
      result.push('webgl max fragment uniform vectors:' + gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS));
      result.push('webgl max render buffer size:' + gl.getParameter(gl.MAX_RENDERBUFFER_SIZE));
      result.push('webgl max texture image units:' + gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS));
      result.push('webgl max texture size:' + gl.getParameter(gl.MAX_TEXTURE_SIZE));
      result.push('webgl max varying vectors:' + gl.getParameter(gl.MAX_VARYING_VECTORS));
      result.push('webgl max vertex attribs:' + gl.getParameter(gl.MAX_VERTEX_ATTRIBS));
      result.push('webgl max vertex texture image units:' + gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS));
      result.push('webgl max vertex uniform vectors:' + gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS));
      result.push('webgl max viewport dims:' + fa2s(gl.getParameter(gl.MAX_VIEWPORT_DIMS)));
      result.push('webgl red bits:' + gl.getParameter(gl.RED_BITS));
      result.push('webgl renderer:' + gl.getParameter(gl.RENDERER));
      result.push('webgl shading language version:' + gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
      result.push('webgl stencil bits:' + gl.getParameter(gl.STENCIL_BITS));
      result.push('webgl vendor:' + gl.getParameter(gl.VENDOR));
      result.push('webgl version:' + gl.getParameter(gl.VERSION));

      try {
        // Add the unmasked vendor and unmasked renderer if the debug_renderer_info extension is available
        var extensionDebugRendererInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (extensionDebugRendererInfo) {
          result.push('webgl unmasked vendor:' + gl.getParameter(extensionDebugRendererInfo.UNMASKED_VENDOR_WEBGL));
          result.push('webgl unmasked renderer:' + gl.getParameter(extensionDebugRendererInfo.UNMASKED_RENDERER_WEBGL));
        }
      } catch (e) { /* squelch */ }

      if (!gl.getShaderPrecisionFormat) {
        return result.join('~');
      }

      var that = self;

      that.each(['FLOAT', 'INT'], function(numType) {
        that.each(['VERTEX', 'FRAGMENT'], function(shader) {
          that.each(['HIGH', 'MEDIUM', 'LOW'], function(numSize) {
            that.each(['precision', 'rangeMin', 'rangeMax'], function(key) {
              var format = gl.getShaderPrecisionFormat(gl[shader + '_SHADER'], gl[numSize + '_' + numType])[key];
              if (key !== 'precision') {
                key = 'precision ' + key;
              }
              var line = ['webgl ', shader.toLowerCase(), ' shader ', numSize.toLowerCase(), ' ', numType.toLowerCase(), ' ', key, ':', format];
              result.push(line.join(''));
            })
          })
        })
      })
      resolve(result.join('~'));
    });
  }

  (function init() {
    UARawString = (window && window.navigator && window.navigator.userAgent) ? window.navigator.userAgent : "";
    platform = (window && window.navigator && window.navigator.platform) ? window.navigator.platform : "";
    UA = _detect(UARawString);
    //Compare platform
    if (UA.mobile && platform && (/Win/i.test(platform) || /Mac/i.test(platform))) {
      isPlatform = false;
    }

  })();

  var identifyJS = function(options) {
    extend(options);
  }

  identifyJS.prototype = {
    getVersion: function() {
      return VERSION;
    },
    getOptions: function() {
      return defaultOptions;
    },
    getPlatform: function() {
      return navigator.platform;
    },
    getLocalIP: function(callback) {
      //callback(_getLocalIP());
      _getLocalIP().then(callback);
    },
    getExternalIP: function(callback) {
      _getExternalIP().then(callback);
    },
    getPlugins: function() {

    },
    getCanvas: function(callback) {
      //https://browserleaks.com/canvas
      var txt = "ASDFOKJ l;ksadjf I;LAWEJFL; ZSGD 김金";
      var canvas = document.createElement('canvas');
      canvas.width = 2000
      canvas.height = 200
      canvas.style.display = 'inline'
    },
    getWebGL: function(callback) {
      _getWebGL(this).then(callback);
    },
    getUserAgent: function() {
      return UA;
    },
    checkPlatform: function() {
      return isPlatform;
    },    
    each(obj, iterator, context) {
      if (obj === null) {
        return;
      }
      if (this.nativeForEach && obj.forEach === this.nativeForEach) {
        obj.forEach(iterator, context);
      } else if (obj.length === +obj.length) {
        for (var i = 0, l = obj.length; i < l; i++) {
          if (iterator.call(context, obj[i], i, obj) === {}) {
            return;
          }
        }
      } else {
        for (var key in obj) {
          if (obj.hasOwnProperty(key)) {
            if (iterator.call(context, obj[key], key, obj) === {}) {
              return;
            }
          }
        }
      }
    }
  }

  //expose to global object
  window.identifyJS = identifyJS;
})(window);
