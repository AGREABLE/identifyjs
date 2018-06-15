(function(window) {
	'use strict';
	var VERSION = "0.1";
	var defaultOptions = {
	};

	var identifyJS = function(options) {
		
	}

	identifyJS.prototype = {
		getVersion: function() {
			return VERSION;
		}
	}

	//expose to global object
	window.identifyJS = identifyJS;
}) (window);