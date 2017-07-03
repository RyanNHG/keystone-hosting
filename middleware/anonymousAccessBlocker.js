'use strict';

var range_check = require('range_check');

// Anonymous Access Blocker middleware
module.exports = function() {

    return function(req, res, next) {
        
        // Read PATHS_TO_IGNORE environment variable
        var pathsToIgnore = process.env.ANONYMOUS_ACCESS_PATHS_TO_IGNORE
            ? process.env.ANONYMOUS_ACCESS_PATHS_TO_IGNORE.split(',').map(function (path) { return path.trim() })
            : []
        
        // Do not handle anything under /keystone
        pathsToIgnore = pathsToIgnore.concat(['/keystone'])
        
        console.log('pathsToIgnore', pathsToIgnore)
        
        var isIgnoredPath = pathsToIgnore
            .filter(function (path) { return req.path.lastIndexOf(path, 0) === 0 })
            .length > 0
        
        console.log(req.path, isIgnoredPath)
        
        // Bail out if the anonymous access blocker is not enabled or the path should be ignored
        if (process.env.ANONYMOUS_ACCESS_BLOCKER_ENABLED !== 'true' || isIgnoredPath) {
            return next();
        }
 
        // Process anonymous requests.
        if (!req.user || !req.user.canAccessKeystone) {
            
            // Check for IP range allowances.  Requests will be allowed through if the IP address is in range.
            var ipRanges = process.env.ANONYMOUS_ACCESS_BLOCKER_ALLOWED_IP_RANGES;
            if (ipRanges) {
                // The set of allowed ranges has to be separated by space
                // characters or a comma.
                var allowedRanges = ipRanges.split(/\s+|,/);
                
                // Using req.ips requires that express 'trust proxy' setting is
                // true. When it *is* set the value for ips is extracted from the
                // X-Forwarded-For request header. The originating IP address is
                // the last one in the array.
                var requestIP = (req.ips.length > 0) ? req.ips.slice().pop() : req.ip;
                console.log('Client IP: ' + requestIP);
                
                // Deny the request if request IP is not in one of the allowed
                // IP address ranges.
                var requestAllowed = range_check.in_range(requestIP, allowedRanges);
                
                if (requestAllowed) {
                    
                    // Allow the request to process
                    return next();
                }
            }

            // Request is not allowed.  Send the contents of the unauthorized.html file.
            res.sendfile(__dirname + '/unauthorized.html');
            return;
        }

        // Allow the request to process
        next();
    };
};
