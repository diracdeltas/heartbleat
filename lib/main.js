/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { Cc, Ci, Cr, Cu, components } = require("chrome");
const events = require("sdk/system/events");

Cu.import("resource://services-common/utils.js");

// Run a local VM w/ Heartbleed vuln on 10.0.1.10, ex: https://github.com/diracdeltas/heartbox
let TEST_HOST = "10.0.1.10";

let socketTransportService = Cc["@mozilla.org/network/socket-transport-service;1"]
                              .getService(Ci.nsISocketTransportService);
Cu.import("resource://gre/modules/NetUtil.jsm");
let makeURI = CommonUtils.makeURI;

// cache decisions returned by the external service to avoid brutalizing it
// and perf to boot
//
// this will automatically be cleared on restart because it's stored in the
// addon's memory. if we persist it, we need to periodically check it as hosts
// update.
let HOSTNAME_CACHE = {};

function HeartbeatCheckListener(origRequest) {
  this.origRequest = origRequest;
  this._wrapper = null;
  this._response = "";
}

let reader = {
    onInputStreamReady : function(input) {
            let sin = Cc["@mozilla.org/scriptableinputstream;1"]
                        .createInstance(Ci.nsIScriptableInputStream);
            sin.init(input);
            sin.available();
            let response = '';
            while (sin.available()) {
                      response = response + sin.read(512);
                    }
            console.log('Received: ' + response);
            input.asyncWait(reader,0,0,null);
        }
};

// @param host can be hostname or ip address
function checkHeartbeat(host, port) {
  port = port ? port : 443;
  console.log("Checking heartbeat on", host, port)

  // Get nsISocketTransport
  let socket = socketTransportService.createTransport(null, 0, host, port, null);

  let inputStream = socket.openInputStream(0, 0, 0)
                      .QueryInterface(Ci.nsIAsyncInputStream); /* nsIAsyncInputStream */

  let outputStream = socket.openOutputStream(Ci.nsITransport.OPEN_BLOCKING, 0, 0); /* nsIOutputStream */
  let binaryOutputStream = Cc["@mozilla.org/binaryoutputstream;1"]
                             .createInstance(Ci.nsIBinaryOutputStream);
  binaryOutputStream.setOutputStream(outputStream);
  binaryOutputStream.writeByteArray(HB12, HB12.length);

  inputStream.asyncWait(reader, 0, 0, null);
}

// TLS ClientHello
const clientHello = [0x16, 0x03, 0x02, 0x00, 0xdc, 0x01, 0x00, 0x00, 0xd8, 0x03, 0x02, 0x53,
0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b, 0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97, 0xcf,
0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85, 0x03, 0x90, 0x9f, 0x77, 0x04, 0x33, 0xd4, 0xde, 0x00,
0x00, 0x66, 0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21, 0x00, 0x39, 0x00, 0x38, 0x00, 0x88,
0x00, 0x87, 0xc0, 0x0f, 0xc0, 0x05, 0x00, 0x35, 0x00, 0x84, 0xc0, 0x12, 0xc0, 0x08, 0xc0, 0x1c,
0xc0, 0x1b, 0x00, 0x16, 0x00, 0x13, 0xc0, 0x0d, 0xc0, 0x03, 0x00, 0x0a, 0xc0, 0x13, 0xc0, 0x09,
0xc0, 0x1f, 0xc0, 0x1e, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9a, 0x00, 0x99, 0x00, 0x45, 0x00, 0x44,
0xc0, 0x0e, 0xc0, 0x04, 0x00, 0x2f, 0x00, 0x96, 0x00, 0x41, 0xc0, 0x11, 0xc0, 0x07, 0xc0, 0x0c,
0xc0, 0x02, 0x00, 0x05, 0x00, 0x04, 0x00, 0x15, 0x00, 0x12, 0x00, 0x09, 0x00, 0x14, 0x00, 0x11,
0x00, 0x08, 0x00, 0x06, 0x00, 0x03, 0x00, 0xff, 0x01, 0x00, 0x00, 0x49, 0x00, 0x0b, 0x00, 0x04,
0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x34, 0x00, 0x32, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x19,
0x00, 0x0b, 0x00, 0x0c, 0x00, 0x18, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x17, 0x00, 0x08,
0x00, 0x06, 0x00, 0x07, 0x00, 0x14, 0x00, 0x15, 0x00, 0x04, 0x00, 0x05, 0x00, 0x12, 0x00, 0x13,
0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 0x23, 0x00, 0x00,
0x00, 0x0f, 0x00, 0x01, 0x01];

// Heartbeat for TLS1.2
const HB12 = [0x18, 0x03, 0x03, 0x00, 0x03, 0x01, 0x10, 0x00];
// Heartbeat for TLS1.1
const HB11 = [0x18, 0x03, 0x02, 0x00, 0x03, 0x01, 0x10, 0x00];
// Heartbeat for TLS1.0
const HB11 = [0x18, 0x03, 0x01, 0x00, 0x03, 0x01, 0x10, 0x00];

HeartbeatCheckListener.prototype = {

  QueryInterface: function(iid) {
    if (iid.equals(Ci.nsIStreamListener) ||
        iid.equals(Ci.nsIRequestObserver) ||
          iid.equals(Ci.nsISupports))
      return this;
    throw Cr.NS_ERROR_NO_INTERFACE;
  },

  onStartRequest: function(request, context) {},

  onDataAvailable:
  function(request, context, inputStream, offset, count) {
    if (this._wrapper == null) {
      this._wrapper = Cc["@mozilla.org/scriptableinputstream;1"]
                      .createInstance(Ci.nsIScriptableInputStream);
      this._wrapper.init(inputStream);
    }
    // store the response as it becomes available
    this._response += this._wrapper.read(count);
  },

  onStopRequest:
    function(request, context, status) {
    // status == NS_OK?
    if (components.isSuccessCode(status)) {
      // check the result
      // TODO: this is dumb
      // response is JSON
      console.log("this._response: " + this._response);
      let responseObj = JSON.parse(this._response);
      console.log("got responseObj: " + responseObj);
      let passedCheck = (responseObj.code == 1);
      // add to cache
      console.log("caching decision (" + this.origRequest.URI.host + ", " + passedCheck + ")");
      HOSTNAME_CACHE[this.origRequest.URI.host] = passedCheck;
      if (passedCheck) {
        console.log("External service said all good, resuming original request");
        this.origRequest.resume();
      } else {
        console.log("External service did no return all good, cancelling original request");
        // Maybe there's some better error to use here
        this.origRequest.cancel(Cr.NS_BINDING_ABORTED);
      }
    }
    else {
      // something went wrong... log error and resume original request to avoid
      // breaking the web TODO do better
      console.error("status != NS_OK, allowing original request due to error");
      // resume the original request
      this.origRequest.resume();
    }
  }
};

function onModifyRequest(event) {
  let channel;
  try {
    channel = event.subject.QueryInterface(Ci.nsIHttpChannel);
  } catch (e) {
    console.log("channel was not nsIHttpChannel in http-on-modify-request");
  }

  if (!channel) { return; }

  let uri = channel.URI;

  // Note: this is not good enough. We probably shouldn't check Safe Browsing
  // requests, etc.
  if (! uri.schemeIs("https")) {
    console.log("not https: " + uri.asciiSpec);
    return;
  }
  console.log("https: " + uri.asciiSpec);

  // first check the cache
  if (HOSTNAME_CACHE.hasOwnProperty(uri.host)) {
    if (HOSTNAME_CACHE[uri.host] == false) {
      console.log("Cancelling request to bad domain according to cached check result");
      channel.cancel();
    } else {
      console.log("Allowing request (skipping check) according to cached check result");
      return;
    }
  }

  /* Start by suspending the original request */
  try {
    channel.suspend();
    console.log("suspended " + uri.asciiSpec);
    // TODO: pulled from reading source on http://filippo.io/Heartbleed
    // Append the hostname at the end of the URL to check
    let checkServiceURI = "http://bleed-1161785939.us-east-1.elb.amazonaws.com/bleed/";
    let ioService = Cc["@mozilla.org/network/io-service;1"]
                   .getService(Ci.nsIIOService);
    let checkChannel = ioService.newChannelFromURI(makeURI(checkServiceURI + uri.host));
    // make request anonymous (no cookies, etc.) so it can't be abused for
    // CSRF, etc.
    checkChannel.loadFlags |= Ci.nsIChannel.LOAD_ANONYMOUS;
    checkChannel.loadGroup = channel.loadGroup;
    checkChannel.asyncOpen(new HeartbeatCheckListener(channel), null);
  } catch (e) {
    console.log("error suspending https channel: " + e);
  }
}

function main(options) {
  checkHeartbeat(TEST_HOST);
  console.log("in main");
  //events.on("http-on-modify-request", onModifyRequest, false);
}

exports.main = main;
