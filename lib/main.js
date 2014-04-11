/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

const { Cc, Ci, Cr, Cu, components } = require("chrome");
const events = require("sdk/system/events");

Cu.import("resource://services-common/utils.js");

let TEST_HOST = "10.0.1.10";

// http://stackoverflow.com/questions/10173811/how-to-connect-to-a-remote-server-using-nsisockettransportservice-in-a-firefox-e
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

// @param host can be hostname or ip address
function checkHeartbeat(host, port) {
  port = port ? port : 443;
  console.log("Checking heartbeat on", host, port)
  // Get nsISocketTransport
  let socket = socketTransportService.createTransport(["ssl"], 1, host, port, null);
  let outputStream = socket.openOutputStream(0, 0, 0); /* nsIOutputStream */
  let clientHello = getHello(); /* byte array */
  let inputStream = socket.openInputStream(0, 0, 0); /* nsIInputStream */

  let binaryOutputStream = Cc["@mozilla.org/binaryoutputstream;1"].createInstance(Ci.nsIBinaryOutputStream);
  binaryOutputStream.setOutputStream(outputStream);
  binaryOutputStream.writeByteArray(clientHello, clientHello.length);
  console.log("got binary output stream", JSON.stringify(binaryOutputStream));

  NetUtil.asyncFetch(inputStream, function(stream, result, request) {
    if (!components.isSuccessCode(result)) {
      console.log("ERROR: Status is", result);
    }
    var data = NetUtil.readInputStreamToString(stream, inputStream.available());
    console.log("INPUT STREAM", data);
  });
}

function getHello() {
  let helloStr = "16 03 02 00 dc 01 00 00 d8 03 02 53 " +
    "43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97 cf " +
    "bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00 " +
    "00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88 " +
    "00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c " +
    "c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09 " +
    "c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44 " +
    "c0 0e c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0 0c " +
    "c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11 " +
    "00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00 04 " +
    "03 00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00 19 " +
    "00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08 " +
    "00 06 00 07 00 14 00 15 00 04 00 05 00 12 00 13 " +
    "00 01 00 02 00 03 00 0f 00 10 00 11 00 23 00 00 " +
    "00 0f 00 01 01";
  let helloBytes = [];
  helloStr.split(' ').forEach(function(element, index, array) {
    helloBytes.push(parseInt(element), 16);
  });
  return helloBytes;
}

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
