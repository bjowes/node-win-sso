import http from 'http';
import https, { request } from 'https';
import net from 'net';
import fs from 'fs';
import {WinSso} from './win-sso';
import {debug} from './utils/debug.logger';
import { TLSSocket } from 'tls';
import { networkInterfaces } from 'os';

process.on('uncaughtException', function (exception) {
  debug(exception); // to see your exception details in the console
  // if you are on production, maybe you can send the exception details to your
  // email as well ?
});
process.on('unhandledRejection', (reason, p) => {
  debug("Unhandled Rejection at: Promise ", p, " reason: ", reason);
  // application specific logging, throwing an error, or other logic here
});
/*
let wa = new WinSso();
let t1token = wa.createAuthRequestHeader('utvapi-testdata.mpautv.mpa.se');
debug(t1token);
//let t2header = 'NTLM TlRMTVNTUAACAAAABgAGADgAAAAGgokCBIcGH3QrcsAAAAAAAAAAAKwArAA+AAAABgOAJQAAAA9NUEFVVFYCAAwATQBQAEEAVQBUAFYAAQAWAFUAVABWAFcARQBCAFMAUgBWADAAOAAEABoAbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQADADIAdQB0AHYAdwBlAGIAcwByAHYAMAA4AC4AbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQAFABoAbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQAHAAgA7I9Cv/Fk1QEAAAAA';
//let t2header = 'NTLM TlRMTVNTUAACAAAADAAMADgAAAA1goniSkJuVLRnpXMAAAAAAAAAAKwArABEAAAABgOAJQAAAA9NAFAAQQBVAFQAVgACAAwATQBQAEEAVQBUAFYAAQAWAFUAVABWAFcARQBCAFMAUgBWADAAOAAEABoAbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQADADIAdQB0AHYAdwBlAGIAcwByAHYAMAA4AC4AbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQAFABoAbQBwAGEAdQB0AHYALgBtAHAAYQAuAHMAZQAHAAgAA2np9oBm1QEAAAAA';
//let t3header = wa.createAuthResponseHeader(t2header, 'utvapi-testdata.mpautv.mpa.se', undefined);
//debug(t3header);
wa.destroy();
*/

let httpType1 = '';
let httpType2 = '';
let httpType3 = '';
let httpsType1 = '';
let httpsType2 = '';
let httpsType3 = '';
const logFile = fs.createWriteStream('c:\\temp\\sslkey.log', { flags: 'a' });
// ...

function go() {
  let wa = new WinSso();
  try {
    debug('pre HTTP');
    handshakeHttp(wa, 'utvapi-keps.mpautv.mpa.se', 'utvapi-keps.mpautv.mpa.se', (err: any) => {
      debug('handshake callback', err);
      wa.destroy();

      debug('pre HTTPS');
      wa = new WinSso();
      handshakeHttps(wa, 'utvapi-keps.mpautv.mpa.se', 'utvapi-keps.mpautv.mpa.se', (err: any) => {
        debug('handshake callback', err);
        wa.destroy();

        //debug('http / https');
        //debug(httpType1);
        //debug(httpsType1);
        //debug(httpType2);
        //debug(httpsType2);
        //debug(httpType3);
        //debug(httpsType3);
      });
    });
  }
  catch (err) {
    debug(err);
    wa.destroy();
  }
}
debug('yo');
setTimeout(() => go(), 100);
setTimeout(() => debug('timeout'), 6000);
setTimeout(() => debug('timeout'), 10000);
//process.stdout.on('drain', () => null);


function handshakeHttp(wa: WinSso, host: string, fqdn: string, callback: (err: any) => void) {

  let agent = new http.Agent({
    keepAlive: true,
    maxSockets: 1
  });
  let requestOptions: http.RequestOptions = {
    method: 'GET',
    path: '/api/v1/PcnProduct/1',
    host: host,
    port: 80,
    agent: agent,
  };
  requestOptions.headers = {};
  setHeaders(requestOptions.headers);
  debug('pre create T1');
  requestOptions.headers['authorization'] = wa.createAuthRequestHeader(host);
  debug('post create T1');
  requestOptions.headers['connection'] = 'keep-alive';
  httpType1 = requestOptions.headers['authorization'];

  let type1req = http.request(requestOptions, (res) => {
    debug(res.socket.localAddress, res.socket.localPort, res.socket.remoteAddress, res.socket.remotePort);
    debug(res.headers);
    res.resume(); // Finalize the response so we can reuse the socket

    if (res.statusCode !== 401) {
      return callback('no auth process');
    }
    debug('Got type 2');
    let type2msg = res.headers['www-authenticate'] || '';
    httpType2 = type2msg;
    debug(type2msg);

    let type3requestOptions: http.RequestOptions = {
      method: requestOptions.method,
      path: requestOptions.path,
      host: requestOptions.host,
      port: requestOptions.port as unknown as string,
      agent: requestOptions.agent,
      headers: {}
    };
    if (type3requestOptions.headers) { // Always true, silent the compiler
      type3requestOptions.headers['authorization'] = wa.createAuthResponseHeader(type2msg, fqdn, httpType1, undefined);
      httpType3 = type3requestOptions.headers['authorization'];
      setHeaders(type3requestOptions.headers);
    }
    //debug(type3requestOptions)
    let type3req = http.request(type3requestOptions, (res) => {
      debug(res.socket.localAddress, res.socket.localPort, res.socket.remoteAddress, res.socket.remotePort);
      debug(res.headers);
        res.resume(); // Finalize the response so we can reuse the socket
      if (res.statusCode === 401) {
        debug('auth failed');
        return callback('fail');
      } else {
        debug('auth success!', res.statusCode);
        return callback('OK');
      }
    });
    type3req.on('error', (err) => {
      debug('Error while sending NTLM message type 3:' + err.message);
      return callback(err);
    });
    //type3req.write(context.getRequestBody());
    debug('Sending  NTLM message type 3');
    type3req.end();
  });
  type1req.on('error', (err: NodeJS.ErrnoException) => {
    debug('Error while sending NTLM message type 1:', err);
    return callback(err);
  });
  debug('Sending  NTLM message type 1');
  type1req.end();
}

//const logFile = fs.createWriteStream('c:\\temp\\sslkey.log', { flags: 'a' });

const SESSION_ID_POS = 16;
const MASTER_KEY_POS = 50;

function parseSession(buf: Buffer | undefined) {

  if (buf === undefined) {
    return { sessionId: 'ERR', masterKey: 'ERR'};
  }

  return {
    sessionId: buf.slice(SESSION_ID_POS, SESSION_ID_POS+32).toString('hex'),
    masterKey: buf.slice(MASTER_KEY_POS, MASTER_KEY_POS+48).toString('hex')
  };
}

function patchRequest(req: http.ClientRequest) {
  req.once('socket', function(s: TLSSocket) {
    s.on('keylog', function (line) {
      debug('* * * ', line);
      logFile.write(line);
    });
    /*
    s.once('secureConnect', function() {
      let session = parseSession(s.getSession());
      // session.sessionId and session.masterKey should be hex strings
      let id = session.sessionId;
      let key = session.masterKey;
      //let logline = 'RSA Session-ID:' + id + 'Master-Key:' + key + '\n';
      let logline = 'CLIENT_RANDOM ' + id + ' ' + key + '\n';
      debug('****', logline);
      //let logfile = process.env.SSLKEYLOGFILE;
      //if (!logfile) {
      //  console.log('Missing Environment Variable SSLKEYLOGFILE');
      //}
      logFile.write(logline);
    });*/
  });
}

function setHeaders(headers: any) {
  headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:50.0) Gecko/20100101 Firefox/50.0';
  headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
  headers['Accept-Language'] ='sv-SE,sv;q=0.8,en-US;q=0.5,en;q=0.3';
  headers['Accept-Encoding'] = 'gzip, deflate';
}

function handshakeHttps(wa: WinSso, host: string, fqdn: string, callback: (err: any) => void) {

  let agent = new https.Agent({
    keepAlive: true,
    maxSockets: 1
  });
  //net.createConnection()
  /*
  (agent as any).createConnectionOrg = (agent as any).createConnection;
  (agent as any).createConnection = (options: net.NetConnectOpts, callback: ((err: any, socket: any) => void | undefined)): net.Socket => {
    debug('*****' ,'enter');
    //debug(options);
    //debug(callback);
    let socket = (agent as any).createConnectionOrg(options, callback);
    //let socket = net.connect(options);
    socket.on('keylog', (line: string) => {
      debug('***** ' +  line);
      logFile.write(line);
    });
    //callback(null, socket);
    debug('*****' ,'exit');
    return socket;
    */
    /*
    let socket = net.createConnection(options, callback);
    socket.on('keylog', line => {
      debug('*****', line);
      logFile.write(line);
    });
    debug('*****' ,'exit');
    return socket; */
  //};
  //sslkeylog.hookAgent(myAgent);
  /*
  for (let socketId in agent.sockets) {
    agent.sockets[socketId].forEach(socket =>
      socket.on('keylog', line => {
        debug('*****', line);
        logFile.write(line);
      })
    );
  }*/
  //agent.sockets.forEach(socket: Socket =>
  let requestOptions: https.RequestOptions = {
    method: 'GET',
    path: '/api/v1/PcnProduct/1',
    host: host,
    port: 443,
    agent: agent,
  };
  requestOptions.headers = {};
  setHeaders(requestOptions.headers);
  requestOptions.headers['authorization'] = wa.createAuthRequestHeader(host);
  httpsType1 = requestOptions.headers['authorization'];
  requestOptions.headers['connection'] = 'keep-alive';

  let type1req = https.request(requestOptions, (res) => {
    debug(res.socket.localAddress, res.socket.localPort, res.socket.remoteAddress, res.socket.remotePort);
    debug(res.headers);
    res.resume(); // Finalize the response so we can reuse the socket

    if (res.statusCode !== 401) {
      return callback('no auth process');
    }
    let tlsSocket = res.connection as TLSSocket;
    let cert = tlsSocket.getPeerCertificate();
    //debug(cert);
    debug('Got type 2');
    let type2msg = res.headers['www-authenticate'] || '';
    httpsType2 = type2msg;
    debug(type2msg);

    let type3requestOptions: https.RequestOptions = {
      method: requestOptions.method,
      path: requestOptions.path,
      host: requestOptions.host,
      port: requestOptions.port as unknown as string,
      agent: requestOptions.agent,
      headers: {}
    };
    if (type3requestOptions.headers) { // Always true, silent the compiler
      type3requestOptions.headers['authorization'] = wa.createAuthResponseHeader(type2msg, fqdn, httpsType1, cert);
      httpsType3 = type3requestOptions.headers['authorization'];
      setHeaders(type3requestOptions.headers);
    }
    //debug(type3requestOptions);
    let type3req = https.request(type3requestOptions, (res) => {
      debug(res.socket.localAddress, res.socket.localPort, res.socket.remoteAddress, res.socket.remotePort);
      debug(res.headers);
      res.resume(); // Finalize the response so we can reuse the socket
      if (res.statusCode === 401) {
        debug('auth failed');
        return callback('fail');
      } else {
        debug('auth success!', res.statusCode);
        return callback('OK');
      }
    });
    patchRequest(type3req);
    type3req.on('error', (err) => {
      debug('Error while sending NTLM message type 3:' + err.message);
      return callback(err);
    });
    /*
    type3req.on('socket', socket => {
      socket.on('keylog', line =>
        logFile.write(line));
    });
    */
    debug('Sending  NTLM message type 3');
    type3req.end();
  });
  patchRequest(type1req);
  type1req.on('error', (err: NodeJS.ErrnoException) => {
    debug('Error while sending NTLM message type 1:', err);
    return callback(err);
  });
  /*
  type1req.on('socket', socket => {
    socket.on('keylog', line => {
      debug('*****', line);
      logFile.write(line);
    });
  });
  */
  debug('Sending  NTLM message type 1');
  type1req.end();
}

/*
debug('acq');
acquireCredentialsHandle(userInfo, credHandle, lifeTime);
debug('init');
initializeCredentialsHandle(credHandle, ctxHandle, lifeTime, undefined, outSecBufferDesc);
debug('outSecBuffer', outSecBuffer);
debug('NTLM type 1', outToken.slice(0,outSecBuffer.cbBuffer).toString('base64'));
debug('write more');

// Send type 1 to server
// Received type 2
// Pass type 2 to initialize
// send type 3 to server

deleteSecurityContext(ctxHandle);
freeCredentialsHandle(credHandle);
debug('all free');
*/
