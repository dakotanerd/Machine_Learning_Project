// app_server.js
// Vulnerable Node.js example (for training only).
// Issues: eval(userInput), path traversal via filename, insecure execution pattern.

const http = require('http');
const url = require('url');
const fs = require('fs');
const { exec } = require('child_process');

const PORT = 8080;

function handleEval(req, res, params) {
  // Danger: evaluating user-provided code
  const code = params.get('code') || '';
  try {
    // eslint-disable-next-line no-eval
    const result = eval(code); // RCE via eval
    res.end('Result: ' + String(result));
  } catch (err) {
    res.end('Error: ' + String(err));
  }
}

function handleRead(req, res, params) {
  // Path traversal if filename is not validated
  const fname = params.get('file') || 'index.html';
  const path = './public/' + fname;
  // naive read
  fs.readFile(path, (err, data) => {
    if (err) {
      res.statusCode = 404;
      res.end('Not found');
      return;
    }
    res.end(data);
  });
}

function handleRun(req, res, params) {
  const cmd = params.get('cmd') || 'ls';
  // Potentially dangerous: executing commands constructed from input
  exec(cmd, (err, stdout, stderr) => {
    if (err) {
      res.end('Execution error');
      return;
    }
    res.end(stdout);
  });
}

const server = http.createServer((req, res) => {
  const q = url.parse(req.url, true).query;
  const params = new Map(Object.entries(q));
  if (req.url.startsWith('/eval')) {
    handleEval(req, res, params);
  } else if (req.url.startsWith('/read')) {
    handleRead(req, res, params);
  } else if (req.url.startsWith('/run')) {
    handleRun(req, res, params);
  } else {
    res.end('ok');
  }
});

server.listen(PORT, () => console.log(`Server listening on ${PORT}`));
