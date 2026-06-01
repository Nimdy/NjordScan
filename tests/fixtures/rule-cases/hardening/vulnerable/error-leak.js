// VULNERABLE: error detail leaked to the client.

function handlerA(req, res) {
  try {
    doWork();
  } catch (err) {
    // fires: info-leak.error-stack-to-client
    res.status(500).send(err.stack);
  }
}

function handlerB(req, res) {
  try {
    doWork();
  } catch (error) {
    // fires: info-leak.error-stack-to-client (whole error object out)
    res.json({ error: error });
  }
}

function handlerC(req, res) {
  try {
    doWork();
  } catch (err) {
    // fires: info-leak.error-message-to-client
    res.status(400).json({ error: err.message });
  }
}
