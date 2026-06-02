// SAFE: errors are logged server-side, only a generic message goes out.

function handlerA(req, res) {
  try {
    doWork();
  } catch (err) {
    console.error(err); // full detail stays on the server
    res.status(500).json({ error: 'Internal Server Error' });
  }
}

function handlerB(req, res) {
  try {
    doWork();
  } catch (error) {
    logger.error(error);
    res.json({ error: 'Request failed', code: 'E_INTERNAL' });
  }
}

function handlerC(req, res) {
  try {
    doWork();
  } catch (err) {
    logger.error(err);
    res.status(400).json({ error: 'Invalid request' });
  }
}
