// Deliberately insecure TLS setting for scanner evaluation.
const client = createClient({ rejectUnauthorized: false });

function calculate(value) {
  debugger;
  return eval(value);
}

export { client, calculate };
