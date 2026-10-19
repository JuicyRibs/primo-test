# Primo Encryption API

NestJS HTTP server with two encryption endpoints, Swagger, unit tests and HTTP integration tests. Requires Node.js 22.13+ and npm. Run commands from the project root.

## Start the service

```sh
npm ci
npm run keys:generate
npm start
```

Open **http://localhost:3000/api-docs** to view and try both APIs. OpenAPI JSON is available at `/api-docs-json`.

`keys:generate` creates a local 2048-bit RSA pair and refuses to overwrite either existing key. Run it once; keep the same keys across restarts to decrypt previous responses. The private key and `.env` are excluded from Git. Restrict private-key file access with your operating system's permissions (Windows ACLs on Windows).

For supplied keys from [CryptoTools RSA generator](https://cryptotools.net/rsagen), save the matching PEM files as `keys/private.pem` and `keys/public.pem`, and skip `keys:generate`. PKCS#1 and PKCS#8 RSA private keys and PKCS#1/SPKI public keys are supported. Keys must be unencrypted RSA PEM files, at least 2048 bits. Local generation avoids passing private-key material through an external website.

Copy `.env.example` to `.env` to change these defaults:

```dotenv
PORT=3000
RSA_PRIVATE_KEY_PATH=./keys/private.pem
RSA_PUBLIC_KEY_PATH=./keys/public.pem
```

Existing environment variables take precedence. Key paths are relative to the working directory. Startup fails on missing, invalid, weak or mismatched keys and invalid ports. No keys are generated automatically during startup.

```sh
npm run start:dev   # Rebuild and restart on src changes
npm run build      # Compile to dist/
npm run start:prod # Run the compiled service
npm test           # Unit and HTTP integration tests; generates temporary test keys
npm run test:coverage
```

Tests use Node's built-in test runner and real cryptographic operations. They do not require `.env` or development keys.

## API

Send `Content-Type: application/json`. Both endpoints return HTTP 200 on success:

```json
{ "successful": true, "error_code": "", "data": {} }
```

### POST /get-encrypt-data

```json
{ "payload": "Hello NestJS" }
```

`payload` is a required string containing 0–2000 Unicode code points. An empty string is valid. Missing/null/non-string values, unknown fields and longer strings are rejected. Combining marks count separately.

```json
{
  "successful": true,
  "error_code": "",
  "data": {
    "data1": "<base64 RSA-encrypted AES key>",
    "data2": "<base64 IV + GCM tag + ciphertext>"
  }
}
```

For each request:

1. Generate 32 cryptographically random bytes and encode them as a 64-character hex string.
2. Decode that string to a 256-bit AES key. Encrypt the UTF-8 payload with AES-256-GCM and a fresh 12-byte random IV.
3. Encrypt the UTF-8/ASCII hex key string with the RSA **private** key using `RSA_PKCS1_PADDING`; Base64-encode it as `data1`.
4. Concatenate the 12-byte IV, 16-byte authentication tag and ciphertext, then Base64-encode the result as `data2`.

### POST /get-decrypt-data

```json
{ "data1": "<data1 from encryption response>", "data2": "<data2 from encryption response>" }
```

Both fields are required, nonempty Base64 strings. The service recovers the AES key string using the RSA **public** key, decodes the hex key, authenticates/decrypts `data2`, and returns:

```json
{ "successful": true, "error_code": "", "data": { "payload": "Hello NestJS" } }
```

An IV, tag, ciphertext or key change fails decryption. Malformed RSA data, invalid UTF-8 and recovered payloads longer than 2000 code points also fail. The JSON body limit is 64 KiB.

### Errors

All API errors use this envelope:

```json
{ "successful": false, "error_code": "VALIDATION_ERROR", "data": null }
```

- HTTP 400 `VALIDATION_ERROR`: invalid fields, wrong types, invalid Base64 or malformed JSON.
- HTTP 400 `INVALID_ENCRYPTED_DATA`: syntactically valid inputs that fail decoding, key recovery, authentication or plaintext validation.
- HTTP 413 `PAYLOAD_TOO_LARGE`: request body exceeds 64 KiB.
- HTTP 404 `NOT_FOUND`: unknown route or unsupported route method.
- HTTP 500 `INTERNAL_ERROR`: unexpected error; details are logged server-side, not returned to clients.

### PowerShell round trip

```powershell
$encrypted = Invoke-RestMethod -Method Post -Uri http://localhost:3000/get-encrypt-data -ContentType 'application/json' -Body (@{ payload = 'Hello NestJS' } | ConvertTo-Json)
$decrypted = Invoke-RestMethod -Method Post -Uri http://localhost:3000/get-decrypt-data -ContentType 'application/json' -Body ($encrypted.data | ConvertTo-Json)
$decrypted.data.payload
```

## Security of the requested RSA direction

This implementation follows the specified private-key encryption/public-key decryption direction. **Anyone holding the public key can recover the AES key, read the payload, and create replacement AES ciphertext using that recovered key.** GCM detects tampering without the AES key; it does not establish sender identity against a public-key holder in this protocol. This is not a digital signature scheme.

For confidentiality against public-key holders, the protocol must instead wrap the AES key with the public key using RSA-OAEP and unwrap it with the private key. Use an actual signature scheme if sender authentication is needed. Those changes would alter the requested protocol.

References: [NestJS validation](https://docs.nestjs.com/techniques/validation), [NestJS Swagger](https://docs.nestjs.com/openapi/introduction), [Node.js crypto](https://nodejs.org/api/crypto.html).
