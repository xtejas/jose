import type * as types from '../types.d.ts'
import invalidKeyInput from './invalid_key_input.js'
import { encodeBase64, decodeBase64 } from '../lib/base64.js'
import { JOSENotSupported } from '../util/errors.js'
import { isCryptoKey, isKeyObject } from './is_key_like.js'

import type { KeyImportOptions } from '../key/import.js'

/**
 * Formats a base64 string as a PEM-encoded key with proper line breaks and headers.
 *
 * @param b64 - Base64-encoded key data
 * @param descriptor - Key type descriptor (e.g., "PUBLIC KEY", "PRIVATE KEY")
 *
 * @returns PEM-formatted string
 */
const formatPEM = (b64: string, descriptor: string) => {
  const newlined = (b64.match(/.{1,64}/g) || []).join('\n')
  return `-----BEGIN ${descriptor}-----\n${newlined}\n-----END ${descriptor}-----`
}

interface ExportOptions {
  format: 'pem'
  type: 'spki' | 'pkcs8'
}

interface ExtractableKeyObject extends types.KeyObject {
  export(arg: ExportOptions): string
}

const genericExport = async (
  keyType: 'private' | 'public',
  keyFormat: 'spki' | 'pkcs8',
  key: unknown,
) => {
  if (isKeyObject(key)) {
    if (key.type !== keyType) {
      throw new TypeError(`key is not a ${keyType} key`)
    }

    return (key as ExtractableKeyObject).export({ format: 'pem', type: keyFormat })
  }

  if (!isCryptoKey(key)) {
    throw new TypeError(invalidKeyInput(key, 'CryptoKey', 'KeyObject'))
  }

  if (!key.extractable) {
    throw new TypeError('CryptoKey is not extractable')
  }

  if (key.type !== keyType) {
    throw new TypeError(`key is not a ${keyType} key`)
  }

  return formatPEM(
    encodeBase64(new Uint8Array(await crypto.subtle.exportKey(keyFormat, key))),
    `${keyType.toUpperCase()} KEY`,
  )
}

export const toSPKI = (key: unknown): Promise<string> => {
  return genericExport('public', 'spki', key)
}

export const toPKCS8 = (key: unknown): Promise<string> => {
  return genericExport('private', 'pkcs8', key)
}

/** Helper function to compare two byte arrays for equality */
const bytesEqual = (a: Uint8Array, b: readonly number[]): boolean => {
  if (a.byteLength !== b.length) return false
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

/** Shared ASN.1 DER parsing utilities */
class ASN1Parser {
  pos = 0
  readonly data: Uint8Array

  constructor(data: Uint8Array) {
    this.data = data
  }

  /** Parses ASN.1 length encoding (both short and long form) */
  parseLength(): number {
    const first = this.data[this.pos++]
    if (first & 0x80) {
      // Long form: first byte indicates number of subsequent length bytes
      const lengthOfLen = first & 0x7f
      let length = 0
      for (let i = 0; i < lengthOfLen; i++) {
        length = (length << 8) | this.data[this.pos++]
      }
      return length
    }
    // Short form: length is encoded directly in first byte
    return first
  }

  /** Skips ASN.1 elements (tag + length + content) */
  skipElement(count: number = 1): void {
    if (count <= 0) return
    this.pos++ // Skip tag byte
    const length = this.parseLength()
    this.pos += length // Skip content bytes
    if (count > 1) {
      this.skipElement(count - 1) // Recursively skip remaining elements
    }
  }

  /** Expects a specific tag and throws if not found */
  expectTag(expectedTag: number, errorMessage: string): void {
    if (this.data[this.pos++] !== expectedTag) {
      throw new Error(errorMessage)
    }
  }

  /** Expects a specific length and throws if not found */
  expectLength(expectedLength: number, errorMessage: string): void {
    const actualLen = this.parseLength()
    if (actualLen !== expectedLength) {
      throw new Error(errorMessage)
    }
  }

  /** Gets a subarray from current position */
  getSubarray(length: number): Uint8Array {
    const result = this.data.subarray(this.pos, this.pos + length)
    this.pos += length
    return result
  }

  /** Parses algorithm OID and returns the OID bytes */
  parseAlgorithmOID(): Uint8Array {
    this.expectTag(0x06, 'Expected algorithm OID')
    const oidLen = this.parseLength()
    return this.getSubarray(oidLen)
  }
}

/** Parses a PKCS#8 private key structure up to the privateKey field */
function parsePKCS8Header(parser: ASN1Parser) {
  // Parse outer SEQUENCE (PrivateKeyInfo)
  parser.expectTag(0x30, 'Invalid PKCS#8 structure')
  parser.parseLength() // Skip outer length

  // Skip version (INTEGER)
  parser.expectTag(0x02, 'Expected version field')
  const verLen = parser.parseLength()
  parser.pos += verLen

  // Parse privateKeyAlgorithm (AlgorithmIdentifier SEQUENCE)
  parser.expectTag(0x30, 'Expected algorithm identifier')
  const algIdLen = parser.parseLength()
  const algIdStart = parser.pos

  return { algIdStart, algIdLength: algIdLen }
}

/** Parses an SPKI structure up to the subjectPublicKey field */
function parseSPKIHeader(parser: ASN1Parser) {
  // Parse outer SEQUENCE (SubjectPublicKeyInfo)
  parser.expectTag(0x30, 'Invalid SPKI structure')
  parser.parseLength() // Skip outer length

  // Parse algorithm identifier (AlgorithmIdentifier SEQUENCE)
  parser.expectTag(0x30, 'Expected algorithm identifier')
  const algIdLen = parser.parseLength()
  const algIdStart = parser.pos

  return { algIdStart, algIdLength: algIdLen }
}

/** Parses algorithm identifier and returns curve name for EC/ECDH keys */
const parseECAlgorithmIdentifier = (parser: ASN1Parser): string => {
  const algOid = parser.parseAlgorithmOID()

  // id-x25519
  if (bytesEqual(algOid, [0x2b, 0x65, 0x6e])) {
    return 'X25519'
  }

  // id-ecPublicKey 1.2.840.10045.2.1
  if (!bytesEqual(algOid, [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])) {
    throw new Error('Unsupported key algorithm')
  }

  // Parse curve parameters (should be an OID for named curves)
  parser.expectTag(0x06, 'Expected curve OID')
  const curveOidLen = parser.parseLength()
  const curveOid = parser.getSubarray(curveOidLen)

  // Compare with known curve OIDs - NIST curves inlined
  for (const { name, oid } of [
    { name: 'P-256', oid: [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] }, // 1.2.840.10045.3.1.7
    { name: 'P-384', oid: [0x2b, 0x81, 0x04, 0x00, 0x22] }, // 1.3.132.0.34
    { name: 'P-521', oid: [0x2b, 0x81, 0x04, 0x00, 0x23] }, // 1.3.132.0.35
  ] as const) {
    if (bytesEqual(curveOid, oid)) {
      return name
    }
  }

  throw new Error('Unsupported named curve')
}

/** Checks if the algorithm is a post-quantum ML-DSA algorithm */
const isMLDSAAlgorithm = (alg: string): alg is MLDSAAlgorithm => {
  return alg === 'ML-DSA-44' || alg === 'ML-DSA-65' || alg === 'ML-DSA-87'
}

/** Union type for supported ML-DSA algorithm identifiers */
type MLDSAAlgorithm = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87'

/** Validates ML-DSA algorithm OID in the algorithm identifier section */
const validateMLDSAAlgorithmIdentifier = (
  parser: ASN1Parser,
  expectedAlg: MLDSAAlgorithm,
): void => {
  // Final arc mapping for each ML-DSA variant
  const finalArcMap: Record<MLDSAAlgorithm, number> = {
    'ML-DSA-44': 0x11, // 17 for 2.16.840.1.101.3.4.3.17
    'ML-DSA-65': 0x12, // 18 for 2.16.840.1.101.3.4.3.18
    'ML-DSA-87': 0x13, // 19 for 2.16.840.1.101.3.4.3.19
  }

  const expectedFinalArc = finalArcMap[expectedAlg]

  // Complete ML-DSA OID: 2.16.840.1.101.3.4.3.{17|18|19}
  const expectedOid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, expectedFinalArc]

  // Validate OID tag and length
  parser.expectTag(0x06, `Invalid ML-DSA OID tag`)
  parser.expectLength(expectedOid.length, `Invalid ML-DSA OID length`)

  // Validate all OID bytes in a single loop
  for (let i = 0; i < expectedOid.length; i++) {
    const expected = expectedOid[i]
    const actual = parser.data[parser.pos]
    if (actual !== expected) {
      throw new Error(`Invalid ML-DSA OID`)
    }
    parser.pos += 1
  }
}

const genericImport = async (
  keyFormat: 'spki' | 'pkcs8',
  keyData: Uint8Array,
  alg: string,
  options?: KeyImportOptions & { getNamedCurve?: (keyData: Uint8Array) => string },
) => {
  let algorithm: RsaHashedImportParams | EcKeyAlgorithm | Algorithm
  let keyUsages: KeyUsage[]

  const isPublic = keyFormat === 'spki'

  // Helper functions for determining key usage based on key type
  const getSigUsages = (): KeyUsage[] => (isPublic ? ['verify'] : ['sign'])
  const getEncUsages = (): KeyUsage[] =>
    isPublic ? ['encrypt', 'wrapKey'] : ['decrypt', 'unwrapKey']

  switch (alg) {
    case 'PS256':
    case 'PS384':
    case 'PS512':
      algorithm = { name: 'RSA-PSS', hash: `SHA-${alg.slice(-3)}` }
      keyUsages = getSigUsages()
      break
    case 'RS256':
    case 'RS384':
    case 'RS512':
      algorithm = { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${alg.slice(-3)}` }
      keyUsages = getSigUsages()
      break
    case 'RSA-OAEP':
    case 'RSA-OAEP-256':
    case 'RSA-OAEP-384':
    case 'RSA-OAEP-512':
      algorithm = {
        name: 'RSA-OAEP',
        hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`,
      }
      keyUsages = getEncUsages()
      break
    case 'ES256':
    case 'ES384':
    case 'ES512': {
      const curveMap = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' } as const
      algorithm = { name: 'ECDSA', namedCurve: curveMap[alg] }
      keyUsages = getSigUsages()
      break
    }
    case 'ECDH-ES':
    case 'ECDH-ES+A128KW':
    case 'ECDH-ES+A192KW':
    case 'ECDH-ES+A256KW': {
      try {
        const namedCurve = options!.getNamedCurve!(keyData)
        algorithm = namedCurve === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve }
      } catch (cause) {
        throw new JOSENotSupported('Invalid or unsupported key format')
      }
      keyUsages = isPublic ? [] : ['deriveBits']
      break
    }
    case 'Ed25519':
    case 'EdDSA':
      algorithm = { name: 'Ed25519' }
      keyUsages = getSigUsages()
      break
    case 'ML-DSA-44':
    case 'ML-DSA-65':
    case 'ML-DSA-87':
      algorithm = { name: alg }
      keyUsages = getSigUsages()
      break
    default:
      throw new JOSENotSupported('Invalid or unsupported "alg" (Algorithm) value')
  }

  return crypto.subtle.importKey(
    keyFormat,
    keyData,
    algorithm,
    options?.extractable ?? (isPublic ? true : false),
    keyUsages,
  )
}

type PEMImportFunction = (
  pem: string,
  alg: string,
  options?: KeyImportOptions,
) => Promise<types.CryptoKey>

/** Helper function to process PEM-encoded data */
const processPEMData = (pem: string, pattern: RegExp): Uint8Array => {
  return decodeBase64(pem.replace(pattern, ''))
}

export const fromPKCS8: PEMImportFunction = (pem, alg, options?) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g)

  let opts: Parameters<typeof genericImport>[3] = options

  if (isMLDSAAlgorithm(alg)) {
    // Inline ML-DSA private key import logic
    const parser = new ASN1Parser(keyData)

    try {
      // Inline extractMLDSASeed logic
      const { algIdStart, algIdLength } = parsePKCS8Header(parser)

      // Validate the OID in the algorithm identifier
      validateMLDSAAlgorithmIdentifier(parser, alg)

      // Skip to the end of the algorithm identifier
      parser.pos = algIdStart + algIdLength

      // Parse privateKey (OCTET STRING containing ML-DSA-PrivateKey)
      parser.expectTag(0x04, 'Expected private key octet string')
      parser.parseLength() // Skip private key length

      // Now parse the ML-DSA-PrivateKey structure inside the OCTET STRING
      const tag = parser.getSubarray(1)[0]
      const length = parser.parseLength()

      let seed: Uint8Array
      if (tag === 0x80) {
        // Case 1: seed [0] OCTET STRING (SIZE (32))
        if (length !== 32) throw new Error('Invalid seed length')
        seed = parser.getSubarray(32)
      } else if (tag === 0x04) {
        // Case 2: expandedKey OCTET STRING (SIZE (2560))
        throw new Error('No seed in expanded key')
      } else if (tag === 0x30) {
        // Case 3: both SEQUENCE { seed OCTET STRING (SIZE (32)), expandedKey OCTET STRING (SIZE (2560)) }
        // Parse seed from the sequence
        parser.expectTag(0x04, 'Expected seed octet string in sequence')
        const seedLen = parser.parseLength()
        if (seedLen !== 32) throw new Error('Invalid seed length in sequence')
        seed = parser.getSubarray(32)
      } else {
        throw new Error('Unsupported ML-DSA key format')
      }

      return crypto.subtle.importKey(
        'raw-seed' as any,
        seed,
        { name: alg },
        options?.extractable ?? false,
        ['sign'],
      )
    } catch (cause) {
      throw new TypeError('Invalid ML-DSA private key', { cause })
    }
  }

  if (alg?.startsWith?.('ECDH-ES')) {
    opts ||= {}
    opts.getNamedCurve = (keyData: Uint8Array) => {
      const parser = new ASN1Parser(keyData)
      parsePKCS8Header(parser)
      return parseECAlgorithmIdentifier(parser)
    }
  }

  return genericImport('pkcs8', keyData, alg, opts)
}

export const fromSPKI: PEMImportFunction = (pem, alg, options?) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g)

  let opts: Parameters<typeof genericImport>[3] = options
  if (isMLDSAAlgorithm(alg)) {
    // Inline ML-DSA public key import logic
    const parser = new ASN1Parser(keyData)

    try {
      // Inline extractMLDSAPublicKey logic
      const { algIdStart, algIdLength } = parseSPKIHeader(parser)

      // Validate the OID in the algorithm identifier
      validateMLDSAAlgorithmIdentifier(parser, alg)

      // Skip to the end of the algorithm identifier
      parser.pos = algIdStart + algIdLength

      // Parse subjectPublicKey (BIT STRING)
      parser.expectTag(0x03, 'Expected public key bit string')
      const bitStringLen = parser.parseLength()

      // Skip the unused bits byte (first byte of BIT STRING content)
      parser.pos++

      // Extract the actual public key bytes (remaining BIT STRING content)
      const publicKeyLen = bitStringLen - 1 // Subtract 1 for the unused bits byte
      const publicKey = parser.getSubarray(publicKeyLen)

      // Validate extracted public key length
      if (publicKey.byteLength === 0) {
        throw new Error('Empty ML-DSA public key')
      }

      // Validate algorithm-specific public key length
      const expectedLengths: Record<MLDSAAlgorithm, number> = {
        'ML-DSA-44': 1312,
        'ML-DSA-65': 1952,
        'ML-DSA-87': 2592,
      }

      const expectedLen = expectedLengths[alg]
      if (expectedLen && publicKey.byteLength !== expectedLen) {
        throw new Error(`Invalid ${alg} key length`)
      }

      return crypto.subtle.importKey(
        'raw-public' as any,
        publicKey,
        { name: alg },
        options?.extractable ?? true,
        ['verify'],
      )
    } catch (cause) {
      throw new TypeError('Invalid ML-DSA public key', { cause })
    }
  }

  if (alg?.startsWith?.('ECDH-ES')) {
    opts ||= {}
    opts.getNamedCurve = (keyData: Uint8Array) => {
      const parser = new ASN1Parser(keyData)
      parseSPKIHeader(parser)
      return parseECAlgorithmIdentifier(parser)
    }
  }

  return genericImport('spki', keyData, alg, opts)
}

/**
 * Extracts the Subject Public Key Info (SPKI) from an X.509 certificate. Parses the ASN.1 DER
 * structure to locate and extract the public key portion.
 *
 * @param buf - DER-encoded X.509 certificate bytes
 *
 * @returns SPKI structure as bytes
 */
function spkiFromX509(buf: Uint8Array): Uint8Array {
  const parser = new ASN1Parser(buf)

  // Parse outer certificate SEQUENCE
  parser.expectTag(0x30, 'Invalid certificate structure')
  parser.parseLength() // Skip certificate length

  // Parse tbsCertificate (To Be Signed Certificate) SEQUENCE
  parser.expectTag(0x30, 'Invalid tbsCertificate structure')
  parser.parseLength() // Skip tbsCertificate length

  if (buf[parser.pos] === 0xa0) {
    // Optional version field present (context-specific [0])
    // Skip: version, serialNumber, signature algorithm, issuer, validity, subject
    parser.skipElement(6)
  } else {
    // No version field (defaults to v1)
    // Skip: serialNumber, signature algorithm, issuer, validity, subject
    parser.skipElement(5)
  }

  // Extract subjectPublicKeyInfo SEQUENCE
  const spkiStart = parser.pos
  parser.expectTag(0x30, 'Invalid SPKI structure')
  const spkiContentLen = parser.parseLength()

  // Return the complete SPKI structure (tag + length + content)
  return buf.subarray(spkiStart, spkiStart + spkiContentLen + (parser.pos - spkiStart))
}

/**
 * Extracts SPKI from a PEM-encoded X.509 certificate string.
 *
 * @param x509 - PEM-encoded X.509 certificate
 *
 * @returns SPKI structure as bytes
 */
function extractX509SPKI(x509: string): Uint8Array {
  const derBytes = processPEMData(x509, /(?:-----(?:BEGIN|END) CERTIFICATE-----|\s)/g)
  return spkiFromX509(derBytes)
}

export const fromX509: PEMImportFunction = (pem, alg, options?) => {
  let spki: Uint8Array
  try {
    spki = extractX509SPKI(pem)
  } catch (cause) {
    throw new TypeError('Failed to parse the X.509 certificate', { cause })
  }
  return fromSPKI(formatPEM(encodeBase64(spki), 'PUBLIC KEY'), alg, options)
}
