const { pad } = require('./pkcs7')
const {
  encryptAes128Ecb,
  decryptAes128Ecb,
  encryptAes128Cbc,
  decryptAes128Cbc,
  encryptEitherECBorCBC,
  detectECBorCBC,
  findOracleBlockSize,
  crackOracleII
} = require('../set1/aes_utils')
const { parseParams, profileFor } = require('./profileUtils')

test('Challenge9: should pad correctly', () => {
  const plainText = Buffer.from('YELLOW SUBMARINE')
  const expectedPaddedText = Buffer.from('YELLOW SUBMARINE\x04\x04\x04\x04')
  expect(pad(plainText, 20)).toStrictEqual(expectedPaddedText)
})

test('Challenge10: AesECB encrypt should work', () => {
  const keyBuffer = Buffer.from('YELLOW SUBMARINE')
  const plainText = 'It is raining outside'
  const encryptedCipherText = encryptAes128Ecb(Buffer.from(plainText), keyBuffer)
  const decryptedText = decryptAes128Ecb(encryptedCipherText, keyBuffer)
  expect(decryptedText.toString()).toBe(plainText)
})

test('Challenge10: AES CBC mode should work', () => {
  const key = 'YELLOW SUBMARINE'
  const plainText = "It is sunny today and I'm going to Legoland tomorrow"
  const { encryptedBuffer, IV } = encryptAes128Cbc(plainText, key)
  // update these once decryption has been created...
  expect(encryptedBuffer).not.toBe(null)
  expect(IV).not.toBe(null)
  const decryptedText = decryptAes128Cbc(encryptedBuffer.toString('base64'), key, IV.toString('base64'))
  expect(decryptedText).toBe(plainText)
})

test('Challenge 11: encryptionOracle should work', () => {
  // 43 a's will always work because it garantees 2 x 16 byte blocks of 'a's
  // regardless of the random 5-10 byte prepended to the begining.
  const plainText = new Array(44).join('a')
  for (let i = 0; i < 10; i++) {
    const result = encryptEitherECBorCBC(plainText)
    expect(result.encryptedBuffer).not.toBe(null)
    const detectedMode = detectECBorCBC(result.encryptedBuffer)
    expect(detectedMode).toBe(result.encryptionMethod)
  }
})

test('Challenge 12: should find block size', () => {
  expect(findOracleBlockSize()).toBe(16)
})

test('Challenge 12: should crack ECB', () => {
  const expectedText = `Rollin' in my 5.0
With my rag-top down so my hair can blow
The girlies on standby waving just to say hi
Did you stop? No, I just drove by
`
  const cracked = crackOracleII()
  expect(cracked.trim()).toBe(expectedText.trim())
})

test.only('Challenge 13: parseParams should work', () => {
  const inputParams = "foo=bar&baz=qux&zap=zazzle"
  const expectedOutput = {
    foo: 'bar',
    baz: 'qux',
    zap: 'zazzle'
  }
  expect(parseParams(inputParams)).toStrictEqual(expectedOutput)
})

test.only('Challenge 13: profileFor function should work', () => {
  const emailAddress = "foo@bar.com"
  const expectedOutput = 'email=foo@bar.com&uid=10&role=user'
  expect(profileFor(emailAddress)).toBe(expectedOutput)
})

test.only('Challenge 13: email address cannot contain & or =', () => {
  const invalidEmailAddress = 'foo@bar.com&role=admin'
  expect(() => {
    profileFor(invalidEmailAddress)
  }).toThrow()
})