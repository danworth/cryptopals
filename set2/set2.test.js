const { pad } = require('./pkcs7')
const {
  encryptAes128Ecb,
  decryptAes128Ecb,
  encryptAes128Cbc,
  decryptAes128Cbc,
  encryptEitherECBorCBC,
  detectECBorCBC
} = require('../set1/aes_utils')

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

test.skip('Challenge 11: encryptionOracle should work', () => {
  const plainText = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  for (let i = 0; i < 10; i++) {
    const result = encryptEitherECBorCBC(plainText)
    expect(result.encryptedBuffer).not.toBe(null)
    const detectedMode = detectECBorCBC(result.encryptedBuffer)
    expect(detectedMode).toBe(result.encryptionMethod)
  }
})
