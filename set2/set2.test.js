const { pad } = require('./pkcs7')
const {
  encryptAes128Ecb,
  decryptAes128Ecb,
  encryptAes128Cbc,
  decryptAes128Cbc,
  encryptEitherECBorCBC,
  detectECBorCBC,
  findBlockSizeForEcb,
  crackAes128ECB
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
  expect(findBlockSizeForEcb()).toBe(16)
})

test.only('Challenge 12: should crack ECB', () => {
  const plainText = `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
  aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
  dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
  YnkK`
  const plainBuffer = Buffer.from(plainText, 'base64')
  expect(crackAes128ECB(plainBuffer)).not.toBe(null)
})
