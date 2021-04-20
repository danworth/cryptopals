const { toBase64 } = require('./hexFunctions')

test('should convert succesfully', () => {
  const hexString = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
  const expectedBase64 = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
  expect(toBase64(hexString)).toBe(expectedBase64)
})
