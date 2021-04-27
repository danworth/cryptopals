function toBase64 (hexString) {
  return Buffer.from(hexString, 'hex').toString('base64')
}

module.exports = {
  toBase64
}
