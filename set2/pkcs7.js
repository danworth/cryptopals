function pad (text, blockLength) {
  const textBuffer = Buffer.from(text)
  const difference = blockLength - textBuffer.length
  const padding = Buffer.alloc(difference).fill(difference)
  return Buffer.concat([textBuffer, padding]).toString()
}

module.exports = {
  pad
}