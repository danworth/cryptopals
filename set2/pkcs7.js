function pad (textBuffer, blockLength) {
  const difference = blockLength - textBuffer.length
  const padding = Buffer.alloc(difference).fill(difference)
  return Buffer.concat([textBuffer, padding])
}

module.exports = {
  pad
}
