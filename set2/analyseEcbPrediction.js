const { encryptEitherECBorCBC, detectECBorCBC } = require('../set1/aes_utils')
const { plot } = require('nodeplotlib')

const results = {}
for (let plainTextLength = 8; plainTextLength < 100; plainTextLength++) {
  const plainText = new Array(plainTextLength + 1).join('a')
  results[plainTextLength] = 0
  for (let atempt = 0; atempt < 100; atempt++) {
    const { encryptedBuffer, encryptionMethod } = encryptEitherECBorCBC(plainText)
    const predictedMethod = detectECBorCBC(encryptedBuffer)
    if (predictedMethod === encryptionMethod) {
      results[plainTextLength]++
    }
  }
}

const plotData = {
  x: Object.keys(results),
  y: Object.values(results),
  type: 'scatter'
}

const layout = {
  xaxis: { title: "How many consecutive 'a's in the plain text" },
  yaxis: { title: 'Prediction accuracy out of 100' }
}

plot([plotData], layout)
