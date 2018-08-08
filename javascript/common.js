/*
 * Javascript common functions
 * 
 * Author: Crifan Li
 * Updated: 20180808
 * 
 */

// range(10, 0, -1)
// range(0, 5, 1)
export function range(start, stop, step) {
  // console.log(`range: start=${start}, stop=${stop}, step=${step}`)

  let realStop = stop
  let realStart = start
  let realStep = step

  if (typeof realStop === 'undefined') {
      // one param defined
      realStop = realStart
      realStart = 0
  }

  if (typeof realStep === 'undefined') {
    realStep = 1
  }
  // console.log(`range: start=${start}, stop=${stop}, step=${step}`)

  if ((realStep > 0 && realStart >= realStop) || (realStep < 0 && realStart <= realStop)) {
      // return []
      return [realStart]
  }

  const result = []
  for (let i = realStart; realStep > 0 ? i < realStop : i > realStop; i += realStep) {
      result.push(i)
  }

  return result
}
