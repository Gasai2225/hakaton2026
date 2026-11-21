const palette = ['#246a9b', '#7b429d', '#26735b', '#b0435b', '#99501e', '#5457a3', '#296c7d', '#825180']

export function participantColor(id: string) {
  let hash = 0
  for (const letter of id) hash = (hash * 31 + letter.charCodeAt(0)) | 0
  return palette[(hash >>> 0) % palette.length]
}
