export async function sourceText(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer())
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes).replace(/\r\n?/g, '\n')
  } catch {
    if (!file.name.endsWith('.properties')) throw new Error('Требуется UTF-8 для файла ' + file.name)
    // Java resource bundles can also use ISO-8859-1, a direct byte-to-code-point mapping.
    return Array.from(bytes, byte => String.fromCharCode(byte)).join('').replace(/\r\n?/g, '\n')
  }
}
