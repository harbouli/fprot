export class LineDecoder {
  private buffer = '';

  constructor(private readonly maxBytes: number) {}

  push(chunk: string): string[] {
    this.buffer += chunk;
    const lines: string[] = [];
    let newline = this.buffer.indexOf('\n');
    while (newline >= 0) {
      if (newline > this.maxBytes) {
        throw new Error('Incoming TCP frame exceeds the configured size limit');
      }
      const line = this.buffer.slice(0, newline);
      this.buffer = this.buffer.slice(newline + 1);
      if (line.length > 0) {
        lines.push(line);
      }
      newline = this.buffer.indexOf('\n');
    }
    if (this.buffer.length > this.maxBytes) {
      throw new Error('Incoming TCP frame exceeds the configured size limit');
    }
    return lines;
  }
}
