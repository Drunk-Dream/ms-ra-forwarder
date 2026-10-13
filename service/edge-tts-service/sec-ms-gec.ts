import { createHash } from 'node:crypto'

// Algorithm reference (Edge 153.0.4234.48, normal browser mode):
// https://github.com/rany2/edge-tts/issues/490#issuecomment-6126621790
// This literal is protocol input; it must not be translated or terminated with NUL.
const PREFIX = 'Copyright (C) Microsoft Corporation. All rights reserved.'
const UNIX_TO_FILETIME_MS = 11644473600000n

function rotate16(value: number): number {
    return ((value << 16) | (value >>> 16)) >>> 0
}

export function generateSecMsGecV2(speechKey: string, unixMs = Date.now()): string {
    if (!Number.isSafeInteger(unixMs) || unixMs < 0) {
        throw new RangeError('Timestamp must be a nonnegative safe integer in milliseconds')
    }
    if (/[^\x00-\x7f]/.test(speechKey)) {
        throw new TypeError('Speech key must contain only ASCII characters')
    }
    const ticks = ((BigInt(unixMs) + UNIX_TO_FILETIME_MS) / 300000n) * 3000000000n
    const input = Buffer.from(`${PREFIX}${ticks}${speechKey}`, 'ascii')
    const digest = createHash('sha256').update(input).digest()
    // Little-endian u32 words, zero-padded to an even number of words.
    const words = Buffer.alloc(Math.ceil(input.length / 8) * 8)
    input.copy(words)
    const a = digest.readUInt32LE(0) | 1
    const b = digest.readUInt32LE(4) | 1
    let swapLast = 0
    let swapSum = 0
    let state = 0
    let reversibleSum = 0

    for (let offset = 0; offset < words.length; offset += 8) {
        const x = words.readUInt32LE(offset)
        const y = words.readUInt32LE(offset + 4)

        // Math.imul preserves the low 32 bits, including overflow, of each product.
        let t = (Math.imul(rotate16(x), 0xEF0569FB) + Math.imul(x, a)) >>> 0
        let q = Math.imul(rotate16(t), 0x76F50F34) >>> 0
        q = (Math.imul(rotate16(q), 0xC3EFEA97) + q) >>> 0
        swapSum = (swapSum + q) >>> 0
        t = (Math.imul(rotate16(y), 0xC31713DB) + Math.imul(y, b)) >>> 0
        q = Math.imul(rotate16(t), 0x1881CE3C) >>> 0
        swapLast = (Math.imul(rotate16(q), 0x35BD1EC9) + q) >>> 0
        swapSum = (swapSum + swapLast) >>> 0

        state = Math.imul((state + x) >>> 0, a) >>> 0
        for (const constant of [0xCF98B111, 0x87085B9F, 0x12CEB96D, 0x257E1D83]) {
            state = Math.imul(rotate16(state), constant) >>> 0
        }
        t = Math.imul((y + state) >>> 0, b) >>> 0
        t = Math.imul(rotate16(t), 0xA27416F5) >>> 0
        t = Math.imul(rotate16(t), 0xD38396FF) >>> 0
        t = rotate16(t)
        reversibleSum = (reversibleSum + state) >>> 0
        state = Math.imul(rotate16(Math.imul(t, 0x7C932B89)), 0xBFA49F69) >>> 0
        reversibleSum = (reversibleSum + state) >>> 0
    }

    const patentHash = Buffer.alloc(8)
    patentHash.writeUInt32LE((swapLast ^ state) >>> 0, 0)
    patentHash.writeUInt32LE((swapSum ^ reversibleSum) >>> 0, 4)
    return `${patentHash.toString('hex')}-${digest.toString('hex')}`.toUpperCase()
}
