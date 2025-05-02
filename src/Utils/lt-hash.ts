import { hkdf } from './crypto'

/**
 * LT Hash is a summation based hash algorithm that maintains the integrity of a piece of data
 * over a series of mutations. You can add/remove mutations and it'll return a hash equal to
 * if the same series of mutations was made sequentially.
 */

const o = 128

// 🔁 Konversi aman ke ArrayBuffer
const toArrayBuffer = (input) => {
	if (input instanceof ArrayBuffer) return input
	if (Buffer.isBuffer(input)) {
		return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength)
	}
	if (input?.buffer instanceof ArrayBuffer) {
		return input.buffer
	}
	throw new Error('Expected ArrayBuffer or Buffer, got ' + typeof input)
}

class d {
	salt: string

	constructor(e: string) {
		this.salt = e
	}

	add(e, t) {
		for (const item of t) {
			e = this._addSingle(e, item)
		}
		return e
	}

	subtract(e, t) {
		for (const item of t) {
			e = this._subtractSingle(e, item)
		}
		return e
	}

	subtractThenAdd(e, t, r) {
		return this.add(this.subtract(e, r), t)
	}

	async _addSingle(e, t) {
		const hashed = new Uint8Array(await hkdf(Buffer.from(t), o, { info: this.salt })).buffer
		return this.performPointwiseWithOverflow(await e, hashed, (x, y) => x + y)
	}

	async _subtractSingle(e, t) {
		const hashed = new Uint8Array(await hkdf(Buffer.from(t), o, { info: this.salt })).buffer
		return this.performPointwiseWithOverflow(await e, hashed, (x, y) => x - y)
	}

	performPointwiseWithOverflow(e, t, r) {
		const n = new DataView(toArrayBuffer(e))
		const i = new DataView(toArrayBuffer(t))
		const a = new ArrayBuffer(n.byteLength)
		const s = new DataView(a)

		for (let offset = 0; offset < n.byteLength; offset += 2) {
			s.setUint16(offset, r(n.getUint16(offset, true), i.getUint16(offset, true)), true)
		}

		return a
	}
}

export const LT_HASH_ANTI_TAMPERING = new d('WhatsApp Patch Integrity')
