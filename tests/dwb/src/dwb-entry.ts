import type {Nilable} from '@blake.regalia/belt';
import type {CwSecretAccAddr} from '@solar-republic/types';

import {bytes_to_biguint_be, bytes_to_hex} from '@blake.regalia/belt';
import {bech32_encode} from '@solar-republic/crypto';
import {BigNumber} from 'bignumber.js';

import {H_ADDRS} from './constants';
import {SX_ANSI_BLUE, SX_ANSI_DIM_ON, SX_ANSI_GREEN, SX_ANSI_RESET, SX_ANSI_YELLOW} from './helper';

const NB_ADDR = 20;
const NB_AMOUNT = 8;
const NB_HEAD = 5;
const NB_LEN = 2;

const NB_ENTRY = NB_ADDR+NB_AMOUNT+NB_HEAD+NB_LEN;

export class DwbEntry {
	constructor(protected _atu8_raw: Uint8Array) {
		if(this._atu8_raw.byteLength !== NB_ENTRY) {
			throw Error(`DWB entry was not exactly ${NB_ENTRY} bytes in length`);
		}
	}

	get raw(): Uint8Array {
		return this._atu8_raw;
	}

	get isNil(): boolean {
		return /^0+$/.test(bytes_to_hex(this._atu8_raw));
	}

	get address(): CwSecretAccAddr {
		return bech32_encode('secret', this._atu8_raw.subarray(0, NB_ADDR));
	}

	get amount(): bigint {
		return bytes_to_biguint_be(this._atu8_raw.subarray(NB_ADDR, NB_ADDR+NB_AMOUNT));
	}

	get head(): bigint {
		return bytes_to_biguint_be(this._atu8_raw.subarray(NB_ADDR+NB_AMOUNT, NB_ADDR+NB_AMOUNT+NB_HEAD));
	}

	get listlen(): bigint {
		return bytes_to_biguint_be(this._atu8_raw.subarray(NB_ADDR+NB_AMOUNT+NB_HEAD, NB_ADDR+NB_AMOUNT+NB_HEAD+NB_LEN));
	}

	toString(k_prev?: Nilable<DwbEntry>): string {
		let s_alias = H_ADDRS[this.address] || '';
		s_alias += s_alias? ` (${this.address.slice(0, 12)+'...'+this.address.slice(-5)})`: this.address;
		s_alias = s_alias.padEnd(45, ' ');

		let s_amount = BigNumber(this.amount+'').shiftedBy(-6).toFixed(6).padStart(12, ' ');

		if(k_prev) {
			if(this.address !== k_prev.address) {
				const sx_color = this.amount? SX_ANSI_GREEN: SX_ANSI_YELLOW;

				s_alias = `${sx_color}${s_alias}${SX_ANSI_RESET}`;
				s_amount = `${sx_color}${s_amount}${SX_ANSI_RESET}`;
			}
			else if(this.amount !== k_prev.amount) {
				s_alias = `${SX_ANSI_BLUE}${s_alias}${SX_ANSI_RESET}`;
				s_amount = `${SX_ANSI_BLUE}${s_amount}${SX_ANSI_RESET}`;
			}
		}

		return [
			s_alias,
			s_amount,
			(this.head+'').padStart(4, ' '),
			(this.listlen+'').padStart(4, ' '),
		].map(s => this.amount? s: `${SX_ANSI_DIM_ON}${s}${SX_ANSI_RESET}`).join(' │ ');
	}
}
