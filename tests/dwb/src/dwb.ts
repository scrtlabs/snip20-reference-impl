import type {SecretApp, WeakSecretAccAddr} from '@solar-republic/neutrino';

import {bytes, parse_json} from '@blake.regalia/belt';
import * as chai from 'chai';
const {expect} = chai;


import {DwbEntry} from './dwb-entry';
import {SX_ANSI_DIM_ON, SX_ANSI_RESET, fail} from './helper';

export type DwbRequirements = {
	showDelta?: boolean;
	shouldNotContainEntriesFor?: WeakSecretAccAddr[];
};

const R_ENTRY = /\s*DelayedWriteBufferEntry\(([^]*?)\)\s*,?/y;

export function parse_dwb_dump(sx_dump: string) {
	const [, sx_contents] = /DelayedWriteBuffer\s*\{\s*([^]*?)\s*\}\s*$/.exec(sx_dump)!;
	const [, sg_empty, sx_entries] = /^\s*empty_space_counter:\s*(\d+),\s*entries:\s*\[([^]*)\]\s*$/.exec(sx_contents)!;

	const a_entries: Uint8Array[] = [];
	for(;;) {
		const m_entry = R_ENTRY.exec(sx_entries)!;
		if(!m_entry) break;

		a_entries.push(bytes(parse_json<number[]>(m_entry[1])));
	}

	return {
		empty_space_counter: parse_json(sg_empty),
		entries: a_entries,
	};
}

export class DwbValidator {
	protected _a_entries_prev: DwbEntry[] = [];
	protected _a_entries: DwbEntry[] = [];
	protected _n_empty = 0;

	constructor(protected _k_app: SecretApp) {}

	get entries(): DwbEntry[] {
		return this._a_entries.slice();
	}

	get previous(): DwbEntry[] {
		return this._a_entries_prev.slice();
	}

	get empty(): number {
		return this._n_empty;
	}

	async sync() {
		// cache previous state
		this._a_entries_prev = this._a_entries.slice();

		// dump dwb contents
		const [g_dwb_res] = await this._k_app.query('dwb', {});

		// parse
		const {
			empty_space_counter: sg_empty,
			entries: a_entries,
		} = parse_dwb_dump((g_dwb_res as {dwb: string}).dwb);

		// update cached entries
		this._a_entries.length = 0;
		this._a_entries.push(...a_entries.map(atu8 => new DwbEntry(atu8)));

		// save empty spaces counter
		this._n_empty = parseFloat(sg_empty as string);

		return this._a_entries;
	}

	async check(gc_check?: DwbRequirements) {
		const a_prev = this._a_entries_prev;
		const a_entries = this._a_entries;

		// should exclude entry for given addresses
		const a_exclude = gc_check?.shouldNotContainEntriesFor;
		if(a_exclude?.length) {
			for(const sa_exclude of a_exclude) {
				const i_found = a_entries.findIndex(k => sa_exclude === k.address);

				if(i_found > -1) {
					fail(`Expected buffer to NOT contain an entry for ${sa_exclude} but found it at position ${i_found}`);
				}
			}
		}

		// count empty spaces
		let c_empty_actual = 0;
		for(let i_space=a_entries.length-1; i_space>0; i_space--) {
			if(!a_entries[i_space].amount) {
				c_empty_actual += 1;
			}
			else {
				break;
			}
		}

		// find changes
		for(let i_space=0; i_space<a_entries.length; i_space++) {
			const k_prev = a_prev[i_space];
			const k_curr = a_entries[i_space];

			// same address
			if(k_prev.address === k_curr.address) {
				// amount changed
				if(k_prev.amount && k_curr.amount && k_prev.amount !== k_curr.amount) {
					// expect it to only ever increase
					if(k_curr.amount < k_prev.amount) {
						fail(`Found a negative change in entry amount`);
					}

					// expect len to have increased by exactly 1
					if(k_curr.listlen !== k_prev.listlen + 1n) {
						fail(`List length change was not exactly 1`);
					}
				}
			}
		}

		// assert empty spaces counter
		if(c_empty_actual < this._n_empty) {
			fail(`Contract reports ${this._n_empty} empty spaces but observed ${c_empty_actual}`);
		}
	}

	toString(b_show_delta?: boolean): string {
		const a_prev = this._a_entries_prev;

		const a_lines: string[] = [
			`┏━━━━━┯━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┯━━━━━━━━━━━━━━┯━━━━━━┯━━━━━━┓`,
			`┃ idx │ address                                       │ amount       │ head │ len  ┃`,
			`┠─────┴───────────────────────────────────────────────┴──────────────┴──────┴──────┨`,
		];
		const empty_row = (c: number) => `┃   ${SX_ANSI_DIM_ON}`+`...(empty x ${c})`.padEnd(78, ' ')+`${SX_ANSI_RESET}`+' ┃';
		let i_index = 0;
		let c_empty = 0;

		for(const k_entry of this._a_entries) {
			if(k_entry.isNil) {
				c_empty += 1;
			}
			else {
				if(c_empty) {
					a_lines.push(empty_row(c_empty));
					c_empty = 0;
				}

				a_lines.push(`┃ ${(i_index+'').padStart(3, ' ')} │ ${k_entry.toString(b_show_delta? a_prev[i_index]: null)} ┃`);
			}

			i_index += 1;
		}

		if(c_empty) a_lines.push(empty_row(c_empty));

		return [
			a_lines.join('\n'),
			`┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛`,
		].join('\n');
	}

	print(b_show_delta?: boolean): void {
		console.log(this.toString(b_show_delta));
	}
}


// const g_dwb = parse_dwb_dump(`
// 	DelayedWriteBuffer {
// empty_space_counter: 61,
//  entries: [
//  	DelayedWriteBufferEntry([30, 64, 27, 13, 80, 9, 191, 112, 225, 11, 76, 117, 251, 233, 171, 52, 62, 116, 221, 165, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 
//  	DelayedWriteBufferEntry([252, 120, 243, 61, 153, 55, 155, 238, 217, 219, 75, 240, 232, 43, 128, 39, 177, 94, 70, 241, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 
//  	DelayedWriteBufferEntry([78, 34, 145, 19, 199, 90, 194, 255, 187, 156, 147, 189, 154, 40, 119, 128, 77, 51, 242, 84, 0, 0, 0, 0, 0, 152, 150, 128, 0, 0, 0, 0, 3, 0, 1]), 
//  	DelayedWriteBufferEntry([236, 133, 74, 220, 71, 232, 157, 194, 70, 160, 113, 10, 155, 74, 105, 192, 216, 151, 180, 80, 0, 0, 0, 0, 0, 30, 132, 128, 0, 0, 0, 0, 7, 0, 2]), 
//  	DelayedWriteBufferEntry([171, 152, 150, 130, 223, 89, 19, 108, 106, 73, 34, 29, 160, 38, 68, 217, 164, 90, 53, 87, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
//  	DelayedWriteBufferEntry([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
//  ]
// }
// `);

// console.log(g_dwb.entries.length);
