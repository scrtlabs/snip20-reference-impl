import type {GroupedGasLogs} from './snip';

import {entries, bigint_abs} from '@blake.regalia/belt';

import {SX_ANSI_GREEN, SX_ANSI_RED, SX_ANSI_MAGENTA, SX_ANSI_RESET, SX_ANSI_YELLOW, SX_ANSI_CYAN} from './helper';

const delta_color = (xg_delta: bigint, nl_pad=0) => (bigint_abs(xg_delta) >= 1n
	? bigint_abs(xg_delta) > 2n
		? SX_ANSI_RED
		: SX_ANSI_YELLOW
	: '')+((xg_delta > 0? '+': '')+xg_delta).padStart(nl_pad, ' ')+SX_ANSI_RESET;

export class GasChecker {
	constructor(protected _h_baseline: GroupedGasLogs, protected _xg_used: bigint) {}

	compare(h_local: GroupedGasLogs, xg_used: bigint): void {
		const {_h_baseline, _xg_used} = this;

		console.log(`  ⚖️  Gas usage relative to baseline:  ${xg_used === _xg_used
			? `${SX_ANSI_GREEN}0`
			: delta_color(xg_used - _xg_used)
		}${SX_ANSI_RESET}`);

		// each group
		for(const [si_group, a_logs_local] of entries(h_local)) {
			// find group in baseline
			const a_logs_baseline = _h_baseline[si_group];

			// offset
			const xg_previous = a_logs_local[0]?.gas;

			// each log
			for(let i_log=1; i_log<a_logs_local.length; i_log++) {
				// ref log
				const {
					index: i_local,
					gap: xg_gap_local,
					comment: s_comment_local,
				} = a_logs_local[i_log];

				const g_log_baseline = a_logs_baseline.find(g => g.index === i_local);

				const xg_gap_baseline = g_log_baseline?.gap || 0n;

				// calculate delta
				const xg_delta = xg_gap_local - xg_gap_baseline;

				// comment only
				if('#' === si_group[0]) {
					if(s_comment_local.trim()) {
						console.log([
							' '.repeat(8)+si_group.slice(0, 20).padEnd(20, ' '),
							' '.repeat(3),
							SX_ANSI_CYAN+s_comment_local+SX_ANSI_RESET,
						].join(' │ '));
					}
				}
				// non-zero delta
				else if(xg_delta || '@' === s_comment_local[0]) {
					console.log([
						' '.repeat(8)+si_group.slice(0, 20).padEnd(20, ' '),
						delta_color(xg_delta, 3),
						('@' === s_comment_local[0]? SX_ANSI_MAGENTA: '')+s_comment_local+SX_ANSI_RESET,
					].join(' │ '));
				}
			}
		}
	}
}
