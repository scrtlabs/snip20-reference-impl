import type {GroupedGasLogs} from './snip';

import {entries} from '@blake.regalia/belt';

import {SX_ANSI_GREEN, SX_ANSI_MAGENTA, SX_ANSI_RESET} from './helper';

export class GasChecker {
	constructor(protected _h_baseline: GroupedGasLogs, protected _xg_used: bigint) {}

	compare(h_local: GroupedGasLogs, xg_used: bigint) {
		const {_h_baseline, _xg_used} = this;

		console.log(`  ⚖️  Gas usage relative to baseline:  ${xg_used === _xg_used
			? `${SX_ANSI_GREEN}0`
			: `${SX_ANSI_MAGENTA}${xg_used > _xg_used? '+': ''}${xg_used - _xg_used}`
		}${SX_ANSI_RESET}`);

		// each group
		for(const [si_group, a_logs_local] of entries(h_local)) {
			// logs emitted from this transfer group
			let c_logs = 0;

			// find group in baseline
			const a_logs_baseline = _h_baseline[si_group];

			// offset
			const xg_previous = a_logs_local[0]?.gas;

			// each log
			for(let i_log=1; i_log<a_logs_local.length; i_log++) {
				// ref log
				const g_log_local = a_logs_local[i_log];

				const g_log_baseline = a_logs_baseline.find(g => g.index === g_log_local.index)!;

				const xg_gap_baseline = g_log_baseline.gap;
				const xg_gap_local = g_log_local.gap;

				// calculate delta
				const xg_delta = xg_gap_local - xg_gap_baseline;

				// non-zero delta
				if(xg_delta) {
					console.log(`        ${si_group.slice(0, 20).padEnd(20, ' ')} │ ${((xg_delta > 0? '+': '')+xg_delta).padEnd(5, ' ')} │ ${g_log_local.comment}`);
					c_logs += 1;
				}
			}
		}
	}
}
