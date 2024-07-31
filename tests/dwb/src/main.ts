import type {Snip24} from '@solar-republic/contractor';

import {readFileSync} from 'node:fs';

import {bytes, bytes_to_base64, entries} from '@blake.regalia/belt';
import {SecretApp, SecretContract, random_32} from '@solar-republic/neutrino';
import {BigNumber} from 'bignumber.js';

import {N_DECIMALS, P_LOCALSECRET_LCD, X_GAS_PRICE, k_wallet_a, k_wallet_b, k_wallet_c, k_wallet_d} from './constants';
import {upload_code, instantiate_contract} from './contract';
import {DwbValidator} from './dwb';
import {GasChecker} from './gas-checker';
import {transfer} from './snip';

const S_CONTRACT_LABEL = 'snip2x-test_'+bytes_to_base64(crypto.getRandomValues(bytes(6)));

const atu8_wasm = readFileSync('../../contract.wasm');

console.debug(`Uploading code...`);
const sg_code_id = await upload_code(k_wallet_a, atu8_wasm);

console.debug(`Instantiating contract...`);

const sa_snip = await instantiate_contract(k_wallet_a, sg_code_id, {
	name: S_CONTRACT_LABEL,
	symbol: 'TKN',
	decimals: 6,
	admin: k_wallet_a.addr,
	initial_balances: entries({
		[k_wallet_a.addr]: 100_000000n,
	}).map(([sa_account, xg_balance]) => ({
		address: sa_account,
		amount: `${xg_balance}`,
	})),
	prng_seed: bytes_to_base64(random_32()),
	config: {
		public_total_supply: true,
		enable_deposit: true,
		enable_redeem: true,
		enable_mint: true,
		enable_burn: true,
	},
});

console.debug(`Running tests against ${sa_snip}...`);

// @ts-expect-error deep instantiation
const k_contract = await SecretContract<Snip24>(P_LOCALSECRET_LCD, sa_snip);

const k_app_a = SecretApp(k_wallet_a, k_contract, X_GAS_PRICE);
const k_app_b = SecretApp(k_wallet_b, k_contract, X_GAS_PRICE);
const k_app_c = SecretApp(k_wallet_c, k_contract, X_GAS_PRICE);
const k_app_d = SecretApp(k_wallet_d, k_contract, X_GAS_PRICE);

const H_APPS = {
	a: k_app_a,
	b: k_app_b,
	c: k_app_c,
	d: k_app_d,
};

const k_dwbv = new DwbValidator(k_app_a);

console.log('# Initialized');
await k_dwbv.sync();
await k_dwbv.print();
console.log('\n');

async function transfer_chain(sx_chain: string) {
	const a_lines = sx_chain.split(/\s*\n+\s*/g).filter(s => s && /^\s*(\d+)/.test(s));

	let k_checker: GasChecker | null = null;

	for(const sx_line of a_lines) {
		const [, sx_amount, si_from, si_to] = /^\s*([\d.]+)(?:\s*TKN)?\s+(\w+)(?:\s+to|\s*[-=]*>+)?\s+(\w+)\s*/.exec(sx_line)!;

		const xg_amount = BigInt(BigNumber(sx_amount).shiftedBy(N_DECIMALS).toFixed(0));

		console.log(sx_amount, si_from, si_to);

		const g_result = await transfer(k_dwbv, xg_amount, H_APPS[si_from[0].toLowerCase()], H_APPS[si_to[0].toLowerCase()], k_checker);

		if(!k_checker) {
			k_checker = new GasChecker(g_result.tracking, g_result.gasUsed);
		}
	}
}

{
	await transfer_chain(`
		1 TKN Alice => Bob
		2 TKN Alice => Carol
		5 TKN Alice => David
		1 TKN Bob => Carol 		-- Bob's entire balance; settles Bob for 1st time
		1 TKN Carol => David 	-- should accumulate; settles Carol for 1st time
		1 TKN David => Alice 	-- re-adds Alice to buffer; settles David for 1st time
	`);

	/*
		All operations should be same gas from now on
			Alice: 93
			Bob: 0
			Carol: 1
			David: 4
	*/

	console.log('--- should all be same gas ---');

	await transfer_chain(`
		1 TKN David => Bob
		1 TKN David => Bob 		-- exact same transfer repeated
		1 TKN Alice => Bob
		1 TKN Bob => Carol
		1 TKN Alice => Carol
		1 TKN Carol => Bob 		-- yet again
	`);
}
