import type {Dict, JsonObject} from '@blake.regalia/belt';

import type {SecretContractInterface, FungibleTransferCall, SecretAccAddr, Snip24} from '@solar-republic/contractor';

import type {CwUint128, WeakUint128Str} from '@solar-republic/types';

import {readFileSync} from 'node:fs';

import {bytes, bytes_to_base64, entries, sha256, text_to_bytes, bigint_greater, bigint_abs} from '@blake.regalia/belt';
import {encodeCosmosBankMsgSend, SI_MESSAGE_TYPE_COSMOS_BANK_MSG_SEND} from '@solar-republic/cosmos-grpc/cosmos/bank/v1beta1/tx';
import {encodeGoogleProtobufAny} from '@solar-republic/cosmos-grpc/google/protobuf/any';
import {SecretApp, SecretContract, Wallet, broadcast_result, create_and_sign_tx_direct, random_32, type TxMeta, type WeakSecretAccAddr} from '@solar-republic/neutrino';
import {BigNumber} from 'bignumber.js';

import {B_TEST_EVAPORATION, N_DECIMALS, P_SECRET_LCD, P_SECRET_RPC, SI_SECRET_CHAIN, X_GAS_PRICE, k_wallet_a, k_wallet_b, k_wallet_c, k_wallet_d} from './constants';
import {upload_code, instantiate_contract} from './contract';
import {DwbValidator} from './dwb';
import {GasChecker} from './gas-checker';
import {transfer, type TransferResult} from './snip';

const S_CONTRACT_LABEL = 'snip2x-test_'+bytes_to_base64(crypto.getRandomValues(bytes(6)));

const atu8_wasm = readFileSync('../../contract.wasm');

console.log(k_wallet_a.addr);

console.debug(`Uploading code...`);
const sg_code_id = await upload_code(k_wallet_a, atu8_wasm);

console.debug(`Instantiating contract...`);

const sa_snip = await instantiate_contract(k_wallet_a, sg_code_id, {
	name: S_CONTRACT_LABEL,
	symbol: 'TKN',
	decimals: 6,
	admin: k_wallet_a.addr,
	initial_balances: entries({
		[k_wallet_a.addr]: 10_000_000000n,
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
const k_contract = await SecretContract<SecretContractInterface<{
	extends: Snip24;
	executions: {
		transfer: [FungibleTransferCall & {
			gas_target?: WeakUint128Str;
		}];
	};
}>>(P_SECRET_LCD, sa_snip);

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

// #ts-expect-error validator!
const k_dwbv = new DwbValidator(k_app_a);

async function transfer_chain(sx_chain: string) {
	const a_lines = sx_chain.split(/\s*\n+\s*/g).filter(s => s && /^\s*(\d+)/.test(s));

	let k_checker: GasChecker | null = null;

	for(const sx_line of a_lines) {
		const [, sx_amount, si_from, si_to] = /^\s*([\d.]+)(?:\s*TKN)?\s+(\w+)(?:\s+to|\s*[-=]*>+)?\s+(\w+)\s*/.exec(sx_line)!;

		const xg_amount = BigInt(BigNumber(sx_amount).shiftedBy(N_DECIMALS).toFixed(0));

		console.log(sx_amount, si_from, si_to);

		// @ts-expect-error secret app
		const g_result = await transfer(k_dwbv, xg_amount, H_APPS[si_from[0].toLowerCase()] as SecretApp, H_APPS[si_to[0].toLowerCase()] as SecretApp, k_checker);

		if(!k_checker) {
			k_checker = new GasChecker(g_result.tracking, g_result.gasUsed);
		}
	}
}

// evaporation
if(B_TEST_EVAPORATION) {
	const xg_post_evaporate_buffer = 50_000n;
	const xg_gas_wanted = 150_000n;
	const xg_gas_target = xg_gas_wanted - xg_post_evaporate_buffer;

	const [g_exec, xc_code, sx_res, g_meta, h_events, si_txn] = await k_app_a.exec('transfer', {
		amount: `${500000n}` as CwUint128,
		recipient: k_wallet_b.addr,
		gas_target: `${xg_gas_target}`,
	}, xg_gas_wanted);

	console.log({g_meta});

	if(xc_code) {
		throw Error(`Failed evaporation test: ${sx_res}`);
	}

	const xg_gas_used = BigInt(g_meta?.gas_used || '0');
	if(xg_gas_used < xg_gas_target) {
		throw Error(`Expected gas used to be greater than ${xg_gas_target} but only used ${xg_gas_used}`);
	}
	else if(bigint_abs(xg_gas_wanted, xg_gas_used) > xg_post_evaporate_buffer) {
		throw Error(`Expected gas used to be ${xg_gas_wanted} but found ${xg_gas_used}`);
	}
}

{
	console.log('# Initialized');
	await k_dwbv.sync();
	k_dwbv.print();
	console.log('\n');

	// basic transfers between principals
	await transfer_chain(`
		1 TKN Alice => Bob
		2 TKN Alice => Carol
		5 TKN Alice => David
		1 TKN Bob => Carol 		-- Bob's entire balance; settles Bob for 1st time
		1 TKN Carol => David 	-- should accumulate; settles Carol for 1st time
		1 TKN David => Alice 	-- re-adds Alice to buffer; settles David for 1st time
	`);

	// extended transfers between principals
	await transfer_chain(`
		1 TKN David => Bob
		1 TKN David => Bob 		-- exact same transfer repeated
		1 TKN Alice => Bob
		1 TKN Bob => Carol
		1 TKN Alice => Carol
		1 TKN Carol => Bob 		-- yet again
	`);

	// gas checker ref
	let k_checker: GasChecker | null = null;

	// grant action from previous simultion
	let f_grant: undefined | (() => Promise<[w_result: JsonObject | undefined, xc_code: number, s_response: string, g_meta: TxMeta | undefined, h_events: Dict<string[]> | undefined, si_txn: string | undefined]>);

	// number of simulations to perform
	const N_SIMULATIONS = 300;

	// record maximum gas used for direct transfers
	let xg_max_gas_used_transfer = 0n;

	// simulate many transfers
	for(let i_sim=0; i_sim<N_SIMULATIONS; i_sim++) {
		const si_receiver = i_sim+'';

		const k_wallet = await Wallet(await sha256(text_to_bytes(si_receiver)), SI_SECRET_CHAIN, P_SECRET_LCD, P_SECRET_RPC, 'secret');

		const k_app_sim = SecretApp(k_wallet, k_contract, X_GAS_PRICE);

		// label
		console.log(`Alice --> ${si_receiver}`);

		// transfer some gas to sim account
		const [atu8_raw,, si_txn] = await create_and_sign_tx_direct(k_wallet_b, [
			encodeGoogleProtobufAny(
				SI_MESSAGE_TYPE_COSMOS_BANK_MSG_SEND,
				encodeCosmosBankMsgSend(k_wallet_b.addr, k_wallet.addr, [[`${1_000000n}`, 'uscrt']])
			),
		], [[`${5000n}`, 'uscrt']], 50_000n);

		// submit all in parallel
		const [
			// @ts-expect-error totally stupid
			g_result_transfer,
			[xc_send_gas, s_err_send_gas],
			a_res_increase,
		] = await Promise.all([
			// #ts-expect-error secret app
			transfer(k_dwbv, i_sim % 2? 1_000000n: 2_000000n, k_app_a, k_app_sim, k_checker),
			broadcast_result(k_wallet, atu8_raw, si_txn),
			f_grant?.(),
		]);

		// send gas error
		if(xc_send_gas) {
			throw Error(`Failed to transfer gas: ${s_err_send_gas}`);
		}

		// increase allowance error
		if(f_grant && a_res_increase?.[1]) {
			throw Error(`Failed to increase allowance: ${a_res_increase[2]}`);
		}

		// approve Alice as spender for future txs
		f_grant = () => k_app_sim.exec('increase_allowance', {
			spender: k_wallet_a.addr,
			amount: `${1_000000n}` as CwUint128,
		}, 60_000n);

		if(!k_checker) {
			k_checker = new GasChecker((g_result_transfer as TransferResult).tracking, (g_result_transfer as TransferResult).gasUsed);
		}

		xg_max_gas_used_transfer = bigint_greater(xg_max_gas_used_transfer, g_result_transfer.gasUsed);
	}

	// reset checker
	k_checker = null;

	// record maximum gas used for transfer froms
	let xg_max_gas_used_transfer_from = 0n;

	// perform transfer_from
	for(let i_sim=N_SIMULATIONS-2; i_sim>0; i_sim--) {
		const si_owner = i_sim+'';
		const si_recipient = (i_sim - 1)+'';

		const k_wallet_owner = await Wallet(await sha256(text_to_bytes(si_owner)), SI_SECRET_CHAIN, P_SECRET_LCD, P_SECRET_RPC, 'secret');
		const k_wallet_recipient = await Wallet(await sha256(text_to_bytes(si_recipient)), SI_SECRET_CHAIN, P_SECRET_LCD, P_SECRET_RPC, 'secret');

		const k_app_owner = SecretApp(k_wallet_owner, k_contract, X_GAS_PRICE);
		const k_app_recipient = SecretApp(k_wallet_recipient, k_contract, X_GAS_PRICE);

		console.log(`${si_owner} --> ${si_recipient}`);

		// #ts-expect-error secret app
		const g_result = await transfer(k_dwbv, 1_000000n, k_app_owner, k_app_recipient, k_checker, k_app_a);

		if(!k_checker) {
			k_checker = new GasChecker(g_result.tracking, g_result.gasUsed);
		}

		xg_max_gas_used_transfer_from = bigint_greater(xg_max_gas_used_transfer_from, g_result.gasUsed);
	}

	// report
	console.log({
		xg_max_gas_used_transfer,
		xg_max_gas_used_transfer_from,
	});

	// done
	process.exit(0);
}
