import type {EncodedGoogleProtobufAny} from '@solar-republic/cosmos-grpc/google/protobuf/any';
import type {TxResponseTuple, Wallet} from '@solar-republic/neutrino';

import {TendermintEventFilter, broadcast_result, create_and_sign_tx_direct} from '@solar-republic/neutrino';

import {P_SECRET_RPC} from './constants';

const k_tef = await TendermintEventFilter(P_SECRET_RPC);

export async function exec(k_wallet: Wallet, atu8_msg: EncodedGoogleProtobufAny, xg_gas_limit: bigint): Promise<TxResponseTuple> {
	const [atu8_raw, sb16_txn, atu8_signdoc] = await create_and_sign_tx_direct(
		k_wallet,
		[atu8_msg],
		xg_gas_limit
	);

	return await broadcast_result(k_wallet, atu8_raw, sb16_txn, k_tef);
}
