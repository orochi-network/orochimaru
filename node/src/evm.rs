use bytes::{BufMut, BytesMut};
use libecvrf::{
    extends::ScalarExtend,
    secp256k1::curve::{Affine, Scalar},
    ECVRFContractProof,
};
use revm::{
    db::BenchmarkDB,
    primitives::{
        address, bytes, Address, Bytecode, Bytes, ExecutionResult, SuccessReason, TransactTo,
    },
    Evm,
};

const SMART_CONTRACT_CALLER: Address = address!("1000000000000000000000000000000000000000");
const SMART_CONTRACT_CALLEE: Address = address!("0000000000000000000000000000000000000000");

/// Emulate the ECVRF inside REVM to makesure that the result is correct
/// This consider to be a double check, we trade-off performance for accuracy
pub fn evm_verify(smart_contract_proof: &ECVRFContractProof) -> bool {
    let bytecode_raw = Bytecode::new_raw(bytes!("608060405234801561001057600080fd5b506004361061002b5760003560e01c8063c8d20a7714610030575b600080fd5b61004361003e366004610bfa565b610055565b60405190815260200160405180910390f35b60006100688a8a8a8a8a8a8a8a8a61009f565b886040516020016100799190610c9a565b60408051601f1981840301815291905280516020909101209a9950505050505050505050565b6100a8896102c7565b6100f95760405162461bcd60e51b815260206004820152601a60248201527f7075626c6963206b6579206973206e6f74206f6e20637572766500000000000060448201526064015b60405180910390fd5b610102886102c7565b6101465760405162461bcd60e51b815260206004820152601560248201527467616d6d61206973206e6f74206f6e20637572766560581b60448201526064016100f0565b61014f836102c7565b61019b5760405162461bcd60e51b815260206004820152601d60248201527f6347616d6d615769746e657373206973206e6f74206f6e20637572766500000060448201526064016100f0565b6101a4826102c7565b6101f05760405162461bcd60e51b815260206004820152601c60248201527f73486173685769746e657373206973206e6f74206f6e2063757276650000000060448201526064016100f0565b6101fc878a888761038a565b6102485760405162461bcd60e51b815260206004820152601960248201527f6164647228632a706b2b732a6729213d5f755769746e6573730000000000000060448201526064016100f0565b60006102548a876104ad565b90506000610267898b878b868989610517565b90506000610278838d8d8a8661063c565b9050808a146102b95760405162461bcd60e51b815260206004820152600d60248201526c34b73b30b634b210383937b7b360991b60448201526064016100f0565b505050505050505050505050565b80516000906401000003d019116103155760405162461bcd60e51b8152602060048201526012602482015271696e76616c696420782d6f7264696e61746560701b60448201526064016100f0565b60208201516401000003d019116103635760405162461bcd60e51b8152602060048201526012602482015271696e76616c696420792d6f7264696e61746560701b60448201526064016100f0565b60208201516401000003d0199080096103838360005b602002015161067c565b1492915050565b60006001600160a01b0382166103d05760405162461bcd60e51b815260206004820152600b60248201526a626164207769746e65737360a81b60448201526064016100f0565b6020840151600090600116156103e757601c6103ea565b601b5b9050600070014551231950b75fc4402da1732fc9bebe1985876000602002015109865170014551231950b75fc4402da1732fc9bebe19918203925060009190890987516040805160008082526020820180845287905260ff88169282019290925260608101929092526080820183905291925060019060a0016020604051602081039080840390855afa158015610485573d6000803e3d6000fd5b5050604051601f1901516001600160a01b039081169088161495505050505050949350505050565b6104b5610b22565b6104e2600184846040516020016104ce93929190610d0a565b6040516020818303038152906040526106a0565b90505b6104ee816102c7565b61051157805160408051602081019290925261050a91016104ce565b90506104e5565b92915050565b61051f610b22565b825186516401000003d019918290069190060361057e5760405162461bcd60e51b815260206004820152601e60248201527f706f696e747320696e2073756d206d7573742062652064697374696e6374000060448201526064016100f0565b6105898789886106ee565b6105ce5760405162461bcd60e51b8152602060048201526016602482015275119a5c9cdd081b5d5b0818da1958dac819985a5b195960521b60448201526064016100f0565b6105d98486856106ee565b6106255760405162461bcd60e51b815260206004820152601760248201527f5365636f6e64206d756c20636865636b206661696c656400000000000000000060448201526064016100f0565b610630868484610819565b98975050505050505050565b60006002868686858760405160200161065a96959493929190610d2b565b60408051601f1981840301815291905280516020909101209695505050505050565b6000806401000003d01980848509840990506401000003d019600782089392505050565b6106a8610b22565b6106b1826108e0565b81526106c66106c1826000610379565b61091b565b60208201819052600290066001036106e9576020810180516401000003d0190390525b919050565b60008260000361072e5760405162461bcd60e51b815260206004820152600b60248201526a3d32b9379039b1b0b630b960a91b60448201526064016100f0565b8351602085015160009061074490600290610d8a565b1561075057601c610753565b601b5b9050600070014551231950b75fc4402da1732fc9bebe198387096040805160008082526020820180845281905260ff86169282019290925260608101869052608081018390529192509060019060a0016020604051602081039080840390855afa1580156107c5573d6000803e3d6000fd5b5050506020604051035190506000866040516020016107e49190610dac565b60408051601f1981840301815291905280516020909101206001600160a01b0392831692169190911498975050505050505050565b610821610b22565b8351602080860151855191860151600093849384936108429390919061093b565b919450925090506401000003d0198582096001146108a25760405162461bcd60e51b815260206004820152601960248201527f696e765a206d75737420626520696e7665727365206f66207a0000000000000060448201526064016100f0565b60405180604001604052806401000003d019806108c1576108c1610ccb565b87860981526020016401000003d0198785099052979650505050505050565b805160208201205b6401000003d01981106106e9576040805160208082019390935281518082038401815290820190915280519101206108e8565b60006105118260026109346401000003d0196001610dbe565b901c610a1b565b60008080600180826401000003d019896401000003d019038808905060006401000003d0198b6401000003d019038a089050600061097b83838585610ab5565b909850905061098c88828e88610ad9565b909850905061099d88828c87610ad9565b909850905060006109b08d878b85610ad9565b90985090506109c188828686610ab5565b90985090506109d288828e89610ad9565b9098509050818114610a07576401000003d019818a0998506401000003d01982890997506401000003d0198183099650610a0b565b8196505b5050505050509450945094915050565b600080610a26610b40565b6020808252818101819052604082015260608101859052608081018490526401000003d01960a0820152610a58610b5e565b60208160c0846005600019fa925082600003610aab5760405162461bcd60e51b81526020600482015260126024820152716269674d6f64457870206661696c7572652160701b60448201526064016100f0565b5195945050505050565b6000806401000003d0198487096401000003d0198487099097909650945050505050565b600080806401000003d019878509905060006401000003d01987876401000003d019030990506401000003d0198183086401000003d01986890990999098509650505050505050565b60405180604001604052806002906020820280368337509192915050565b6040518060c001604052806006906020820280368337509192915050565b60405180602001604052806001906020820280368337509192915050565b600082601f830112610b8d57600080fd5b6040516040810181811067ffffffffffffffff82111715610bbe57634e487b7160e01b600052604160045260246000fd5b8060405250806040840185811115610bd557600080fd5b845b81811015610bef578035835260209283019201610bd7565b509195945050505050565b60008060008060008060008060006101a08a8c031215610c1957600080fd5b610c238b8b610b7c565b9850610c328b60408c01610b7c565b975060808a0135965060a08a0135955060c08a0135945060e08a01356001600160a01b0381168114610c6357600080fd5b9350610c738b6101008c01610b7c565b9250610c838b6101408c01610b7c565b91506101808a013590509295985092959850929598565b60408101818360005b6002811015610cc2578151835260209283019290910190600101610ca3565b50505092915050565b634e487b7160e01b600052601260045260246000fd5b8060005b6002811015610d04578151845260209384019390910190600101610ce5565b50505050565b838152610d1a6020820184610ce1565b606081019190915260800192915050565b868152610d3b6020820187610ce1565b610d486060820186610ce1565b610d5560a0820185610ce1565b610d6260e0820184610ce1565b60609190911b6bffffffffffffffffffffffff19166101208201526101340195945050505050565b600082610da757634e487b7160e01b600052601260045260246000fd5b500690565b610db68183610ce1565b604001919050565b8082018082111561051157634e487b7160e01b600052601160045260246000fdfea2646970667358221220f4fef21a2c3a082b44f6636b8b7b901beff44394d33ed1542357f956279ba39864736f6c63430008130033"));
    let mut affine_pub_key: Affine = smart_contract_proof.pk.into();

    affine_pub_key.x.normalize();
    affine_pub_key.y.normalize();

    let mut buf = BytesMut::new();
    // Call signature
    buf.put_slice(&[0xc8u8, 0xd2, 0x0a, 0x77]);
    // Public key
    buf.put_slice(&affine_pub_key.x.b32());
    buf.put_slice(&affine_pub_key.y.b32());
    // Gamma
    buf.put_slice(&smart_contract_proof.gamma.x.b32());
    buf.put_slice(&smart_contract_proof.gamma.y.b32());
    // C
    buf.put_slice(&smart_contract_proof.c.b32());
    // S
    buf.put_slice(&smart_contract_proof.s.b32());
    // Alpha
    buf.put_slice(&smart_contract_proof.alpha.b32());
    // Witness address
    buf.put_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    buf.put_slice(&smart_contract_proof.witness_address.b32()[0..20]);
    // Gama Witness
    buf.put_slice(&smart_contract_proof.witness_gamma.x.b32());
    buf.put_slice(&smart_contract_proof.witness_gamma.y.b32());
    // Hash Witness
    buf.put_slice(&smart_contract_proof.witness_hash.x.b32());
    buf.put_slice(&smart_contract_proof.witness_hash.y.b32());
    // Inverted Z
    buf.put_slice(&smart_contract_proof.inverse_z.b32());

    // BenchmarkDB is dummy state that implements Database trait.
    // We don't need any better database since we simulate the execution only
    // The state will be discarded
    let mut evm = Evm::builder()
        .modify_tx_env(|tx| {
            tx.caller = SMART_CONTRACT_CALLER;
            tx.transact_to = TransactTo::Call(SMART_CONTRACT_CALLEE);
            tx.data = Bytes::from(buf.freeze());
        })
        .with_db(BenchmarkDB::new_bytecode(bytecode_raw))
        .build();

    match evm
        .transact()
        .expect("Unable to perform transaction")
        .result
    {
        ExecutionResult::Success {
            reason,
            gas_used: _,
            gas_refunded: _,
            logs: _,
            output,
        } => {
            if reason == SuccessReason::Return {
                Scalar::from_bytes(output.data()) == smart_contract_proof.y
            } else {
                false
            }
        }
        _ => false,
    }
}
