import MerkleTree, { checkProofOrdered, merkleRoot, checkProofSolidityFactory,checkProofOrderedSolidityFactory } from 'merkle-tree-solidity'
import { sha3 } from 'ethereumjs-util'
import setup from './js/setup'


// create merkle tree
// expects 32 byte buffers as inputs (no hex strings)
// if using web3.sha3, convert first -> Buffer(web3.sha3('a'), 'hex')

let merkleProof, eth, accounts, web3
let checkProofSolidity

(async()=>{

    let result = await setup()
    merkleProof = result.merkleProof
    eth = result.eth
    accounts = result.accounts
    web3 = result.web3
    checkProofSolidity = checkProofSolidityFactory(merkleProof.checkProof)

})()

const elements = Array.apply(null, Array(10)).map(function (_, i) {return "elem"+i}).map(e => sha3(e))

console.log(elements)

// include the 'true' flag when generating the merkle tree
const merkleTree = new MerkleTree(elements, true)

// [same as above]
// get the merkle root
// returns 32 byte buffer
const root = merkleTree.getRoot()
console.log(root)
// for convenience if only the root is desired
// this creates a new MerkleTree under the hood
// 2nd arg is "preserveOrder" flag
const easyRoot = merkleRoot(elements, true)

// generate merkle proof
// 2nd argugment is the 1-n index of the element
// returns array of 32 byte buffers
const index = 1
const proof = merkleTree.getProofOrdered(elements[0], index)

