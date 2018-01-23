'use strict';

require('babel-register');
require('./test.js');
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.checkProofOrderedSolidityFactory = exports.checkProofSolidityFactory = exports.merkleRoot = exports.checkProofOrdered = exports.checkProof = undefined;

var _ethereumjsUtil = require('ethereumjs-util');

// Expects elements to be Buffers of length 32
// Empty string elements will be removed prior to the buffer check
// by default, order is not preserved
function MerkleTree(elements, preserveOrder) {
  if (!(this instanceof MerkleTree)) {
    return new MerkleTree(elements, preserveOrder);
  }

  // remove empty strings
  this.elements = elements.filter(a => a);

  // check buffers
  if (this.elements.some(e => !(e.length == 32 && Buffer.isBuffer(e)))) {
    throw new Error('elements must be 32 byte buffers');
  }

  // if we are not preserving order, dedup and sort
  this.preserveOrder = !!preserveOrder;
  if (!this.preserveOrder) {
    this.elements = bufDedup(this.elements);
    this.elements.sort(Buffer.compare);
  }

  this.layers = getLayers(this.elements, this.preserveOrder);
} // https://github.com/raiden-network/raiden/blob/master/raiden/mtree.py
// Create a merkle root from a list of elements
// Elements are assumed to be 32 bytes hashes (Buffers)
//  (but may be expressed as 0x prefixed hex strings of length 66)
// The bottom layer of the tree (leaf nodes) are the elements
// All layers above are combined hashes of the element pairs

// Two strategies for creating tree and checking proofs (preserveOrder flag)
// 1. raiden - sort the leaves of the tree, and also sort each pair of
//    pre-images, which allows you to verify the proof without the index
// 2. storj - preserve the order of the leaves and pairs of pre-images, and use
//    the index to verify the proof

// The MerkleTree is a 2d array of layers
// [ elements, combinedHashes1, combinedHashes2, ... root]
// root is a length 1 array

MerkleTree.prototype.getRoot = function () {
  return this.layers[this.layers.length - 1][0];
};

MerkleTree.prototype.getProof = function (element, hex) {
  const index = getBufIndex(element, this.elements);
  if (index == -1) {
    throw new Error('element not found in merkle tree');
  }
  return getProof(index, this.layers, hex);
};

// Expects 1-n index, converts it to 0-n index internally
MerkleTree.prototype.getProofOrdered = function (element, index, hex) {
  if (!element.equals(this.elements[index - 1])) {
    throw new Error('element does not match leaf at index in tree');
  }
  return getProof(index - 1, this.layers, hex);
};

const checkProofOrdered = function checkProofOrdered(proof, root, element, index) {
  // use the index to determine the node ordering
  // index ranges 1 to n

  let tempHash = element;

  for (let i = 0; i < proof.length; i++) {
    let remaining = proof.length - i;

    // we don't assume that the tree is padded to a power of 2
    // if the index is odd then the proof will start with a hash at a higher
    // layer, so we have to adjust the index to be the index at that layer
    while (remaining && index % 2 === 1 && index > Math.pow(2, remaining)) {
      index = Math.round(index / 2);
    }

    if (index % 2 === 0) {
      tempHash = combinedHash(proof[i], tempHash, true);
    } else {
      tempHash = combinedHash(tempHash, proof[i], true);
    }
    index = Math.round(index / 2);
  }

  return tempHash.equals(root);
};

const checkProof = function checkProof(proof, root, element) {
  return root.equals(proof.reduce((hash, pair) => {
    return combinedHash(hash, pair);
  }, element));
};

const merkleRoot = function merkleRoot(elements, preserveOrder) {
  return new MerkleTree(elements, preserveOrder).getRoot();
};

// converts buffers from MerkleRoot functions into hex strings
// merkleProof is the contract abstraction for MerkleProof.sol
const checkProofSolidityFactory = function checkProofSolidityFactory(checkProofContractMethod) {
  return function (proof, root, hash) {
    proof = '0x' + proof.map(e => e.toString('hex')).join('');
    root = bufToHex(root);
    hash = bufToHex(hash);
    return checkProofContractMethod(proof, root, hash);
  };
};

const checkProofOrderedSolidityFactory = function checkProofOrderedSolidityFactory(checkProofOrderedContractMethod) {
  return function (proof, root, hash, index) {
    proof = '0x' + proof.map(e => e.toString('hex')).join('');
    root = bufToHex(root);
    hash = bufToHex(hash);
    return checkProofOrderedContractMethod(proof, root, hash, index);
  };
};

exports.default = MerkleTree;
exports.checkProof = checkProof;
exports.checkProofOrdered = checkProofOrdered;
exports.merkleRoot = merkleRoot;
exports.checkProofSolidityFactory = checkProofSolidityFactory;
exports.checkProofOrderedSolidityFactory = checkProofOrderedSolidityFactory;


function combinedHash(first, second, preserveOrder) {
  if (!second) {
    return first;
  }
  if (!first) {
    return second;
  }
  if (preserveOrder) {
    return (0, _ethereumjsUtil.sha3)(bufJoin(first, second));
  } else {
    return (0, _ethereumjsUtil.sha3)(bufSortJoin(first, second));
  }
}

function getNextLayer(elements, preserveOrder) {
  return elements.reduce((layer, element, index, arr) => {
    if (index % 2 == 0) {
      layer.push(combinedHash(element, arr[index + 1], preserveOrder));
    }
    return layer;
  }, []);
}

function getLayers(elements, preserveOrder) {
  if (elements.length == 0) {
    return [['']];
  }
  const layers = [];
  layers.push(elements);
  while (layers[layers.length - 1].length > 1) {
    layers.push(getNextLayer(layers[layers.length - 1], preserveOrder));
  }
  return layers;
}

function getProof(index, layers, hex) {
  const proof = layers.reduce((proof, layer) => {
    let pair = getPair(index, layer);
    if (pair) {
      proof.push(pair);
    }
    index = Math.floor(index / 2);
    return proof;
  }, []);
  if (hex) {
    return '0x' + proof.map(e => e.toString('hex')).join('');
  } else {
    return proof;
  }
}

function getPair(index, layer) {
  let pairIndex = index % 2 ? index - 1 : index + 1;
  if (pairIndex < layer.length) {
    return layer[pairIndex];
  } else {
    return null;
  }
}

function getBufIndex(element, array) {
  for (let i = 0; i < array.length; i++) {
    if (element.equals(array[i])) {
      return i;
    }
  }
  return -1;
}

function bufToHex(element) {
  return Buffer.isBuffer(element) ? '0x' + element.toString('hex') : element;
}

function bufJoin() {
  for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
    args[_key] = arguments[_key];
  }

  return Buffer.concat([...args]);
}

function bufSortJoin() {
  for (var _len2 = arguments.length, args = Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
    args[_key2] = arguments[_key2];
  }

  return Buffer.concat([...args].sort(Buffer.compare));
}

function bufDedup(buffers) {
  return buffers.filter((buffer, i) => {
    return getBufIndex(buffer, buffers) == i;
  });
}
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _fs = require('fs');

var _fs2 = _interopRequireDefault(_fs);

var _es6Promisify = require('es6-promisify');

var _es6Promisify2 = _interopRequireDefault(_es6Promisify);

var _ethereumjsTestrpc = require('ethereumjs-testrpc');

var _ethereumjsTestrpc2 = _interopRequireDefault(_ethereumjsTestrpc);

var _solc = require('solc');

var _solc2 = _interopRequireDefault(_solc);

var _ethjsQuery = require('ethjs-query');

var _ethjsQuery2 = _interopRequireDefault(_ethjsQuery);

var _ethjsContract = require('ethjs-contract');

var _ethjsContract2 = _interopRequireDefault(_ethjsContract);

var _web = require('web3');

var _web2 = _interopRequireDefault(_web);

var _ethjsProviderHttp = require('ethjs-provider-http');

var _ethjsProviderHttp2 = _interopRequireDefault(_ethjsProviderHttp);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

const SOL_PATH = __dirname + '/../src/';
const TESTRPC_PORT = 8545;
const MNEMONIC = 'elegant ability lawn fiscal fossil general swarm trap bind require exchange ostrich';

// opts
// initTestRPC - if true, starts a testRPC server
// mnemonic - seed for accounts
// port - testrpc port
// noDeploy - if true, skip contract deployment
// testRPCProvider - http connection string for console testprc instance
// defaultAcct - the index of the default account

exports.default = (() => {
  var _ref = _asyncToGenerator(function* (opts) {
    opts = opts || {};
    const mnemonic = opts.mnemonic || MNEMONIC;
    const testRPCServer = opts.testRPCServer;
    const port = opts.port || TESTRPC_PORT;
    const noDeploy = opts.noDeploy;
    const defaultAcct = opts.defaultAcct ? opts.defaultAcct : 0;

    // START TESTRPC PROVIDER
    let provider;
    if (opts.testRPCProvider) {
      provider = new _ethjsProviderHttp2.default(opts.testRPCProvider);
    } else {
      provider = _ethereumjsTestrpc2.default.provider({
        mnemonic: mnemonic
      });
    }

    // START TESTRPC SERVER
    if (opts.testRPCServer) {
      console.log('setting up testrpc server');
      yield (0, _es6Promisify2.default)(_ethereumjsTestrpc2.default.server({
        mnemonic: mnemonic
      }).listen)(port);
    }

    // BUILD ETHJS ABSTRACTIONS
    const eth = new _ethjsQuery2.default(provider);
    const contract = new _ethjsContract2.default(eth);
    const accounts = yield eth.accounts();

    // COMPILE THE CONTRACT
    const input = {
      'MerkleProof.sol': _fs2.default.readFileSync(SOL_PATH + 'MerkleProof.sol').toString()
    };

    const output = _solc2.default.compile({ sources: input }, 1);
    if (output.errors) {
      throw new Error(output.errors);
    }

    const abi = JSON.parse(output.contracts['MerkleProof.sol:MerkleProof'].interface);
    const bytecode = output.contracts['MerkleProof.sol:MerkleProof'].bytecode;

    // PREPARE THE CONTRACT ABSTRACTION OBJECT
    const MerkleProof = contract(abi, bytecode, {
      from: accounts[defaultAcct],
      gas: 3000000
    });

    let txHash, receipt, merkleProof;

    if (!noDeploy) {
      // DEPLOY THE ADMARKET CONTRACT
      txHash = yield MerkleProof.new();
      yield wait(1500);
      // USE THE ADDRESS FROM THE TX RECEIPT TO BUILD THE CONTRACT OBJECT
      receipt = yield eth.getTransactionReceipt(txHash);
      merkleProof = MerkleProof.at(receipt.contractAddress);
    }

    // MAKE WEB3
    const web3 = new _web2.default();
    web3.setProvider(provider);
    web3.eth.defaultAccount = accounts[0];

    return { merkleProof: merkleProof, MerkleProof: MerkleProof, eth: eth, accounts: accounts, web3: web3 };
  });

  return function (_x) {
    return _ref.apply(this, arguments);
  };
})();

// async/await compatible setTimeout
// http://stackoverflow.com/questions/38975138/is-using-async-in-settimeout-valid
// await wait(2000)


const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
'use strict';

var _chai = require('chai');

var _es6Promisify = require('es6-promisify');

var _es6Promisify2 = _interopRequireDefault(_es6Promisify);

var _web = require('web3');

var _web2 = _interopRequireDefault(_web);

var _ethereumjsUtil = require('ethereumjs-util');

var _setup = require('./setup');

var _setup2 = _interopRequireDefault(_setup);

var _index = require('../index');

var _index2 = _interopRequireDefault(_index);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

// import MerkleTree, { checkProof, checkProofOrdered,
//   merkleRoot, checkProofSolidityFactory, checkProofOrderedSolidityFactory
// } from './merkle'

describe('MerkleTree -- no preserving order', () => {
  it('empty', () => {
    _chai.assert.equal((0, _index.merkleRoot)([]), '');
    _chai.assert.equal((0, _index.merkleRoot)(['']), '');
  });

  it('multiple empty', () => {
    _chai.assert.equal((0, _index.merkleRoot)(['', '']), '');
  });

  it('elements must be 32 byte buffers', () => {
    const inputs = [makeString('x', 32), Buffer(makeString('x', 33)), '0x' + Buffer(makeString('x', 32)).toString('hex'), 123];

    inputs.forEach(input => {
      try {
        (0, _index.merkleRoot)([input]);
        _chai.assert.isTrue(false);
      } catch (err) {
        _chai.assert.equal(err.message, 'elements must be 32 byte buffers');
      }
    });
  });

  it('single', () => {
    const hash_0 = (0, _ethereumjsUtil.sha3)('x');
    _chai.assert.equal((0, _index.merkleRoot)([hash_0]), hash_0);
  });

  it('duplicates', () => {
    const hash_0 = (0, _ethereumjsUtil.sha3)('x');
    const hash_1 = (0, _ethereumjsUtil.sha3)('y');

    _chai.assert.equal((0, _index.merkleRoot)([hash_0, hash_0]), hash_0);

    const result_0 = (0, _index.merkleRoot)([hash_0, hash_1, hash_0]);
    const result_1 = (0, _index.merkleRoot)([hash_0, hash_1]);
    _chai.assert.isTrue(result_0.equals(result_1));
  });

  it('duplicates -- with different buffer objects', () => {
    const hash_0 = (0, _ethereumjsUtil.sha3)('x');
    const hash_0_dup = (0, _ethereumjsUtil.sha3)('x');
    const hash_1 = (0, _ethereumjsUtil.sha3)('y');

    _chai.assert.equal((0, _index.merkleRoot)([hash_0, hash_0_dup]), hash_0);

    const result_0 = (0, _index.merkleRoot)([hash_0, hash_1, hash_0_dup]);
    const result_1 = (0, _index.merkleRoot)([hash_0, hash_1]);
    _chai.assert.isTrue(result_0.equals(result_1));
  });

  it('one', () => {
    const hash_0 = (0, _ethereumjsUtil.sha3)('x');

    const merkleTree = new _index2.default([hash_0]);
    const proof = merkleTree.getProof(hash_0);
    const root = merkleTree.getRoot();

    _chai.assert.sameMembers(proof, []);
    _chai.assert.equal(root, hash_0);
    _chai.assert.isTrue((0, _index.checkProof)(proof, root, hash_0));
  });

  it('one -- different element object', () => {
    // this test is here because getProof was doing an indexOf deep equality
    // search to determine if the element was in the tree
    // it should still work with different but equal buffer objects
    const hash_0 = (0, _ethereumjsUtil.sha3)('x');
    const hash_0_dup = (0, _ethereumjsUtil.sha3)('x');

    const merkleTree = new _index2.default([hash_0]);
    const proof = merkleTree.getProof(hash_0_dup);
    const root = merkleTree.getRoot();

    _chai.assert.sameMembers(proof, []);
    _chai.assert.equal(root, hash_0);
    _chai.assert.isTrue((0, _index.checkProof)(proof, root, hash_0));
  });

  it('two', () => {
    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));

    const merkleTree = new _index2.default([hash_0, hash_1]);
    const proof0 = merkleTree.getProof(hash_0);
    const root = merkleTree.getRoot();

    _chai.assert.sameMembers(proof0, [hash_1]);
    _chai.assert.isTrue(root.equals((0, _ethereumjsUtil.sha3)(bufSortJoin(hash_0, hash_1))));
    _chai.assert.isTrue((0, _index.checkProof)(proof0, root, hash_0));

    const proof1 = merkleTree.getProof(hash_1);

    _chai.assert.sameMembers(proof1, [hash_0]);
    _chai.assert.isTrue((0, _index.checkProof)(proof1, root, hash_1));
  });

  it('three', () => {
    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));
    const hash_2 = Buffer(makeString('c', 32));

    const hash_01 = Buffer('6d65ef9ca93d3516a4d38ab7d989c2b500e2fc89ccdcf878f9c46daaf6ad0d5b', 'hex');

    const calculated_01 = (0, _ethereumjsUtil.sha3)(bufSortJoin(hash_0, hash_1));
    _chai.assert.isTrue(calculated_01.equals(hash_01));

    const calculatedRoot = (0, _ethereumjsUtil.sha3)(bufSortJoin(hash_01, hash_2));

    const merkleTree = new _index2.default([hash_0, hash_1, hash_2]);
    const proof0 = merkleTree.getProof(hash_0);
    const root = merkleTree.getRoot();

    _chai.assert.sameMembers(proof0, [hash_1, hash_2]);
    _chai.assert.isTrue(root.equals(calculatedRoot));
    _chai.assert.isTrue((0, _index.checkProof)(proof0, root, hash_0));

    const proof1 = merkleTree.getProof(hash_1);

    _chai.assert.sameMembers(proof1, [hash_0, hash_2]);
    _chai.assert.isTrue((0, _index.checkProof)(proof1, root, hash_1));

    const proof2 = merkleTree.getProof(hash_2);

    _chai.assert.isTrue(proof2[0].equals(hash_01));
    _chai.assert.isTrue((0, _index.checkProof)(proof2, root, hash_2));
  });

  it('many', () => {
    const many = 10;

    for (let i = 1; i <= many; i++) {
      let elements = range(i).map(e => (0, _ethereumjsUtil.sha3)(e));
      let merkleTree = new _index2.default(elements);
      let root = merkleTree.getRoot();

      elements.forEach(element => {
        let proof = merkleTree.getProof(element);
        _chai.assert.isTrue((0, _index.checkProof)(proof, root, element));
      });

      const reverseTree = new _index2.default(elements.reverse());
      _chai.assert.isTrue(root.equals(reverseTree.getRoot()));
    }
  });
});

describe('MerkleTree [preserve order]', () => {
  it('two', () => {
    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));

    const merkleTree = new _index2.default([hash_0, hash_1], true);
    const proof0 = merkleTree.getProof(hash_0);
    const root = merkleTree.getRoot();

    _chai.assert.sameMembers(proof0, [hash_1]);
    _chai.assert.isTrue(root.equals((0, _ethereumjsUtil.sha3)(bufJoin(hash_0, hash_1))));
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof0, root, hash_0, 1));

    const proof1 = merkleTree.getProof(hash_1);

    _chai.assert.sameMembers(proof1, [hash_0]);
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof1, root, hash_1, 2));
  });

  it('three', () => {
    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));
    const hash_2 = Buffer(makeString('c', 32));

    const hash_01 = Buffer('6d65ef9ca93d3516a4d38ab7d989c2b500e2fc89ccdcf878f9c46daaf6ad0d5b', 'hex');

    const calculated_01 = (0, _ethereumjsUtil.sha3)(bufJoin(hash_0, hash_1));
    _chai.assert.isTrue(calculated_01.equals(hash_01));

    const calculatedRoot = (0, _ethereumjsUtil.sha3)(bufJoin(hash_01, hash_2));

    const merkleTree = new _index2.default([hash_0, hash_1, hash_2], true);
    const proof0 = merkleTree.getProof(hash_0);
    const root = merkleTree.getRoot();

    _chai.assert.sameMembers(proof0, [hash_1, hash_2]);
    _chai.assert.isTrue(root.equals(calculatedRoot));
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof0, root, hash_0, 1));

    const proof1 = merkleTree.getProof(hash_1);

    _chai.assert.sameMembers(proof1, [hash_0, hash_2]);
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof1, root, hash_1, 2));

    const proof2 = merkleTree.getProof(hash_2);

    _chai.assert.isTrue(proof2[0].equals(hash_01));
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof2, root, hash_2, 3));
  });

  it('three -- duplicates are preserved', () => {
    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));
    const hash_2 = Buffer(makeString('a', 32));

    const hash_01 = Buffer('6d65ef9ca93d3516a4d38ab7d989c2b500e2fc89ccdcf878f9c46daaf6ad0d5b', 'hex');

    const calculated_01 = (0, _ethereumjsUtil.sha3)(bufJoin(hash_0, hash_1));
    _chai.assert.isTrue(calculated_01.equals(hash_01));

    const calculatedRoot = (0, _ethereumjsUtil.sha3)(bufJoin(hash_01, hash_2));

    const merkleTree = new _index2.default([hash_0, hash_1, hash_2], true);
    const proof0 = merkleTree.getProofOrdered(hash_0, 1);
    const root = merkleTree.getRoot();

    _chai.assert.sameMembers(proof0, [hash_1, hash_2]);
    _chai.assert.isTrue(root.equals(calculatedRoot));
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof0, root, hash_0, 1));

    const proof1 = merkleTree.getProofOrdered(hash_1, 2);

    _chai.assert.sameMembers(proof1, [hash_0, hash_2]);
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof1, root, hash_1, 2));

    const proof2 = merkleTree.getProofOrdered(hash_2, 3);

    _chai.assert.isTrue(proof2[0].equals(hash_01));
    _chai.assert.isTrue((0, _index.checkProofOrdered)(proof2, root, hash_2, 3));
  });

  it('many', () => {
    const many = 10;

    for (let i = 1; i <= many; i++) {
      let elements = range(i).map(e => (0, _ethereumjsUtil.sha3)(e));
      let merkleTree = new _index2.default(elements, true);
      let root = merkleTree.getRoot();

      elements.forEach((element, index) => {
        let proof = merkleTree.getProofOrdered(element, index + 1);
        _chai.assert.isTrue((0, _index.checkProofOrdered)(proof, root, element, index + 1));
      });
    }
  });

  it('many -- with duplicates', () => {
    const many = 10;

    for (let i = 1; i <= many; i++) {
      let elements = range(i).map(e => (0, _ethereumjsUtil.sha3)(e % 5));
      let merkleTree = new _index2.default(elements, true);
      let root = merkleTree.getRoot();

      elements.forEach((element, index) => {
        let proof = merkleTree.getProofOrdered(element, index + 1);
        _chai.assert.isTrue((0, _index.checkProofOrdered)(proof, root, element, index + 1));
      });
    }
  });
});

describe('solidity -- checkProof', _asyncToGenerator(function* () {

  let merkleProof, eth, accounts, web3;
  let checkProofSolidity;

  before(_asyncToGenerator(function* () {
    let result = yield (0, _setup2.default)();
    merkleProof = result.merkleProof;
    eth = result.eth;
    accounts = result.accounts;
    web3 = result.web3;
    checkProofSolidity = (0, _index.checkProofSolidityFactory)(merkleProof.checkProof);
  }));

  it('checkProof - two', _asyncToGenerator(function* () {

    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));

    const merkleTree = new _index2.default([hash_0, hash_1]);
    const root = merkleTree.getRoot();
    const proof0 = merkleTree.getProof(hash_0);

    _chai.assert.sameMembers(proof0, [hash_1]);
    _chai.assert.isTrue(root.equals((0, _ethereumjsUtil.sha3)(hash_0 + hash_1)));
    _chai.assert.isTrue((0, _index.checkProof)(proof0, root, hash_0));
    _chai.assert.isTrue((yield checkProofSolidity(proof0, root, hash_0))[0]);

    const proof1 = merkleTree.getProof(hash_1);

    _chai.assert.sameMembers(proof1, [hash_0]);
    _chai.assert.isTrue((0, _index.checkProof)(proof1, root, hash_1));
    _chai.assert.isTrue((yield checkProofSolidity(proof1, root, hash_1))[0]);
  }));

  it('checkProof - two fails', _asyncToGenerator(function* () {
    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));

    const merkleTree = new _index2.default([hash_0, hash_1]);
    const root = merkleTree.getRoot();
    const proof0 = merkleTree.getProof(hash_1); // switched hashes

    _chai.assert.sameMembers(proof0, [hash_0]);
    _chai.assert.isTrue(root.equals((0, _ethereumjsUtil.sha3)(hash_0 + hash_1)));
    _chai.assert.isFalse((0, _index.checkProof)(proof0, root, hash_0));
    _chai.assert.isFalse((yield checkProofSolidity(proof0, root, hash_0))[0]);
  }));

  it('checkProof - many', _asyncToGenerator(function* () {
    const many = 10;

    for (let i = 1; i <= many; i++) {
      let elements = range(i).map(function (e) {
        return (0, _ethereumjsUtil.sha3)(e);
      });
      elements.sort(Buffer.compare);
      let merkleTree = new _index2.default(elements);
      let root = merkleTree.getRoot();

      for (let element of elements) {
        let proof = merkleTree.getProof(element);
        _chai.assert.isTrue((0, _index.checkProof)(proof, root, element));
        _chai.assert.isTrue((yield checkProofSolidity(proof, root, element))[0]);
      }

      const reverseTree = new _index2.default(elements.reverse());
      _chai.assert.isTrue(root.equals(reverseTree.getRoot()));
    }
  }));
}));

describe('solidity -- checkProofOrdered', _asyncToGenerator(function* () {

  let merkleProof, eth, accounts, web3;
  let checkProofSolidity;

  before(_asyncToGenerator(function* () {
    let result = yield (0, _setup2.default)();
    merkleProof = result.merkleProof;
    eth = result.eth;
    accounts = result.accounts;
    web3 = result.web3;
    checkProofSolidity = (0, _index.checkProofOrderedSolidityFactory)(merkleProof.checkProofOrdered);
  }));

  it('checkProof - two', _asyncToGenerator(function* () {

    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));

    const merkleTree = new _index2.default([hash_0, hash_1], true);
    const root = merkleTree.getRoot();
    const proof0 = merkleTree.getProof(hash_0);

    _chai.assert.sameMembers(proof0, [hash_1]);
    _chai.assert.isTrue(root.equals((0, _ethereumjsUtil.sha3)(hash_0 + hash_1)));
    _chai.assert.isTrue((0, _index.checkProof)(proof0, root, hash_0));
    _chai.assert.isTrue((yield checkProofSolidity(proof0, root, hash_0, 1))[0]);

    const proof1 = merkleTree.getProof(hash_1);

    _chai.assert.sameMembers(proof1, [hash_0]);
    _chai.assert.isTrue((0, _index.checkProof)(proof1, root, hash_1));
    _chai.assert.isTrue((yield checkProofSolidity(proof1, root, hash_1, 2))[0]);
  }));

  it('checkProof - two fails', _asyncToGenerator(function* () {
    const hash_0 = Buffer(makeString('a', 32));
    const hash_1 = Buffer(makeString('b', 32));

    const merkleTree = new _index2.default([hash_0, hash_1], true);
    const root = merkleTree.getRoot();
    const proof0 = merkleTree.getProof(hash_1); // switched hashes

    _chai.assert.sameMembers(proof0, [hash_0]);
    _chai.assert.isTrue(root.equals((0, _ethereumjsUtil.sha3)(hash_0 + hash_1)));
    _chai.assert.isFalse((0, _index.checkProof)(proof0, root, hash_0));
    _chai.assert.isFalse((yield checkProofSolidity(proof0, root, hash_0, 1))[0]);
  }));

  it('checkProof - many', _asyncToGenerator(function* () {
    const many = 10;

    for (let i = 1; i <= many; i++) {
      let elements = range(i).map(function (e) {
        return (0, _ethereumjsUtil.sha3)(e);
      });
      elements.sort(Buffer.compare);
      let merkleTree = new _index2.default(elements, true);
      let root = merkleTree.getRoot();

      for (let index = 0; index < elements.length; index++) {
        let element = elements[index];
        let proof = merkleTree.getProof(element);
        _chai.assert.isTrue((0, _index.checkProofOrdered)(proof, root, element, index + 1));
        _chai.assert.isTrue((yield checkProofSolidity(proof, root, element, index + 1))[0]);
      }
    }
  }));
}));

function bufJoin() {
  for (var _len = arguments.length, args = Array(_len), _key = 0; _key < _len; _key++) {
    args[_key] = arguments[_key];
  }

  return Buffer.concat([...args]);
}

function bufSortJoin() {
  for (var _len2 = arguments.length, args = Array(_len2), _key2 = 0; _key2 < _len2; _key2++) {
    args[_key2] = arguments[_key2];
  }

  return Buffer.concat([...args].sort(Buffer.compare));
}

function makeString(char, length) {
  let string = '';
  for (let i = 0; i < length; i++) {
    string += char;
  }
  return string;
}

function range(max) {
  const arr = [];
  for (let i = 0; i < max; i++) {
    arr.push(i + 1);
  }
  return arr;
}
'use strict';

var _merkleTreeSolidity = require('merkle-tree-solidity');

var _merkleTreeSolidity2 = _interopRequireDefault(_merkleTreeSolidity);

var _ethereumjsUtil = require('ethereumjs-util');

var _setup = require('./js/setup');

var _setup2 = _interopRequireDefault(_setup);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

let result = (0, _setup2.default)();
// create merkle tree
// expects 32 byte buffers as inputs (no hex strings)
// if using web3.sha3, convert first -> Buffer(web3.sha3('a'), 'hex')
const elements = [1, 2, 3].map(e => (0, _ethereumjsUtil.sha3)(e));

// include the 'true' flag when generating the merkle tree
const merkleTree = new _merkleTreeSolidity2.default(elements, true);

// [same as above]
// get the merkle root
// returns 32 byte buffer
const root = merkleTree.getRoot();

// for convenience if only the root is desired
// this creates a new MerkleTree under the hood
// 2nd arg is "preserveOrder" flag
const easyRoot = (0, _merkleTreeSolidity.merkleRoot)(elements, true);

// generate merkle proof
// 2nd argugment is the 1-n index of the element
// returns array of 32 byte buffers
const index = 1;
const proof = merkleTree.getProofOrdered(elements[0], index);
