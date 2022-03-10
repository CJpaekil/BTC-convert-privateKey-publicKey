const ecc = require('eosjs-ecc');
const base58 = require('bs58');
const ripemd160 = require('ripemd160')
const fs = require('fs');
const readline = require('readline');

async function processLineByLine() {
  const fileStream = fs.createReadStream('data\\privateKey.txt');

  const rl = readline.createInterface({
    input: fileStream,
    crlfDelay: Infinity
  });
  // Note: we use the crlfDelay option to recognize all instances of CR LF
  // ('\r\n') in input.txt as a single line break.
  var line_count=0;
  fs.writeFile('data\\Keypairs.txt', '', function(){})
  for await (const line of rl) {
    // Each line in input.txt will be successively available here as `line`.
    	
    	const wif = line;
		const privkey = ecc.PrivateKey.fromString(wif);
		const compressed_pubkey = privkey.toPublic();
		const uncompressed_pubkey = compressed_pubkey.toUncompressed();

		const hash1 = ecc.sha256(compressed_pubkey.toBuffer());
		const hash2 = new ripemd160().update(Buffer.from(hash1, 'hex')).digest('hex');
		const hash3 = ecc.sha256(uncompressed_pubkey.toBuffer());
		const hash4 = new ripemd160().update(Buffer.from(hash3, 'hex')).digest('hex');

		const with_prefix_compressed = '00' + hash2;
		const with_prefix_uncompressed = '00' + hash4;

		const hash5 = ecc.sha256(Buffer.from(with_prefix_compressed, 'hex'));
		const hash6 = ecc.sha256(Buffer.from(hash5, 'hex'));
		const hash7 = ecc.sha256(Buffer.from(with_prefix_uncompressed, 'hex'));
		const hash8 = ecc.sha256(Buffer.from(hash7, 'hex'));

		const binary_address_compressed = with_prefix_compressed + hash6.slice(0,8);
		const binary_address_uncompressed = with_prefix_uncompressed + hash8.slice(0,8);

		const bitcoin_address_compressed = base58.encode(Buffer.from(binary_address_compressed, 'hex'));
		const bitcoin_address_uncompressed = base58.encode(Buffer.from(binary_address_uncompressed, 'hex'));

		console.log("Success");

		var result_flag=true
		var logger = fs.createWriteStream('data\\Keypairs.txt', {
		  flags: 'a' // 'a' means appending (old data will be preserved)
		})
			line_count++;
			var write_text=line_count+'. Private Key: '+wif+'\n'+'   Public Key: '+bitcoin_address_uncompressed+'\n'
			logger.write(write_text)

  }
}

processLineByLine();