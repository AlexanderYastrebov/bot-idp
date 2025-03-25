async function challenge(params) {
    const { blockHex, difficulty } = params;

    const hashTarget = 1n << (63n - BigInt(difficulty));
    console.log("hashTarget", hashTarget.toString(16))

    const blockLen = blockHex.length / 2;
    const blockView = new DataView(new ArrayBuffer(blockLen + 8));
    for (let i = 0; i < blockLen; i++) {
        blockView.setUint8(i, parseInt(blockHex.substring(i * 2, (i + 1) * 2), 16));
    }

    let nonce = 0n;
    var hashHex;
    while (true) {
        blockView.setBigUint64(blockLen, ++nonce);

        hash = await window.crypto.subtle.digest("SHA-256", blockView.buffer);

        if (new DataView(hash).getBigUint64(0) <= hashTarget) {
            hashHex = [...new Uint8Array(hash)].map(x => x.toString(16).padStart(2, '0')).join('');
            break
        }
    }
    return { nonce: nonce, hashHex: hashHex };
}
