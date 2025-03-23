async function challenge(params) {
    console.log(params);

    const hashTarget = 1n << (63n - BigInt(params.difficulty));
    console.log("hashTarget", hashTarget.toString(16))

    const blockLen = params.blockHex.length / 2;
    const view = new DataView(new ArrayBuffer(blockLen + 8));
    for (let i = 0; i < blockLen; i++) {
        view.setUint8(i, params.blockHex.substring(i * 2, (i + 1) * 2));
    }

    let nonce = 0n;
    var hash;
    performance.mark("hashing-started");
    do {
        view.setBigInt64(blockLen, ++nonce);
        hash = await window.crypto.subtle.digest("SHA-256", view.buffer)
            .then(value => {
                if (new DataView(value).getBigUint64(0) <= hashTarget) {
                    return [...new Uint8Array(value)].map(x => x.toString(16).padStart(2, '0')).join('');
                }
                return null;
            });
    } while (!hash);
    performance.mark("hashing-finished");

    const hashingMeasure = performance.measure(
        "hashing-duration",
        "hashing-started",
        "hashing-finished",
    );
    console.log(`Found ${hash} in ${hashingMeasure.duration} ms`);

    const redirectUri = new URL(params.redirectUri);
    redirectUri.searchParams.set("code", nonce + "." + hash + "." + params.signature)

    console.log("redirectUri", redirectUri);

    document.location = redirectUri;
}
