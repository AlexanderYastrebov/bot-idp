async function challenge(params) {
    const hashTarget = 1n << (64n - BigInt(params.difficulty));
    console.log("hashTarget", hashTarget.toString(16))

    const view = new DataView(new ArrayBuffer(16));
    view.setBigUint64(0, BigInt(params.code));

    let nonce = 0n;
    var hash;
    performance.mark("hashing-started");
    do {
        view.setBigInt64(1, ++nonce);
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
    redirectUri.searchParams.append("code", "XXX")

    // document.location = redirectUri;
}
