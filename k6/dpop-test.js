import http from 'k6/http';
import { check } from 'k6';
import encoding from 'k6/encoding';

const KEYCLOAK_URL = __ENV.KEYCLOAK_URL || 'http://localhost:8080';
const QUARKUS_URL = __ENV.QUARKUS_URL || 'http://localhost:8180';
const REALM = __ENV.REALM || 'master';
const CLIENT_ID = __ENV.CLIENT_ID || 'dpop-demo';
const USERNAME = __ENV.USERNAME || 'hakdogan';
const PASSWORD = __ENV.PASSWORD || '12345';

const TOKEN_URL = `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token`;
const USER_INFO_URL = `${QUARKUS_URL}/api/user-info`;
const LIST_USERS_URL = `${QUARKUS_URL}/api/list-users`;

export const options = {
    iterations: 1,
    vus: 1,
};

function stringToArrayBuffer(str) {
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        buf[i] = str.charCodeAt(i);
    }
    return buf.buffer;
}

function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = (Math.random() * 16) | 0;
        return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16);
    });
}

function logResponse(label, res) {
    console.log(`\n=== ${label} ===`);
    console.log(`Status : ${res.status}`);
    console.log(`Response : ${res.body}`);
}

async function createDpopProof(privateKey, publicJwk, htm, htu, accessToken) {
    const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk };
    const payload = { jti: uuid(), htm, htu, iat: Math.floor(Date.now() / 1000) };

    if (accessToken) {
        const hash = await crypto.subtle.digest('SHA-256', stringToArrayBuffer(accessToken));
        payload.ath = encoding.b64encode(hash, 'rawurl');
    }

    const headerB64 = encoding.b64encode(JSON.stringify(header), 'rawurl');
    const payloadB64 = encoding.b64encode(JSON.stringify(payload), 'rawurl');
    const signingInput = `${headerB64}.${payloadB64}`;

    const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        stringToArrayBuffer(signingInput)
    );

    return `${signingInput}.${encoding.b64encode(signature, 'rawurl')}`;
}

export default async function () {
    // Generate EC key pair
    const keyPair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
    );

    const fullJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const publicJwk = { kty: fullJwk.kty, crv: fullJwk.crv, x: fullJwk.x, y: fullJwk.y };

    // --- Get DPoP-bound access token ---
    const tokenProof = await createDpopProof(keyPair.privateKey, publicJwk, 'POST', TOKEN_URL);

    const tokenRes = http.post(TOKEN_URL, {
        grant_type: 'password',
        client_id: CLIENT_ID,
        username: USERNAME,
        password: PASSWORD,
    }, {
        headers: { 'DPoP': tokenProof },
    });

    check(tokenRes, { 'Token request succeeds': (r) => r.status === 200 });
    if (tokenRes.status !== 200) {
        console.error('Token request failed:', tokenRes.body);
        return;
    }

    const accessToken = tokenRes.json('access_token');

    // === 1. GET /user-info (Happy Path) ===
    const happyProof = await createDpopProof(keyPair.privateKey, publicJwk, 'GET', USER_INFO_URL, accessToken);

    const happyRes = http.get(USER_INFO_URL, {
        headers: {
            Authorization: `DPoP ${accessToken}`,
            DPoP: happyProof,
        },
    });

    check(happyRes, { 'GET /user-info returns 200': (r) => r.status === 200 });
    logResponse('1. GET /user-info (Happy Path)', happyRes);

    // === 2. POST /user-info ===
    const postProof = await createDpopProof(keyPair.privateKey, publicJwk, 'POST', USER_INFO_URL, accessToken);

    const postRes = http.post(USER_INFO_URL, null, {
        headers: {
            Authorization: `DPoP ${accessToken}`,
            DPoP: postProof,
        },
    });

    check(postRes, { 'POST /user-info returns 200': (r) => r.status === 200 });
    logResponse('2. POST /user-info', postRes);

    // === 3. POST /list-users ===
    const listProof = await createDpopProof(keyPair.privateKey, publicJwk, 'POST', LIST_USERS_URL, accessToken);

    const listRes = http.post(LIST_USERS_URL, null, {
        headers: {
            Authorization: `DPoP ${accessToken}`,
            DPoP: listProof,
        },
    });

    check(listRes, { 'POST /list-users returns 200': (r) => r.status === 200 });
    logResponse('3. POST /list-users', listRes);

    // === 4. Replay Attack: reuse proof from scenario 1 ===
    const replayRes = http.get(USER_INFO_URL, {
        headers: {
            Authorization: `DPoP ${accessToken}`,
            DPoP: happyProof,
        },
    });

    check(replayRes, { 'Replay attack returns 401': (r) => r.status === 401 });
    logResponse('4. GET /user-info (Replay Attack - jti reuse)', replayRes);

    // === 5. Method Mismatch: GET proof sent to POST endpoint ===
    const getProof = await createDpopProof(keyPair.privateKey, publicJwk, 'GET', USER_INFO_URL, accessToken);

    const htmRes = http.post(USER_INFO_URL, null, {
        headers: {
            Authorization: `DPoP ${accessToken}`,
            DPoP: getProof,
        },
    });

    check(htmRes, { 'htm mismatch returns 401': (r) => r.status === 401 });
    logResponse('5. POST /user-info (Method Mismatch - htm)', htmRes);

    // === 6. URL Mismatch: /user-info proof sent to /list-users ===
    const wrongUrlProof = await createDpopProof(keyPair.privateKey, publicJwk, 'POST', USER_INFO_URL, accessToken);

    const htuRes = http.post(LIST_USERS_URL, null, {
        headers: {
            Authorization: `DPoP ${accessToken}`,
            DPoP: wrongUrlProof,
        },
    });

    check(htuRes, { 'htu mismatch returns 401': (r) => r.status === 401 });
    logResponse('6. POST /list-users (URL Mismatch - htu)', htuRes);
}
