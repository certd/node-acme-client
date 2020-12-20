/**
 * ACME challenge verification
 */

const Promise = require('bluebird');
const dns = Promise.promisifyAll(require('dns'));
const logger = require('./util.log.js');

const debug = logger.info;
const axios = require('./axios');


/**
 * Verify ACME HTTP challenge
 *
 * https://tools.ietf.org/html/rfc8555#section-8.3
 *
 * @param {object} authz Identifier authorization
 * @param {object} challenge Authorization challenge
 * @param {string} keyAuthorization Challenge key authorization
 * @param {string} [suffix] URL suffix
 * @returns {Promise<boolean>}
 */

async function verifyHttpChallenge(authz, challenge, keyAuthorization, suffix = `/.well-known/acme-challenge/${challenge.token}`) {
    const httpPort = axios.defaults.acmeSettings.httpChallengePort || 80;
    const challengeUrl = `http://${authz.identifier.value}:${httpPort}${suffix}`;

    logger.info(`Sending HTTP query to ${authz.identifier.value}, suffix: ${suffix}, port: ${httpPort}`);
    const resp = await axios.get(challengeUrl);
    const data = (resp.data || '').replace(/\s+$/, '');

    logger.info(`Query successful, HTTP status code: ${resp.status}`);

    if (!data || (data !== keyAuthorization)) {
        throw new Error(`Authorization not found in HTTP response from ${authz.identifier.value}`);
    }

    logger.info(`Key authorization match for ${challenge.type}/${authz.identifier.value}, ACME challenge verified`);
    return true;
}


/**
 * Verify ACME DNS challenge
 *
 * https://tools.ietf.org/html/rfc8555#section-8.4
 *
 * @param {object} authz Identifier authorization
 * @param {object} challenge Authorization challenge
 * @param {string} keyAuthorization Challenge key authorization
 * @param {string} [prefix] DNS prefix
 * @returns {Promise<boolean>}
 */

async function verifyDnsChallenge(authz, challenge, keyAuthorization, prefix = '_acme-challenge.') {
    logger.info(`Resolving DNS TXT records for ${authz.identifier.value}, prefix: ${prefix}`);
    let challengeRecord = `${prefix}${authz.identifier.value}`;

    try {
        /* Attempt CNAME record first */
        logger.info(`Checking CNAME for record ${challengeRecord}`);
        const cnameRecords = await dns.resolveCnameAsync(challengeRecord);

        if (cnameRecords.length) {
            logger.info(`CNAME found at ${challengeRecord}, new challenge record: ${cnameRecords[0]}`);
            challengeRecord = cnameRecords[0];
        }
    }
    catch (e) {
        logger.info(`No CNAME found for record ${challengeRecord}`);
    }

    /* Read TXT record */
    const result = await dns.resolveTxtAsync(challengeRecord);
    const records = [].concat(...result);

    logger.info(`Query successful, found ${records.length} DNS TXT records`);

    if (records.indexOf(keyAuthorization) === -1) {
        throw new Error(`Authorization not found in DNS TXT records for ${authz.identifier.value}`);
    }

    logger.info(`Key authorization match for ${challenge.type}/${authz.identifier.value}, ACME challenge verified`);
    return true;
}


/**
 * Export API
 */

module.exports = {
    'http-01': verifyHttpChallenge,
    'dns-01': verifyDnsChallenge
};
