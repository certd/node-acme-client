/**
 * ACME auto helper
 */

const Promise = require('bluebird');
const logger = require('./util.log.js');

const debug = logger.info;
const forge = require('./crypto/forge');

const defaultOpts = {
    csr: null,
    email: null,
    preferredChain: null,
    termsOfServiceAgreed: false,
    skipChallengeVerification: false,
    challengePriority: ['http-01', 'dns-01'],
    challengeCreateFn: async () => { throw new Error('Missing challengeCreateFn()'); },
    challengeRemoveFn: async () => { throw new Error('Missing challengeRemoveFn()'); }
};


/**
 * ACME client auto mode
 *
 * @param {AcmeClient} client ACME client
 * @param {object} userOpts Options
 * @returns {Promise<buffer>} Certificate
 */

module.exports = async function(client, userOpts) {
    const opts = Object.assign({}, defaultOpts, userOpts);
    const accountPayload = { termsOfServiceAgreed: opts.termsOfServiceAgreed };

    if (!Buffer.isBuffer(opts.csr)) {
        opts.csr = Buffer.from(opts.csr);
    }

    if (opts.email) {
        accountPayload.contact = [`mailto:${opts.email}`];
    }


    /**
     * Register account
     */

    logger.info('[auto] Checking account');

    try {
        client.getAccountUrl();
        logger.info('[auto] Account URL already exists, skipping account registration');
    }
    catch (e) {
        logger.info('[auto] Registering account');
        await client.createAccount(accountPayload);
    }


    /**
     * Parse domains from CSR
     */

    logger.info('[auto] Parsing domains from Certificate Signing Request');
    const csrDomains = await forge.readCsrDomains(opts.csr);
    const domains = [csrDomains.commonName].concat(csrDomains.altNames);

    logger.info(`[auto] Resolved ${domains.length} domains from parsing the Certificate Signing Request`);


    /**
     * Place order
     */

    logger.info('[auto] Placing new certificate order with ACME provider');
    const orderPayload = { identifiers: domains.map((d) => ({ type: 'dns', value: d })) };
    const order = await client.createOrder(orderPayload);
    const authorizations = await client.getAuthorizations(order);

    logger.info(`[auto] Placed certificate order successfully, received ${authorizations.length} identity authorizations`);


    /**
     * Resolve and satisfy challenges
     */

    logger.info('[auto] Resolving and satisfying authorization challenges');

    const challengePromises = authorizations.map(async (authz) => {
        const d = authz.identifier.value;

        /* Select challenge based on priority */
        const challenge = authz.challenges.sort((a, b) => {
            const aidx = opts.challengePriority.indexOf(a.type);
            const bidx = opts.challengePriority.indexOf(b.type);

            if (aidx === -1) return 1;
            if (bidx === -1) return -1;
            return aidx - bidx;
        }).slice(0, 1)[0];

        if (!challenge) {
            throw new Error(`Unable to select challenge for ${d}, no challenge found`);
        }

        logger.info(`[auto] [${d}] Found ${authz.challenges.length} challenges, selected type: ${challenge.type}`);

        /* Trigger challengeCreateFn() */
        logger.info(`[auto] [${d}] Trigger challengeCreateFn()`);
        const keyAuthorization = await client.getChallengeKeyAuthorization(challenge);

        let recordItem;
        try {
            recordItem = await opts.challengeCreateFn(authz, challenge, keyAuthorization);

            /* Challenge verification */
            if (opts.skipChallengeVerification === true) {
                logger.info(`[auto] [${d}] Skipping challenge verification since skipChallengeVerification=true`);
            }
            else {
                logger.info(`[auto] [${d}] Running challenge verification`);
                await client.verifyChallenge(authz, challenge);
            }

            /* Complete challenge and wait for valid status */
            logger.info(`[auto] [${d}] Completing challenge with ACME provider and waiting for valid status`);
            await client.completeChallenge(challenge);
            await client.waitForValidStatus(challenge);
        }
        finally {
            /* Trigger challengeRemoveFn(), suppress errors */
            logger.info(`[auto] [${d}] Trigger challengeRemoveFn()`);

            try {
                await opts.challengeRemoveFn(authz, challenge, keyAuthorization, recordItem);
            }
            catch (e) {
                logger.info(`[auto] [${d}] challengeRemoveFn threw error: ${e.message}`);
            }
        }
    });

    logger.info('[auto] Waiting for challenge valid status');
    try {
        await Promise.all(challengePromises);
    }
    catch (e) {
        logger.error('验证出错：', e);
        throw e;
    }


    /**
     * Finalize order and download certificate
     */

    logger.info('[auto] Finalizing order and downloading certificate');
    await client.finalizeOrder(order, opts.csr);
    return client.getCertificate(order, opts.preferredChain);
};
