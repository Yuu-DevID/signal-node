'use strict';

const queueBuckets = new Map();
const GC_LIMIT = 10000;

async function processQueue(queue, cleanup) {
    let offset = 0;

    while (queue.length > 0) {
        const limit = Math.min(queue.length, GC_LIMIT);

        for (let i = offset; i < limit; i++) {
            const { task, resolve, reject } = queue[i];
            try {
                resolve(await task());
            } catch (error) {
                reject(error);
            }
        }

        if (limit < queue.length) {
            queue.splice(0, limit); // Efficiently remove processed items
            offset = 0;
        } else {
            queue.length = 0; // Clear queue when all tasks are processed
        }
    }

    cleanup();
}

module.exports = function addToQueue(bucket, task) {
    if (typeof task !== 'function') {
        throw new TypeError('The task must be a function.');
    }

    if (!queueBuckets.has(bucket)) {
        queueBuckets.set(bucket, []);
        // Start processing queue when bucket is newly created
        processQueue(queueBuckets.get(bucket), () => queueBuckets.delete(bucket));
    }

    const queue = queueBuckets.get(bucket);

    return new Promise((resolve, reject) => {
        queue.push({ task, resolve, reject });
    });
};
