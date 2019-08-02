const zlib = require('zlib');
const AWS = require('aws-sdk');
const find = require('lodash.find');
const EC2 = require('aws-sdk/clients/ec2');
const jmespath = require('jmespath');

const parser = /^(\d) (\d+|\w+) (eni-\w+) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|-) (\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}|-) (\d+|-) (\d+|-) (\d+|-) (\d+|-) (\d+|-) (\d+) (\d+) (ACCEPT|REJECT|-) (OK|NODATA|SKIPDATA)/

let ec2 = null;

const listNetworkInterfaces = async () => {
    if (!ec2) { ec2 = new EC2({ region: process.env.AWS_REGION }) }
    return ec2.describeNetworkInterfaces().promise();
};

const buildEniToSecurityGroupMapping = async () => {
    let interfaces = await listNetworkInterfaces()

    let mapping = jmespath.search(interfaces,
        `NetworkInterfaces[].{
        interfaceId: NetworkInterfaceId,
        securityGroupIds: Groups[].GroupId,
        ipAddress: PrivateIpAddresses[?Primary].PrivateIpAddress
      }`);

    return Promise.resolve(mapping);
}

const extractRecords = async (records) => {
    let result = []
    let match = parser.exec(records.message)
    if (match) {
        let matched = {
            '@timestamp': new Date(),
            'version': Number(match[1]),
            'account-id': match[2],
            'interface-id': match[3],
            'srcaddr': match[4],
            'destaddr': match[5],
            'srcport': Number(match[6]),
            'dstport': Number(match[7]),
            'protocol': Number(match[8]),
            'packets': Number(match[9]),
            'bytes': Number(match[10]),
            'start': Number(match[11]),
            'end': Number(match[12]),
            'action': match[13],
            'log-status': match[14]
        }

        result.push({
            id: records.id,
            data: matched,
            error: false
        })
    } else {
        result.push({
            id: records.id,
            data: records.message,
            error: true
        })
    }

    return Promise.resolve(result)
}

const decorateRecords = async (records, mapping) => {
    for (let record of records) {
        let eniData = find(mapping, { 'interfaceId': record.data['interface-id'] });
        if (eniData) {
            record.data['security-group-ids'] = eniData.securityGroupIds;
            record.data['direction'] = (record.data['destaddr'] == eniData.ipAddress) ? 'inbound' : 'outbound';
        } else {
            console.log(`No ENI data found for interface ${record.data['interface-id']}`);
        }
        return Promise.resolve(records)
    };
}

function transformLogEvent(logEvent) {
    return Promise.all([buildEniToSecurityGroupMapping(), extractRecords(logEvent)])
        .then((results) => {
            return decorateRecords(results[1], results[0])
        })
}

function putRecordsToFirehoseStream(streamName, records, client, resolve, reject, attemptsMade, maxAttempts) {
    client.putRecordBatch({
        DeliveryStreamName: streamName,
        Records: records,
    }, (err, data) => {
        const codes = [];
        let failed = [];
        let errMsg = err;

        if (err) {
            failed = records;
        } else {
            for (let i = 0; i < data.RequestResponses.length; i++) {
                const code = data.RequestResponses[i].ErrorCode;
                if (code) {
                    codes.push(code);
                    failed.push(records[i]);
                }
            }
            errMsg = `Individual error codes: ${codes}`;
        }

        if (failed.length > 0) {
            if (attemptsMade + 1 < maxAttempts) {
                console.log('Some records failed while calling PutRecordBatch, retrying. %s', errMsg);
                putRecordsToFirehoseStream(streamName, failed, client, resolve, reject, attemptsMade + 1, maxAttempts);
            } else {
                reject(`Could not put records after ${maxAttempts} attempts. ${errMsg}`);
            }
        } else {
            resolve('');
        }
    });
}

function putRecordsToKinesisStream(streamName, records, client, resolve, reject, attemptsMade, maxAttempts) {
    client.putRecords({
        StreamName: streamName,
        Records: records,
    }, (err, data) => {
        const codes = [];
        let failed = [];
        let errMsg = err;

        if (err) {
            failed = records;
        } else {
            for (let i = 0; i < data.Records.length; i++) {
                const code = data.Records[i].ErrorCode;
                if (code) {
                    codes.push(code);
                    failed.push(records[i]);
                }
            }
            errMsg = `Individual error codes: ${codes}`;
        }

        if (failed.length > 0) {
            if (attemptsMade + 1 < maxAttempts) {
                console.log('Some records failed while calling PutRecords, retrying. %s', errMsg);
                putRecordsToKinesisStream(streamName, failed, client, resolve, reject, attemptsMade + 1, maxAttempts);
            } else {
                reject(`Could not put records after ${maxAttempts} attempts. ${errMsg}`);
            }
        } else {
            resolve('');
        }
    });
}

function createReingestionRecord(isSas, originalRecord) {
    if (isSas) {
        return {
            Data: new Buffer(originalRecord.data, 'base64'),
            PartitionKey: originalRecord.kinesisRecordMetadata.partitionKey,
        };
    } else {
        return {
            Data: new Buffer(originalRecord.data, 'base64'),
        };
    }
}


function getReingestionRecord(isSas, reIngestionRecord) {
    if (isSas) {
        return {
            Data: reIngestionRecord.Data,
            PartitionKey: reIngestionRecord.PartitionKey,
        };
    } else {
        return {
            Data: reIngestionRecord.Data,
        };
    }
}

exports.handler = (event, context, callback) => {
    Promise.all(event.records.map(r => {
        const buffer = new Buffer(r.data, 'base64');
        const decompressed = zlib.gunzipSync(buffer);
        const data = JSON.parse(decompressed);
        if (data.messageType === 'CONTROL_MESSAGE') {
            return Promise.resolve({
                recordId: r.recordId,
                result: 'Dropped',
            });
        } else if (data.messageType === 'DATA_MESSAGE') {
            const promises = data.logEvents.map(transformLogEvent);
            return Promise.all(promises)
                .then(transformed => {
                    const encoded = new Buffer(JSON.stringify(transformed[0][0], null, 2)).toString('base64');
                    return {
                        recordId: r.recordId,
                        result: 'Ok',
                        data: encoded,
                    };
                });
        } else {
            return Promise.resolve({
                recordId: r.recordId,
                result: 'ProcessingFailed',
            });
        }
    })).then(recs => {
        const isSas = Object.prototype.hasOwnProperty.call(event, 'sourceKinesisStreamArn');
        const streamARN = isSas ? event.sourceKinesisStreamArn : event.deliveryStreamArn;
        const region = streamARN.split(':')[3];
        const streamName = streamARN.split('/')[1];
        const result = { records: recs };
        let recordsToReingest = [];
        const putRecordBatches = [];
        let totalRecordsToBeReingested = 0;
        const inputDataByRecId = {};
        event.records.forEach(r => inputDataByRecId[r.recordId] = createReingestionRecord(isSas, r));

        let projectedSize = recs.filter(rec => rec.result === 'Ok')
            .map(r => r.recordId.length + r.data.length)
            .reduce((a, b) => a + b);
        // 6000000 instead of 6291456 to leave ample headroom for the stuff we didn't account for
        for (let idx = 0; idx < event.records.length && projectedSize > 6000000; idx++) {
            const rec = result.records[idx];
            if (rec.result === 'Ok') {
                totalRecordsToBeReingested++;
                recordsToReingest.push(getReingestionRecord(isSas, inputDataByRecId[rec.recordId]));
                projectedSize -= rec.data.length;
                delete rec.data;
                result.records[idx].result = 'Dropped';

                // split out the record batches into multiple groups, 500 records at max per group
                if (recordsToReingest.length === 500) {
                    putRecordBatches.push(recordsToReingest);
                    recordsToReingest = [];
                }
            }
        }

        if (recordsToReingest.length > 0) {
            putRecordBatches.push(recordsToReingest);
        }

        if (putRecordBatches.length > 0) {
            new Promise((resolve, reject) => {
                let recordsReingestedSoFar = 0;
                for (let idx = 0; idx < putRecordBatches.length; idx++) {
                    const recordBatch = putRecordBatches[idx];
                    if (isSas) {
                        const client = new AWS.Kinesis({ region: region });
                        putRecordsToKinesisStream(streamName, recordBatch, client, resolve, reject, 0, 20);
                    } else {
                        const client = new AWS.Firehose({ region: region });
                        putRecordsToFirehoseStream(streamName, recordBatch, client, resolve, reject, 0, 20);
                    }
                    recordsReingestedSoFar += recordBatch.length;
                    console.log('Reingested %s/%s records out of %s in to %s stream', recordsReingestedSoFar, totalRecordsToBeReingested, event.records.length, streamName);
                }
            }).then(
                () => {
                    console.log('Reingested all %s records out of %s in to %s stream', totalRecordsToBeReingested, event.records.length, streamName);
                    callback(null, result);
                },
                failed => {
                    console.log('Failed to reingest records. %s', failed);
                    callback(failed, null);
                });
        } else {
            console.log('No records needed to be reingested.');
            callback(null, result);
        }
    }).catch(ex => {
        console.log('Error: ', ex);
        callback(ex, null);
    });
};