import { Boom } from '@hapi/boom'
import { randomBytes } from 'crypto'
import { URL } from 'url'
import { promisify } from 'util'
import { proto } from '../../WAProto'
import {
    DEF_CALLBACK_PREFIX,
    DEF_TAG_PREFIX,
    INITIAL_PREKEY_COUNT,
    MIN_PREKEY_COUNT,
    NOISE_WA_HEADER
} from '../Defaults'
import { DisconnectReason, SocketConfig } from '../Types'
import {
    addTransactionCapability,
    aesEncryptCTR,
    bindWaitForConnectionUpdate,
    bytesToCrockford,
    configureSuccessfulPairing,
    Curve,
    derivePairingCodeKey,
    generateLoginNode,
    generateMdTagPrefix,
    generateRegistrationNode,
    getCodeFromWSError,
    getErrorCodeFromStreamError,
    getNextPreKeysNode,
    getPlatformId,
    makeEventBuffer,
    makeNoiseHandler,
    promiseTimeout
} from '../Utils'
import {
    assertNodeErrorFree,
    BinaryNode,
    binaryNodeToString,
    encodeBinaryNode,
    getBinaryNodeChild,
    getBinaryNodeChildren,
    jidEncode,
    S_WHATSAPP_NET
} from '../WABinary'
import { WebSocketClient } from './Client'

export const makeSocket = (config: SocketConfig) => {
    const {
        waWebSocketUrl,
        connectTimeoutMs,
        logger,
        keepAliveIntervalMs,
        browser,
        auth: authState,
        printQRInTerminal,
        defaultQueryTimeoutMs,
        transactionOpts,
        qrTimeout,
        makeSignalRepository
    } = config

    if (printQRInTerminal) {
        console.warn(
            '⚠️ The printQRInTerminal option has been deprecated. You will no longer receive QR codes in the terminal automatically. Please listen to the connection.update event yourself and handle the QR your way. You can remove this message by removing this option. This message will be removed in a future version.'
        )
    }

    const url = typeof waWebSocketUrl === 'string' ? new URL(waWebSocketUrl) : waWebSocketUrl

    if (config.mobile || url.protocol === 'tcp:') {
        throw new Boom('Mobile API is not supported anymore', { statusCode: DisconnectReason.loggedOut })
    }

    if (url.protocol === 'wss' && authState?.creds?.routingInfo) {
        url.searchParams.append('ED', authState.creds.routingInfo.toString('base64url'))
    }

    const ws = new WebSocketClient(url, config)

    ws.connect()

    const ev = makeEventBuffer(logger)
    const ephemeralKeyPair = Curve.generateKeyPair()
    const noise = makeNoiseHandler({
        keyPair: ephemeralKeyPair,
        NOISE_HEADER: NOISE_WA_HEADER,
        logger,
        routingInfo: authState?.creds?.routingInfo
    })

    const { creds } = authState
    const keys = addTransactionCapability(authState.keys, logger, transactionOpts)
    const signalRepository = makeSignalRepository({ creds, keys })

    let lastDateRecv: Date
    let epoch = 1
    let keepAliveReq: NodeJS.Timeout
    let qrTimer: NodeJS.Timeout
    let closed = false

    const uqTagId = generateMdTagPrefix()
    const generateMessageTag = () => `${uqTagId}${epoch++}`

    const sendPromise = promisify(ws.send)
    const sendRawMessage = async (data: Uint8Array | Buffer) => {
        if (!ws.isOpen) {
            throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
        }

        const bytes = noise.encodeFrame(data)
        await promiseTimeout<void>(connectTimeoutMs, async (resolve, reject) => {
            try {
                await sendPromise.call(ws, bytes)
                resolve()
            } catch (error) {
                reject(error)
            }
        })
    }

    const sendNode = (frame: BinaryNode) => {
        if (logger.level === 'trace') {
            logger.trace({ xml: binaryNodeToString(frame), msg: 'xml send' })
        }

        const buff = encodeBinaryNode(frame)
        return sendRawMessage(buff)
    }

    const onUnexpectedError = (err: Error | Boom, msg: string) => {
        logger.error({ err }, `unexpected error in '${msg}'`)
    }

    const awaitNextMessage = async <T>(sendMsg?: Uint8Array) => {
        if (!ws.isOpen) {
            throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
        }

        let onOpen: (data: T) => void
        let onClose: (err: Error) => void

        const result = promiseTimeout<T>(connectTimeoutMs, (resolve, reject) => {
            onOpen = resolve
            onClose = mapWebSocketError(reject)
            ws.on('frame', onOpen)
            ws.on('close', onClose)
            ws.on('error', onClose)
        }).finally(() => {
            ws.off('frame', onOpen)
            ws.off('close', onClose)
            ws.off('error', onClose)
        })

        if (sendMsg) {
            sendRawMessage(sendMsg).catch(onClose!)
        }

        return result
    }

    const waitForMessage = async <T>(msgId: string, timeoutMs = defaultQueryTimeoutMs) => {
        let onRecv: (json) => void
        let onErr: (err) => void
        try {
            const result = await promiseTimeout<T>(timeoutMs, (resolve, reject) => {
                onRecv = resolve
                onErr = err => {
                    reject(err || new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed }))
                }

                ws.on(`TAG:${msgId}`, onRecv)
                ws.on('close', onErr)
                ws.on('error', onErr)
            })

            return result as any
        } finally {
            ws.off(`TAG:${msgId}`, onRecv!)
            ws.off('close', onErr!)
            ws.off('error', onErr!)
        }
    }

    const query = async (node: BinaryNode, timeoutMs?: number) => {
        if (!node.attrs.id) {
            node.attrs.id = generateMessageTag()
        }

        const msgId = node.attrs.id

        const [result] = await Promise.all([waitForMessage(msgId, timeoutMs), sendNode(node)])

        if ('tag' in result) {
            assertNodeErrorFree(result)
        }

        return result
    }

    const validateConnection = async () => {
        let helloMsg: proto.IHandshakeMessage = {
            clientHello: { ephemeral: ephemeralKeyPair.public }
        }
        helloMsg = proto.HandshakeMessage.fromObject(helloMsg)

        logger.info({ browser, helloMsg }, 'connected to WA')

        const init = proto.HandshakeMessage.encode(helloMsg).finish()

        const result = await awaitNextMessage<Uint8Array>(init)
        const handshake = proto.HandshakeMessage.decode(result)

        logger.trace({ handshake }, 'handshake recv from WA')

        const keyEnc = await noise.processHandshake(handshake, creds.noiseKey)

        let node: proto.IClientPayload
        if (!creds.me) {
            node = generateRegistrationNode(creds, config)
            logger.info({ node }, 'not logged in, attempting registration...')
        } else {
            node = generateLoginNode(creds.me.id, config)
            logger.info({ node }, 'logging in...')
        }

        const payloadEnc = noise.encrypt(proto.ClientPayload.encode(node).finish())
        await sendRawMessage(
            proto.HandshakeMessage.encode({
                clientFinish: {
                    static: keyEnc,
                    payload: payloadEnc
                }
            }).finish()
        )
        noise.finishInit()
        startKeepAliveRequest()
    }

    const getAvailablePreKeysOnServer = async () => {
        const result = await query({
            tag: 'iq',
            attrs: {
                id: generateMessageTag(),
                xmlns: 'encrypt',
                type: 'get',
                to: S_WHATSAPP_NET
            },
            content: [{ tag: 'count', attrs: {} }]
        })
        const countChild = getBinaryNodeChild(result, 'count')
        return +countChild!.attrs.value
    }

    const uploadPreKeys = async (count = INITIAL_PREKEY_COUNT) => {
        await keys.transaction(async () => {
            logger.info({ count }, 'uploading pre-keys')
            const { update, node } = await getNextPreKeysNode({ creds, keys }, count)

            await query(node)
            ev.emit('creds.update', update)

            logger.info({ count }, 'uploaded pre-keys')
        })
    }

    const uploadPreKeysToServerIfRequired = async () => {
        const preKeyCount = await getAvailablePreKeysOnServer()
        logger.info(`${preKeyCount} pre-keys found on server`)
        if (preKeyCount <= MIN_PREKEY_COUNT) {
            await uploadPreKeys()
        }
    }

    const onMessageReceived = (data: Buffer) => {
        noise.decodeFrame(data, frame => {
            lastDateRecv = new Date()

            let anyTriggered = false

            anyTriggered = ws.emit('frame', frame)
            if (!(frame instanceof Uint8Array)) {
                const msgId = frame.attrs.id

                if (logger.level === 'trace') {
                    logger.trace({ xml: binaryNodeToString(frame), msg: 'recv xml' })
                }

                anyTriggered = ws.emit(`${DEF_TAG_PREFIX}${msgId}`, frame) || anyTriggered
                const l0 = frame.tag
                const l1 = frame.attrs || {}
                const l2 = Array.isArray(frame.content) ? frame.content[0]?.tag : ''

                for (const key of Object.keys(l1)) {
                    anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]},${l2}`, frame) || anyTriggered
                    anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}:${l1[key]}`, frame) || anyTriggered
                    anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},${key}`, frame) || anyTriggered
                }

                anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0},,${l2}`, frame) || anyTriggered
                anyTriggered = ws.emit(`${DEF_CALLBACK_PREFIX}${l0}`, frame) || anyTriggered

                if (!anyTriggered && logger.level === 'debug') {
                    logger.debug({ unhandled: true, msgId, fromMe: false, frame }, 'communication recv')
                }
            }
        })
    }

    const end = (error: Error | undefined) => {
        if (closed) {
            logger.trace({ trace: error?.stack }, 'connection already closed')
            return
        }

        closed = true
        logger.info({ trace: error?.stack }, error ? 'connection errored' : 'connection closed')

        clearInterval(keepAliveReq)
        clearTimeout(qrTimer)

        ws.removeAllListeners('close')
        ws.removeAllListeners('open')
        ws.removeAllListeners('message')

        if (!ws.isClosed && !ws.isClosing) {
            try {
                ws.close()
            } catch {}
        }

        ev.emit('connection.update', {
            connection: 'close',
            lastDisconnect: {
                error,
                date: new Date()
            }
        })
        ev.removeAllListeners('connection.update')
    }

    const waitForSocketOpen = async () => {
        if (ws.isOpen) {
            return
        }

        if (ws.isClosed || ws.isClosing) {
            throw new Boom('Connection Closed', { statusCode: DisconnectReason.connectionClosed })
        }

        let onOpen: () => void
        let onClose: (err: Error) => void
        await new Promise((resolve, reject) => {
            onOpen = () => resolve(undefined)
            onClose = mapWebSocketError(reject)
            ws.on('open', onOpen)
            ws.on('close', onClose)
            ws.on('error', onClose)
        }).finally(() => {
            ws.off('open', onOpen)
            ws.off('close', onClose)
            ws.off('error', onClose)
        })
    }

    const startKeepAliveRequest = () =>
        (keepAliveReq = setInterval(() => {
            if (!lastDateRecv) {
                lastDateRecv = new Date()
            }

            const diff = Date.now() - lastDateRecv.getTime()
            if (diff > keepAliveIntervalMs + 5000) {
                end(new Boom('Connection was lost', { statusCode: DisconnectReason.connectionLost }))
            } else if (ws.isOpen) {
                query({
                    tag: 'iq',
                    attrs: {
                        id: generateMessageTag(),
                        to: S_WHATSAPP_NET,
                        type: 'get',
                        xmlns: 'w:p'
                    },
                    content: [{ tag: 'ping', attrs: {} }]
                }).catch(err => {
                    logger.error({ trace: err.stack }, 'error in sending keep alive')
                })
            } else {
                logger.warn('keep alive called when WS not open')
            }
        }, keepAliveIntervalMs))

    const sendPassiveIq = (tag: 'passive' | 'active') =>
        query({
            tag: 'iq',
            attrs: {
                to: S_WHATSAPP_NET,
                xmlns: 'passive',
                type: 'set'
            },
            content: [{ tag, attrs: {} }]
        })

    const logout = async (msg?: string) => {
        const jid = authState.creds.me?.id
        if (jid) {
            await sendNode({
                tag: 'iq',
                attrs: {
                    to: S_WHATSAPP_NET,
                    type: 'set',
                    id: generateMessageTag(),
                    xmlns: 'md'
                },
                content: [
                    {
                        tag: 'remove-companion-device',
                        attrs: {
                            jid,
                            reason: 'user_initiated'
                        }
                    }
                ]
            })
        }

        end(new Boom(msg || 'Intentional Logout', { statusCode: DisconnectReason.loggedOut }))
    }

    const requestPairingCode = async (phoneNumber: string, customPairingCode?: string): Promise<string> => {
    const cleanedPhoneNumber = phoneNumber.replace(/[\s-+]/g, '')
    if (!cleanedPhoneNumber.match(/^\d+$/)) {
        throw new Boom('Invalid phone number format', { statusCode: 400 })
    }

    const pairingCode = customPairingCode ?? bytesToCrockford(randomBytes(5))
    if (pairingCode.length !== 8) {
        throw new Boom('Pairing code must be exactly 8 characters', { statusCode: 400 })
    }

    await waitForSocketOpen()

    authState.creds.pairingCode = pairingCode
    authState.creds.me = {
        id: jidEncode(cleanedPhoneNumber, 's.whatsapp.net'),
        name: '~'
    }
    ev.emit('creds.update', authState.creds)

    try {
        const iqNode: BinaryNode = {
            tag: 'iq',
            attrs: {
                to: S_WHATSAPP_NET,
                type: 'set',
                id: generateMessageTag(),
                xmlns: 'md'
            },
            content: [
                {
                    tag: 'link_code_companion_reg',
                    attrs: {
                        jid: authState.creds.me.id,
                        stage: 'companion_hello',
                        should_show_push_notification: 'true'
                    },
                    content: [
                        {
                            tag: 'link_code_pairing_wrapped_companion_ephemeral_pub',
                            attrs: {},
                            content: await generatePairingKey()
                        },
                        {
                            tag: 'companion_server_auth_key_pub',
                            attrs: {},
                            content: authState.creds.noiseKey.public
                        },
                        {
                            tag: 'companion_platform_id',
                            attrs: {},
                            content: getPlatformId(browser[1])
                        },
                        {
                            tag: 'companion_platform_display',
                            attrs: {},
                            content: `${browser[1]} (${browser[0]})`
                        },
                        {
                            tag: 'link_code_pairing_nonce',
                            attrs: {},
                            content: '0'
                        }
                    ]
                }
            ]
        }

        await sendNode(iqNode)
        logger.info({ phoneNumber: cleanedPhoneNumber, pairingCode }, 'Pairing code request sent')

        // Wait for pairing success or failure
        await new Promise<void>((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Boom('Pairing timeout', { statusCode: 408 }))
            }, 60000) // 60 seconds timeout

            const listener = (update: Partial<ConnectionState>) => {
                if (update.connection === 'open') {
                    clearTimeout(timeout)
                    ev.off('connection.update', listener)
                    resolve()
                } else if (update.connection === 'close') {
                    clearTimeout(timeout)
                    ev.off('connection.update', listener)
                    reject(new Boom('Connection closed before pairing', { statusCode: DisconnectReason.connectionClosed }))
                }
            }

            ev.on('connection.update', listener)
        })

        return pairingCode
    } catch (error) {
        logger.error({ trace: error.stack }, 'Error in requestPairingCode')
        throw new Boom('Failed to request pairing code', {
            statusCode: getCodeFromWSError(error) || DisconnectReason.connectionClosed,
            data: error
        })
    }
}

    async function generatePairingKey() {
        const salt = randomBytes(32)
        const randomIv = randomBytes(16)
        const key = await derivePairingCodeKey(authState.creds.pairingCode!, salt)
        const ciphered = aesEncryptCTR(authState.creds.pairingEphemeralKeyPair.public, key, randomIv)
        return Buffer.concat([salt, randomIv, ciphered])
    }

    const sendWAMBuffer = (wamBuffer: Buffer) => {
        return query({
            tag: 'iq',
            attrs: {
                to: S_WHATSAPP_NET,
                id: generateMessageTag(),
                xmlns: 'w:stats'
            },
            content: [
                {
                    tag: 'add',
                    attrs: {},
                    content: wamBuffer
                }
            ]
        })
    }

    ws.on('message', onMessageReceived)

    ws.on('open', async () => {
        try {
            await validateConnection()
        } catch (err) {
            logger.error({ err }, 'error in validating connection')
            end(err)
        }
    })

    ws.on('error', mapWebSocketError(end))
    ws.on('close', () => end(new Boom('Connection Terminated', { statusCode: DisconnectReason.connectionClosed })))
    ws.on('CB:xmlstreamend', () =>
        end(new Boom('Connection Terminated by Server', { statusCode: DisconnectReason.connectionClosed }))
    )
    ws.on('CB:iq,type:set,pair-device', async (stanza: BinaryNode) => {
        const iq: BinaryNode = {
            tag: 'iq',
            attrs: {
                to: S_WHATSAPP_NET,
                type: 'result',
                id: stanza.attrs.id
            }
        }
        await sendNode(iq)

        const pairDeviceNode = getBinaryNodeChild(stanza, 'pair-device')
        const refNodes = getBinaryNodeChildren(pairDeviceNode, 'ref')
        const noiseKeyB64 = Buffer.from(creds.noiseKey.public).toString('base64')
        const identityKeyB64 = Buffer.from(creds.signedIdentityKey.public).toString('base64')
        const advB64 = creds.advSecretKey

        let qrMs = qrTimeout || 60_000
        const genPairQR = () => {
            if (!ws.isOpen) {
                return
            }

            const refNode = refNodes.shift()
            if (!refNode) {
                end(new Boom('QR refs attempts ended', { statusCode: DisconnectReason.timedOut }))
                return
            }

            const ref = (refNode.content as Buffer).toString('utf-8')
            const qr = [ref, noiseKeyB64, identityKeyB64, advB64].join(',')

            ev.emit('connection.update', { qr })

            qrTimer = setTimeout(genPairQR, qrMs)
            qrMs = qrTimeout || 20_000
        }

        genPairQR()
    })
    ws.on('CB:iq,,pair-success', async (stanza: BinaryNode) => {
        logger.debug('pair success recv')
        try {
            const { reply, creds: updatedCreds } = configureSuccessfulPairing(stanza, creds)

            logger.info(
                { me: updatedCreds.me, platform: updatedCreds.platform },
                'pairing configured successfully, expect to restart the connection...'
            )

            ev.emit('creds.update', updatedCreds)
            ev.emit('connection.update', { isNewLogin: true, qr: undefined })

            await sendNode(reply)
        } catch (error) {
            logger.info({ trace: error.stack }, 'error in pairing')
            end(error)
        }
    })
    ws.on('CB:success', async (node: BinaryNode) => {
        await uploadPreKeysToServerIfRequired()
        await sendPassiveIq('active')

        logger.info('opened connection to WA')
        clearTimeout(qrTimer)

        ev.emit('creds.update', { me: { ...authState.creds.me!, lid: node.attrs.lid } })

        ev.emit('connection.update', { connection: 'open' })
    })

    ws.on('CB:stream:error', (node: BinaryNode) => {
        logger.error({ node }, 'stream errored out')

        const { reason, statusCode } = getErrorCodeFromStreamError(node)

        end(new Boom(`Stream Errored (${reason})`, { statusCode, data: node }))
    })
    ws.on('CB:failure', (node: BinaryNode) => {
        const reason = +(node.attrs.reason || 500)
        end(new Boom('Connection Failure', { statusCode: reason, data: node.attrs }))
    })

    ws.on('CB:ib,,downgrade_webclient', () => {
        end(new Boom('Multi-device beta not joined', { statusCode: DisconnectReason.multideviceMismatch }))
    })

    ws.on('CB:ib,,offline_preview', (node: BinaryNode) => {
        logger.info('offline preview received', JSON.stringify(node))
        sendNode({
            tag: 'ib',
            attrs: {},
            content: [{ tag: 'offline_batch', attrs: { count: '100' } }]
        })
    })

    ws.on('CB:ib,,edge_routing', (node: BinaryNode) => {
        const edgeRoutingNode = getBinaryNodeChild(node, 'edge_routing')
        const routingInfo = getBinaryNodeChild(edgeRoutingNode, 'routing_info')
        if (routingInfo?.content) {
            authState.creds.routingInfo = Buffer.from(routingInfo?.content as Uint8Array)
            ev.emit('creds.update', authState.creds)
        }
    })

    let didStartBuffer = false
    process.nextTick(() => {
        if (creds.me?.id) {
            ev.buffer()
            didStartBuffer = true
        }

        ev.emit('connection.update', { connection: 'connecting', receivedPendingNotifications: false, qr: undefined })
    })

    ws.on('CB:ib,,offline', (node: BinaryNode) => {
        const child = getBinaryNodeChild(node, 'offline')
        const offlineNotifs = +(child?.attrs.count || 0)

        logger.info(`handled ${offlineNotifs} offline messages/notifications`)
        if (didStartBuffer) {
            ev.flush()
            logger.trace('flushed events for initial buffer')
        }

        ev.emit('connection.update', { receivedPendingNotifications: true })
    })

    ev.on('creds.update', update => {
        const name = update.me?.name
        if (creds.me?.name !== name) {
            logger.debug({ name }, 'updated pushName')
            sendNode({
                tag: 'presence',
                attrs: { name: name! }
            }).catch(err => {
                logger.warn({ trace: err.stack }, 'error in sending presence update on name change')
            })
        }

        Object.assign(creds, update)
    })

    return {
        type: 'md' as 'md',
        ws,
        ev,
        authState: { creds, keys },
        signalRepository,
        get user() {
            return authState.creds.me
        },
        generateMessageTag,
        query,
        waitForMessage,
        waitForSocketOpen,
        sendRawMessage,
        sendNode,
        logout,
        end,
        onUnexpectedError,
        uploadPreKeys,
        uploadPreKeysToServerIfRequired,
        requestPairingCode,
        sendWAMBuffer
    }
}

function mapWebSocketError(handler: (err: Error) => void) {
    return (error: Error) => {
        handler(new Boom(`WebSocket Error (${error?.message})`, { statusCode: getCodeFromWSError(error), data: error }))
    }
}
