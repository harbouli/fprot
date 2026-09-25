#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>

@interface RCT_EXTERN_MODULE(FprotNative, RCTEventEmitter)

RCT_EXTERN_METHOD(tcpServerListen:(double)serverId
                  host:(NSString *)host
                  port:(double)port
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(tcpServerClose:(double)serverId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(tcpConnect:(double)socketId
                  host:(NSString *)host
                  port:(double)port
                  timeoutMs:(double)timeoutMs
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(tcpWrite:(double)socketId
                  data:(NSString *)data
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(tcpDestroy:(double)socketId
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(randomBytes:(double)size)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(sha256:(NSString *)utf8Input)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(boxKeypair)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(boxSeal:(NSString *)plaintextUtf8
                                        nonceB64:(NSString *)nonceB64
                                        remotePubB64:(NSString *)remotePubB64
                                        localPrivB64:(NSString *)localPrivB64)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(boxOpen:(NSString *)ciphertextB64
                                        nonceB64:(NSString *)nonceB64
                                        remotePubB64:(NSString *)remotePubB64
                                        localPrivB64:(NSString *)localPrivB64)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signKeypair)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(signDetached:(NSString *)messageUtf8
                                        secretKey64B64:(NSString *)secretKey64B64)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(verifyDetached:(NSString *)messageUtf8
                                        signature64B64:(NSString *)signature64B64
                                        publicKey32B64:(NSString *)publicKey32B64)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(secretboxSeal:(NSString *)plaintextUtf8
                                        nonceB64:(NSString *)nonceB64
                                        key32B64:(NSString *)key32B64)

RCT_EXTERN__BLOCKING_SYNCHRONOUS_METHOD(secretboxOpen:(NSString *)ciphertextB64
                                        nonceB64:(NSString *)nonceB64
                                        key32B64:(NSString *)key32B64)

@end
