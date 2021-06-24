//
//  UPTEthereumSigner.m
//  UPTEthereumSigner
//
//  Created by josh on 10/18/17.
//  Copyright © 2017 ConsenSys AG. All rights reserved.
//

@import CoreEth;
@import Valet;
//#import <Valet/Valet.h>
#import "EthereumSigner.h"
#import "UPTEthereumSigner.h"
//#import "EthCore/CoreBitcoin+Categories.h"
#import "keccak.h"

NSString *const ReactNativeKeychainProtectionLevelNormal = @"simple";
NSString *const ReactNativeKeychainProtectionLevelICloud = @"cloud"; // icloud keychain backup
NSString *const ReactNativeKeychainProtectionLevelPromptSecureEnclave = @"prompt";
NSString *const ReactNativeKeychainProtectionLevelSinglePromptSecureEnclave = @"singleprompt";

/// @description identifiers so valet can encapsulate our keys in the keychain
NSString *const UPTPrivateKeyIdentifier = @"UportPrivateKeys";
NSString *const UPTProtectionLevelIdentifier = @"UportProtectionLevelIdentifier";
NSString *const UPTEthAddressIdentifier = @"UportEthAddressIdentifier";

/// @desctiption the key prefix to concatenate with the eth address necessary to lookup the private key
NSString *const UPTPrivateKeyLookupKeyNamePrefix = @"address-";
NSString *const UPTProtectionLevelLookupKeyNamePrefix = @"level-address-";

NSString *const UPTSignerErrorCodeLevelParamNotRecognized = @"-11";
NSString *const UPTSignerErrorCodeLevelPrivateKeyNotFound = @"-12";
NSString *const UPTSignerErrorCodeLevelSigningError = @"-14";

@implementation UPTEthereumSigner

+ (void)createKeyPairWithStorageLevel:(UPTEthKeychainProtectionLevel)protectionLevel result:(UPTEthSignerKeyPairCreationResult)result {
    BTCKey *keyPair = [[BTCKey alloc] init];
    [UPTEthereumSigner saveKey:keyPair.privateKey protectionLevel:protectionLevel result:result];
}


+ (void)signTransaction:(NSString *)ethAddress data:(NSString *)payload userPrompt:(NSString*)userPromptText  result:(UPTEthSignerTransactionSigningResult)result {
    NSData *payloadData = [[NSData alloc] initWithBase64EncodedString:payload options:0];
    [UPTEthereumSigner signTransaction:ethAddress
                   serializedTxPayload:payloadData
                               chainId:nil
                            userPrompt:userPromptText
                                result:result];
}

+ (void)signTransaction:(NSString *)ethAddress serializedTxPayload:(NSData *)payloadData chainId:(NSData *)chainId userPrompt:(NSString*)userPromptText result:(UPTEthSignerTransactionSigningResult)result {
    UPTEthKeychainProtectionLevel protectionLevel = [UPTEthereumSigner protectionLevelWithEthAddress:ethAddress];
    if (protectionLevel == UPTEthKeychainProtectionLevelNotRecognized) {
        NSError *protectionLevelError = [[NSError alloc] initWithDomain:@"UPTError" code:UPTSignerErrorCodeLevelParamNotRecognized.integerValue userInfo:@{@"message": @"protection level not found for eth address"}];
        result(nil, protectionLevelError);
        return;
    }

    BTCKey *key = [self keyPairWithEthAddress:ethAddress userPromptText:userPromptText protectionLevel:protectionLevel];
    if (key) {
        NSData *hash = [UPTEthereumSigner keccak256:payloadData];
        NSDictionary *signature = ethereumSignature(key, hash, chainId);
        if (signature) {
            result(signature, nil);
        } else {
            NSError *signingError = [[NSError alloc] initWithDomain:@"UPTError"
                                                               code:UPTSignerErrorCodeLevelSigningError.integerValue
                                                           userInfo:@{ @"message" : [NSString stringWithFormat:@"signing failed due to invalid signature components for eth address: signTransaction %@", ethAddress] }];
            result(nil, signingError);
        }
    } else {
        NSError *protectionLevelError = [[NSError alloc] initWithDomain:@"UPTError"
                                                                   code:UPTSignerErrorCodeLevelPrivateKeyNotFound.integerValue 
                                                               userInfo:@{ @"message" : @"private key not found for eth address" }];
        result(nil, protectionLevelError);
    }
}

+ (void)signJwt:(NSString *)ethAddress userPrompt:(NSString *)userPromptText data:(NSData *)payload result:(UPTEthSignerJWTSigningResult)result {
    UPTEthKeychainProtectionLevel protectionLevel = [UPTEthereumSigner protectionLevelWithEthAddress:ethAddress];
    if (protectionLevel == UPTEthKeychainProtectionLevelNotRecognized) {
        NSError *protectionLevelError = [[NSError alloc] initWithDomain:@"UPTError" 
                                                                   code:UPTSignerErrorCodeLevelParamNotRecognized.integerValue 
                                                               userInfo:@{ @"message" : @"protection level not found for eth address" }];
        result(nil, protectionLevelError);
        return;
    }

    BTCKey *key = [self keyPairWithEthAddress:ethAddress userPromptText:userPromptText protectionLevel:protectionLevel];
    if (key) {
        NSData *hash = [payload SHA256];
        NSDictionary *signature = jwtSignature(key, hash);
        if (signature) {
            result(@{ @"r" : signature[@"r"], @"s" : signature[@"s"], @"v" : @([signature[@"v"] intValue]) }, nil);
        } else {
            NSError *signingError = [[NSError alloc] initWithDomain:@"UPTError"
                                                               code:UPTSignerErrorCodeLevelSigningError.integerValue
                                                           userInfo:@{ @"message" : [NSString stringWithFormat:@"signing failed due to invalid signature components for eth address: signJwt %@", ethAddress] }];
            result(nil, signingError);
        }
    } else {
        NSError *protectionLevelError = [[NSError alloc] initWithDomain:@"UPTError" 
                                                                   code:UPTSignerErrorCodeLevelPrivateKeyNotFound.integerValue
                                                               userInfo:@{ @"message": @"private key not found for eth address" }];
        result(nil, protectionLevelError);
    }
}

+ (NSArray *)allAddresses {
    VALValet *addressKeystore = [UPTEthereumSigner ethAddressesKeystore];
    NSError *error;
    NSSet<NSString *>* keys = [addressKeystore allKeysAndReturnError:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
        return [[NSArray alloc] init];
    }
    return [keys allObjects];
}

/// @description - saves the private key and requested protection level in the keychain
///              - private key converted to nsdata without base64 encryption
+ (void)saveKey:(NSData *)privateKey protectionLevel:(UPTEthKeychainProtectionLevel)protectionLevel result:(UPTEthSignerKeyPairCreationResult)result {
    BTCKey *keyPair = [[BTCKey alloc] initWithPrivateKey:privateKey];
    NSString *ethAddress = [UPTEthereumSigner ethAddressWithPublicKey:keyPair.publicKey];
    VALValet *privateKeystore = [UPTEthereumSigner privateKeystoreWithProtectionLevel:protectionLevel];
    NSString *privateKeyLookupKeyName = [UPTEthereumSigner privateKeyLookupKeyNameWithEthAddress:ethAddress];
    NSError *error;
    [privateKeystore setObject:keyPair.privateKey forKey:privateKeyLookupKeyName error:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
    [UPTEthereumSigner saveProtectionLevel:protectionLevel withEthAddress:ethAddress];
    [UPTEthereumSigner saveEthAddress:ethAddress];
    NSString *publicKeyString = [keyPair.publicKey base64EncodedStringWithOptions:0];
    result( ethAddress, publicKeyString, nil );
}

+ (void)deleteKey:(NSString *)ethAddress result:(UPTEthSignerDeleteKeyResult)result {
    UPTEthKeychainProtectionLevel protectionLevel = [UPTEthereumSigner protectionLevelWithEthAddress:ethAddress];
    NSError *error;
    if (protectionLevel != UPTEthKeychainProtectionLevelNotRecognized) {
        VALValet *privateKeystore = [UPTEthereumSigner privateKeystoreWithProtectionLevel:protectionLevel];
        [privateKeystore removeObjectForKey:ethAddress error:&error];
        if (error != nil) {
            NSLog(@"%@", [error localizedDescription]);
        }
    }
    
    VALValet *protectionLevelsKeystore = [UPTEthereumSigner keystoreForProtectionLevels];
    [protectionLevelsKeystore removeObjectForKey:ethAddress error:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
    VALValet *addressKeystore = [UPTEthereumSigner ethAddressesKeystore];
    [addressKeystore removeObjectForKey:ethAddress error:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
    result(YES, nil);
}

#pragma mark - Private

+ (void)saveProtectionLevel:(UPTEthKeychainProtectionLevel)protectionLevel withEthAddress:(NSString *)ethAddress {
    VALValet *protectionLevelsKeystore = [UPTEthereumSigner keystoreForProtectionLevels];
    NSString *protectionLevelLookupKey = [UPTEthereumSigner protectionLevelLookupKeyNameWithEthAddress:ethAddress];
    NSString *keystoreCompatibleProtectionLevel = [UPTEthereumSigner keychainCompatibleProtectionLevel:protectionLevel];
    NSError *error;
    [protectionLevelsKeystore setString:keystoreCompatibleProtectionLevel forKey:protectionLevelLookupKey error:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
}

+ (UPTEthKeychainProtectionLevel)protectionLevelWithEthAddress:(NSString *)ethAddress {
    NSString *protectionLevelLookupKeyName = [UPTEthereumSigner protectionLevelLookupKeyNameWithEthAddress:ethAddress];
    VALValet *protectionLevelsKeystore = [UPTEthereumSigner keystoreForProtectionLevels];
    NSError *error;
    NSString *keychainSourcedProtectionLevel = [protectionLevelsKeystore stringForKey:protectionLevelLookupKeyName error:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
    return [UPTEthereumSigner protectionLevelFromKeychainSourcedProtectionLevel:keychainSourcedProtectionLevel];
}

+ (NSString *)ethAddressWithPublicKey:(NSData *)publicKey {
    NSData *strippedPublicKey = [publicKey subdataWithRange:NSMakeRange(1,[publicKey length]-1)];
    NSData *address = [[UPTEthereumSigner keccak256:strippedPublicKey] subdataWithRange:NSMakeRange(12, 20)];
    return [NSString stringWithFormat:@"0x%@", [address hex]];
}

+ (VALValet *)keystoreForProtectionLevels {
    return [VALValet valetWithIdentifier:UPTProtectionLevelIdentifier accessibility:VALAccessibilityWhenPasscodeSetThisDeviceOnly];
//    return [[VALValet alloc] initWithIdentifier:UPTProtectionLevelIdentifier accessibility:VALAccessibilityAlways];
}

+ (NSString *)privateKeyLookupKeyNameWithEthAddress:(NSString *)ethAddress {
    return [NSString stringWithFormat:@"%@%@", UPTPrivateKeyLookupKeyNamePrefix, ethAddress];
}

+ (NSString *)protectionLevelLookupKeyNameWithEthAddress:(NSString *)ethAddress {
    return [NSString stringWithFormat:@"%@%@", UPTProtectionLevelLookupKeyNamePrefix, ethAddress];
}

+ (VALValet *)ethAddressesKeystore {
    return [VALValet valetWithIdentifier:UPTEthAddressIdentifier accessibility:VALAccessibilityWhenPasscodeSetThisDeviceOnly];
}

/// @return NSString a derived version of UPTEthKeychainProtectionLevel appropriate for keychain storage
+ (NSString *)keychainCompatibleProtectionLevel:(UPTEthKeychainProtectionLevel)protectionLevel {
    return @(protectionLevel).stringValue;
}

/// @param protectionLevel sourced from the keychain. Was originally created with +(NSString *)keychainCompatibleProtectionLevel:
+ (UPTEthKeychainProtectionLevel)protectionLevelFromKeychainSourcedProtectionLevel:(NSString *)protectionLevel {
    return (UPTEthKeychainProtectionLevel)protectionLevel.integerValue;
}

+ (NSSet *)addressesFromKeystore:(UPTEthKeychainProtectionLevel)protectionLevel {
    VALValet *keystore = [UPTEthereumSigner privateKeystoreWithProtectionLevel:protectionLevel];
    NSError *error;
    NSSet<NSString *>* keySets = [keystore allKeysAndReturnError:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
    NSArray *keys = [keySets allObjects];
    NSMutableSet *addresses = [NSMutableSet new];
    for (NSString *key in keys) {
        NSString *ethAddress = [key substringFromIndex:UPTPrivateKeyLookupKeyNamePrefix.length];
        [addresses addObject:ethAddress];
    }

    return addresses;
}

+ (void)saveEthAddress:(NSString *)ethAddress {
    VALValet *addressKeystore = [UPTEthereumSigner ethAddressesKeystore];
    NSError *error;
    [addressKeystore setString:ethAddress forKey:ethAddress error:&error];
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
}

/// @param userPromptText the string to display to the user when requesting access to the secure enclave
/// @return private key as NSData
+ (NSData *)privateKeyWithEthAddress:(NSString *)ethAddress userPromptText:(NSString *)userPromptText protectionLevel:(UPTEthKeychainProtectionLevel)protectionLevel {
    VALValet *privateKeystore = [self privateKeystoreWithProtectionLevel:protectionLevel];
    NSString *privateKeyLookupKeyName = [UPTEthereumSigner privateKeyLookupKeyNameWithEthAddress:ethAddress];
    NSData *privateKey;
    NSError *error;
    switch ( protectionLevel ) {
        case UPTEthKeychainProtectionLevelNormal: {
            privateKey = [privateKeystore objectForKey:privateKeyLookupKeyName error:&error];
            break;
        }
        case UPTEthKeychainProtectionLevelICloud: {
            privateKey = [privateKeystore objectForKey:privateKeyLookupKeyName error:&error];
            break;
        }
        case UPTEthKeychainProtectionLevelPromptSecureEnclave: {
            privateKey = [(VALSecureEnclaveValet *)privateKeystore objectForKey:privateKeyLookupKeyName withPrompt:userPromptText error:&error];
//            privateKey = [(VALSecureEnclaveValet *)privateKeystore objectForKey:privateKeyLookupKeyName userPrompt:userPromptText];
            break;
        }
        case UPTEthKeychainProtectionLevelSinglePromptSecureEnclave: {
            privateKey = [(VALSinglePromptSecureEnclaveValet *)privateKeystore objectForKey:privateKeyLookupKeyName withPrompt:userPromptText error:&error];
//            privateKey = [(VALSinglePromptSecureEnclaveValet *)privateKeystore objectForKey:privateKeyLookupKeyName userPrompt:userPromptText];
            break;
        }
        case UPTEthKeychainProtectionLevelNotRecognized: {
            privateKey = nil;
            break;
        }
        default: {
            privateKey = nil;
            break;
        }
    }
    if (error != nil) {
        NSLog(@"%@", [error localizedDescription]);
    }
    return privateKey;
}
/// @param userPromptText the string to display to the user when requesting access to the secure enclave
/// @return BTCKey
+ (BTCKey *)keyPairWithEthAddress:(NSString *)ethAddress userPromptText:(NSString *)userPromptText protectionLevel:(UPTEthKeychainProtectionLevel)protectionLevel {
    NSData *privateKey = [self privateKeyWithEthAddress:ethAddress userPromptText:userPromptText protectionLevel:protectionLevel];
    if (privateKey) {
        return [[BTCKey alloc] initWithPrivateKey:privateKey];
    } else {
        return nil;
    }
}

/// @param protectionLevel indicates which private keystore to create and return
/// @return returns VALValet or valid subclass: VALSynchronizableValet, VALSecureEnclaveValet, VALSinglePromptSecureEnclaveValet
+ (VALValet *)privateKeystoreWithProtectionLevel:(UPTEthKeychainProtectionLevel)protectionLevel {
    VALValet *keystore;
    switch (protectionLevel) {
        case UPTEthKeychainProtectionLevelNormal: {
            keystore = [VALValet valetWithIdentifier:UPTPrivateKeyIdentifier accessibility:VALAccessibilityWhenUnlockedThisDeviceOnly];
            break;
        }
        case UPTEthKeychainProtectionLevelICloud: {
            keystore = [VALValet valetWithIdentifier:UPTPrivateKeyIdentifier accessibility:VALAccessibilityWhenUnlocked];
            break;
        }
        case UPTEthKeychainProtectionLevelPromptSecureEnclave: {
            keystore = (VALValet*)[VALSecureEnclaveValet valetWithIdentifier:UPTPrivateKeyIdentifier accessControl:VALSecureEnclaveAccessControlUserPresence];
            break;
        }
        case UPTEthKeychainProtectionLevelSinglePromptSecureEnclave: {
            keystore = (VALValet*)[VALSinglePromptSecureEnclaveValet valetWithIdentifier:UPTPrivateKeyIdentifier accessControl:VALSecureEnclaveAccessControlUserPresence];
            break;
        }
        case UPTEthKeychainProtectionLevelNotRecognized: {
            keystore = nil;
            break;
        }
        default: {
            keystore = nil;
            break;
        }
    }
    return keystore;
}

#pragma mark - Utils

+ (NSData *)keccak256:(NSData *)input {
    char *outputBytes = malloc(32);
    sha3_256((uint8_t *)outputBytes, 32, (uint8_t *)[input bytes], (size_t)[input length]);
    return [NSData dataWithBytesNoCopy:outputBytes length:32 freeWhenDone:YES];
}

+ (UPTEthKeychainProtectionLevel)enumStorageLevelWithStorageLevel:(NSString *)storageLevel {
    NSArray<NSString *> *storageLevels = @[ ReactNativeKeychainProtectionLevelNormal,
                                            ReactNativeKeychainProtectionLevelICloud,
                                            ReactNativeKeychainProtectionLevelPromptSecureEnclave,
                                            ReactNativeKeychainProtectionLevelSinglePromptSecureEnclave];
    return (UPTEthKeychainProtectionLevel)[storageLevels indexOfObject:storageLevel];
}

+ (NSString *)hexStringWithDataKey:(NSData *)dataPrivateKey {
    return BTCHexFromData(dataPrivateKey);
}

+ (NSData *)dataFromHexString:(NSString *)originalHexString {
    return BTCDataFromHex(originalHexString);
}

+ (NSString *)base64StringWithURLEncodedBase64String:(NSString *)URLEncodedBase64String {
    NSMutableString *characterConverted = [[[URLEncodedBase64String stringByReplacingOccurrencesOfString:@"-" withString:@"+"] stringByReplacingOccurrencesOfString:@"_" withString:@"/"] mutableCopy];
    if ( characterConverted.length % 4 != 0 ) {
        NSUInteger numEquals = 4 - characterConverted.length % 4;
        NSString *equalsPadding = [@"" stringByPaddingToLength:numEquals withString: @"=" startingAtIndex:0];
        [characterConverted appendString:equalsPadding];
    }
    
    return characterConverted;
}

+ (NSString *)URLEncodedBase64StringWithBase64String:(NSString *)base64String {
    return [[[base64String stringByReplacingOccurrencesOfString:@"+" withString:@"-"] stringByReplacingOccurrencesOfString:@"/" withString:@"_"] stringByReplacingOccurrencesOfString:@"=" withString:@""];
}

@end
