//
//  UPTEthereumSignerTests.m
//  UPTEthereumSignerTests
//
//  Created by josh on 12/05/2017.
//  Copyright (c) 2017 josh. All rights reserved.
//

@import Specta;
@import CoreEth;
@import Foundation;
#import "UPTEthereumSigner.h"

SpecBegin(UPTEthereumSigner)

describe(@"1. key creation, address retrieval", ^{
    
    it(@"1. can create keys", ^{
        [UPTEthereumSigner createKeyPairWithStorageLevel:UPTEthKeychainProtectionLevelPromptSecureEnclave result:^(NSString *ethAddress, NSString *publicKey, NSError *error) {
            NSLog(@"eth address: %@ . for public key: %@", ethAddress, publicKey);
            XCTAssertNil(error);
//            expect(error).to.beNil();
        }];
    });
    
    it(@"2. can retrieve all ethereum addresses", ^{
        NSInteger lastProtectionLevel = (NSInteger) UPTEthKeychainProtectionLevelSinglePromptSecureEnclave;
        for (NSInteger i = 0; i <= lastProtectionLevel; ++i) {
            [UPTEthereumSigner createKeyPairWithStorageLevel:(UPTEthKeychainProtectionLevel) i result:^(NSString *ethAddress, NSString *publicKey, NSError *error) {
                XCTAssertNil(error);
//                expect(error).to.beNil();
                NSLog(@"eth address: %@ . for public key: %@", ethAddress, publicKey);
            }];
        }
        
        NSArray *allAddresses = [UPTEthereumSigner allAddresses];
        XCTAssertGreaterThan(allAddresses.count, lastProtectionLevel);
//        expect(allAddresses.count).to.beGreaterThan(lastProtectionLevel);
        NSLog(@"allAddresses -> %@", allAddresses);
    });
});

describe(@"2. CoreBitcoin basic operations, fidelity", ^{
    
    it(@"3. can recreate keys from it's own private keys", ^{
        NSData *privateKey = [BTCKey new].privateKey;
        NSString *privateKeyString = [[NSString alloc] initWithData:privateKey encoding:NSUTF8StringEncoding];
        BTCKey *keyCopy = [[BTCKey alloc] initWithPrivateKey:privateKey];
        NSString *keyCopyString = [[NSString alloc] initWithData:keyCopy.privateKey encoding:NSUTF8StringEncoding];
        XCTAssertEqualObjects(privateKey, keyCopy.privateKey);
        XCTAssertEqualObjects(privateKeyString, keyCopyString);
//        expect(privateKey).to.equal(keyCopy.privateKey);
//        expect(privateKeyString).to.equal(keyCopyString);
    });
    
    it(@"4. can create valid keys from external private keys", ^{
        NSString *referencePrivateKey = @"5047c789919e943c559d8c134091d47b4642122ba0111dfa842ef6edefb48f38"; // hex string
        NSData *privateKeyData32Bytes = BTCDataFromHex(referencePrivateKey);
        NSLog(@"private key data from hex strin has num bytes -> %@", @(privateKeyData32Bytes.length));
        
        BTCKey *keyPair = [[BTCKey alloc] initWithPrivateKey:privateKeyData32Bytes];
        XCTAssertEqualObjects(privateKeyData32Bytes, keyPair.privateKey);
//        expect(privateKeyData32Bytes).to.equal(keyPair.privateKey);
        
        NSString *referencePublicKey = @"04bf42759e6d2a684ef64a8210c55bf2308e4101f78959ffa335ff045ef1e4252b1c09710281f8971b39efed7bfb61ae381ed73b9faa5a96f17e00c1a4c32796b1";
        NSString *hexPublicKeyRecreation = BTCHexFromData(keyPair.publicKey);
        XCTAssertEqualObjects(hexPublicKeyRecreation, referencePublicKey);
//        expect(hexPublicKeyRecreation).to.equal(referencePublicKey);
        
        NSString *hexPrivateKeyRecreation = BTCHexFromData(keyPair.privateKey);
        NSLog(@"privatekey reference: %@ and generated privateKey: %@", referencePrivateKey, hexPrivateKeyRecreation);
        XCTAssertEqualObjects(referencePrivateKey, hexPrivateKeyRecreation);
//        expect(referencePrivateKey).to.equal(hexPrivateKeyRecreation);
    });
    
    it(@"5. can create valid public key from external public keys", ^{
        NSString *referencePublicKey = @"04bf42759e6d2a684ef64a8210c55bf2308e4101f78959ffa335ff045ef1e4252b1c09710281f8971b39efed7bfb61ae381ed73b9faa5a96f17e00c1a4c32796b1";
        NSData *publicKeyDataBytes = BTCDataFromHex(referencePublicKey);
        NSLog(@"public key data from hex strin has num bytes -> %@", @(publicKeyDataBytes.length));
        
        BTCKey *keyPair = [[BTCKey alloc] initWithPublicKey:publicKeyDataBytes];
        XCTAssertEqualObjects(publicKeyDataBytes, keyPair.publicKey);
//        expect(publicKeyDataBytes).to.equal(keyPair.publicKey);
        
        NSString *hexPublicKeyRecreation = BTCHexFromData(keyPair.publicKey);
        NSLog(@"public key reference : %@ and generated public key : %@", referencePublicKey, hexPublicKeyRecreation);
        XCTAssertEqualObjects(referencePublicKey, hexPublicKeyRecreation);
//        expect(referencePublicKey).to.equal(hexPublicKeyRecreation);
    });
});

describe(@"3. Saving", ^{
    it(@"6. can save keys", ^{
        NSString *referencePrivateKey = @"5047c789919e943c559d8c134091d47b4642122ba0111dfa842ef6edefb48f38";
        NSString *referencePublicKey = @"BL9CdZ5tKmhO9kqCEMVb8jCOQQH3iVn/ozX/BF7x5CUrHAlxAoH4lxs57+17+2GuOB7XO5+qWpbxfgDBpMMnlrE=";
        NSString *referenceEthAddress = @"0x45c4EBd7Ffb86891BA6f9F68452F9F0815AAcD8b".lowercaseString;
        NSData *privateKeyData32Bytes = BTCDataFromHex(referencePrivateKey);
        [UPTEthereumSigner saveKey:privateKeyData32Bytes protectionLevel:UPTEthKeychainProtectionLevelPromptSecureEnclave result:^(NSString *ethAddress, NSString *publicKey, NSError *error) {
            NSLog(@"testSavingKey, created public key is -> %@ and the eth address is %@", publicKey, ethAddress);
            XCTAssertNil(error);
            XCTAssertEqualObjects(referencePublicKey, publicKey);
            XCTAssertEqualObjects(referenceEthAddress, ethAddress);
//            expect(error).to.beNil();
//            expect(referencePublicKey).to.equal(publicKey);
//            expect(referenceEthAddress).to.equal(ethAddress);
        }];
    });
});

describe(@"4. Deletion", ^{
    it(@"7. Can delete", ^{
        NSString *referencePrivateKey = @"5047c789919e943c559d8c134091d47b4642122ba0111dfa842ef6edefb48f38";
        NSData *privateKeyData = [UPTEthereumSigner dataFromHexString:referencePrivateKey];
        [UPTEthereumSigner saveKey:privateKeyData protectionLevel:UPTEthKeychainProtectionLevelNormal result:^(NSString *ethAddress, NSString *publicKey, NSError *error) {
            XCTAssertNil(error);
            [UPTEthereumSigner deleteKey:ethAddress result:^(BOOL deleted, NSError *error) {
                XCTAssertTrue(deleted);
                XCTAssertNil(error);
            }];
        }];
    });
});

describe(@"5. Signing", ^{
    it(@"8. can sign transaction", ^{
        NSString *referencePrivateKey = @"NobiRYkMf5l3Zrc6Idjln2OF4SCIMa84YldHkMvD0Vg=";
        NSString *referenceEthAddress = @"0x7f2d6bb19b6a52698725f4a292e985c51cefc315";
        NSString *rawTransaction = @"84CFC6Q7dACDL+/YlJ4gaMziLeTh6A8Vy3HvQ1ogo7N8iA3gtrOnZAAAiQq83vASNFZ4kA==";
        int vReference = 28;
        NSString *rReference = @"gJ47XvJfSjsDkTni+3D3C2NuuonHejsB4MccGjbYQSY=";
        NSString *sReference = @"OFJN/NPkEstrw39FlLutEEtnZLsUxk5CxplzAQbRiFo=";
        
        NSData *privateKeyData32Bytes = [[NSData alloc] initWithBase64EncodedString:referencePrivateKey options:0];
        NSLog(@"private key data: %@", privateKeyData32Bytes);
        [UPTEthereumSigner saveKey:privateKeyData32Bytes protectionLevel:UPTEthKeychainProtectionLevelNormal result:^(NSString *ethAddress, NSString *publicKey, NSError *error) {
            NSLog(@"testSavingKey, created public key is -> %@ and the eth address is %@", publicKey, ethAddress);
            XCTAssertNil(error);
            XCTAssertEqualObjects(ethAddress, referenceEthAddress);
//            expect(error).to.beNil();
//            expect(ethAddress).to.equal(referenceEthAddress);
        }];
        
        [UPTEthereumSigner signTransaction:referenceEthAddress data:rawTransaction userPrompt:@"signing test" result:^(NSDictionary *signature, NSError *error) {
            XCTAssertNil(error);
//            expect(error).to.beNil();
            if (!error) {
                NSLog(@"signature: %@", signature);
                XCTAssertEqualObjects(signature[@"r"], rReference);
                XCTAssertEqualObjects(signature[@"s"], sReference);
                XCTAssertEqualObjects(signature[@"v"], @(vReference));
//                expect(signature[@"r"]).to.equal(rReference);
//                expect(signature[@"s"]).to.equal(sReference);
//                expect(signature[@"v"]).to.equal(@(vReference));
            } else {
                NSLog(@"error signing transaction : %@", error);
            }
        }];
    });
    
    it(@"9. can sign JWT", ^{
        NSString *referencePrivateKey = @"278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f";
        NSString *referenceAddress = @"0xf3beac30c498d9e26865f34fcaa57dbb935b0d74";
        NSData *privateKeyData32Bytes = BTCDataFromHex(referencePrivateKey);
        
        [UPTEthereumSigner saveKey:privateKeyData32Bytes protectionLevel:UPTEthKeychainProtectionLevelNormal result:^(NSString *ethAddress, NSString *publicKey, NSError *error) {
            NSLog(@"testSavingKey, created public key is -> %@ and the eth address is %@", publicKey, ethAddress);
            XCTAssertNil(error);
            XCTAssertEqualObjects(ethAddress, referenceAddress);
//            expect(error).to.beNil();
//            expect(ethAddress).to.equal(referenceAddress);
        }];
        
        NSBundle *bundle = [NSBundle bundleForClass:[self class]];
        NSString *referenceDataPath = [bundle pathForResource:@"ReferenceData" ofType:@"plist"];
        NSArray *referenceData = [NSArray arrayWithContentsOfFile:referenceDataPath];
        for ( NSDictionary *example in referenceData ) {
            NSData *payload = [[NSData alloc] initWithBase64EncodedString:example[@"encoded"] options:0];
            [UPTEthereumSigner signJwt:referenceAddress userPrompt:@"test signing data" data:payload result:^(NSDictionary *signature, NSError *error) {
                XCTAssertNil(error);
                XCTAssertEqualObjects(signature[@"r"], example[@"r"]);
                XCTAssertEqualObjects(signature[@"s"], example[@"s"]);
                XCTAssertEqualObjects(signature[@"v"], example[@"v"]);
//                expect(error).to.beNil();
//                expect(signature[@"r"]).to.equal(example[@"r"]);
//                expect(signature[@"s"]).to.equal(example[@"s"]);
//                expect(signature[@"v"]).to.equal(example[@"v"]);

            }];
        };
    });
});


describe(@"6. Comprehensive tests", ^{
    it(@"10. can combine saving, signing transactions and signing JWTs", ^{
        NSBundle *bundle = [NSBundle bundleForClass:[self class]];
        NSString *keyPairsPath = [bundle pathForResource:@"KeyPairsTestData" ofType:@"plist"];
        NSArray *keyPairs = [NSArray arrayWithContentsOfFile:keyPairsPath];
        NSString *txData = @"9oCFC6Q7dACDL+/YlJ4gaMziLeTh6A8Vy3HvQ1ogo7N8iA3gtrOnZAAAiQq83vASNFZ4kByAgA==";
        NSData *jwtData = [[NSData alloc] initWithBase64EncodedString:@"ZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKRlV6STFOa3NpZlEuZXlKcGMzTWlPaUl6TkhkcWMzaDNkbVIxWVc1dk4wNUdRemgxYWs1S2JrWnFZbUZqWjFsbFYwRTRiU0lzSW1saGRDSTZNVFE0TlRNeU1URXpNeXdpWTJ4aGFXMXpJanA3SW01aGJXVWlPaUpDYjJJaWZTd2laWGh3SWpveE5EZzFOREEzTlRNemZR" options:0];
        for (NSDictionary *kp in keyPairs) {
            NSData *privateKeyData32Bytes = BTCDataFromHex(kp[@"privateKey"]);
            XCTAssertEqual(privateKeyData32Bytes.length, 32);
//            expect(privateKeyData32Bytes.length).to.equal(32);
            BTCKey *keyPair = [[BTCKey alloc] initWithPrivateKey:privateKeyData32Bytes];
//            expect(privateKeyData32Bytes).to.equal(keyPair.privateKey);
            XCTAssertEqualObjects(privateKeyData32Bytes, keyPair.privateKey);
            
            NSString *hexPublicKeyRecreation = BTCHexFromData(keyPair.publicKey);
            XCTAssertEqualObjects(hexPublicKeyRecreation, kp[@"publicKey"]);
//            expect(hexPublicKeyRecreation).to.equal(kp[@"publicKey"]);
            
            NSString *ethAddress = [UPTEthereumSigner ethAddressWithPublicKey:keyPair.publicKey];
            XCTAssertEqualObjects(ethAddress, kp[@"address"]);
//            expect(ethAddress).to.equal(kp[@"address"]);
            
            NSString *hexPrivateKeyRecreation = BTCHexFromData(keyPair.privateKey);
            XCTAssertEqualObjects(hexPrivateKeyRecreation, kp[@"privateKey"]);
//            expect(hexPrivateKeyRecreation).to.equal(kp[@"privateKey"]);
            
            [UPTEthereumSigner saveKey:privateKeyData32Bytes protectionLevel:UPTEthKeychainProtectionLevelNormal result:^(NSString *ethAddress, NSString *publicKey, NSError *error) {
                XCTAssertNil(error);
//                expect(error).to.beNil();
                if (!error) {
                    XCTAssertEqualObjects(ethAddress, kp[@"address"]);
//                    expect(ethAddress).to.equal(kp[@"address"]);
                    NSString *refPublicKey = [BTCDataFromHex(kp[@"publicKey"]) base64EncodedStringWithOptions:0];
                    XCTAssertEqualObjects(publicKey, refPublicKey);
//                    expect(publicKey).to.equal(refPublicKey);
                    NSString *transaction = kp[@"address"];
                    [UPTEthereumSigner signTransaction:transaction data:txData userPrompt:@"signing test" result:^(NSDictionary *signature, NSError *error) {
                        XCTAssertNil(error);
//                        expect(error).to.beNil();
                        if (!error) {
                            XCTAssertEqualObjects(signature[@"r"], kp[@"txsig"][@"r"]);
                            XCTAssertEqualObjects(signature[@"s"], kp[@"txsig"][@"s"]);
                            XCTAssertEqualObjects(signature[@"v"], kp[@"txsig"][@"v"]);
//                            expect(signature[@"r"]).to.equal(kp[@"txsig"][@"r"]);
//                            expect(signature[@"s"]).to.equal(kp[@"txsig"][@"s"]);
//                            expect(signature[@"v"]).to.equal(kp[@"txsig"][@"v"]);
                            NSString *jwtAddress = kp[@"address"];
                            [UPTEthereumSigner signJwt:jwtAddress userPrompt:@"test signing data" data:jwtData result:^(NSDictionary *signature, NSError *error)
                            {
                                NSString *jwtSigEncoded = [UPTEthereumSigner base64StringWithURLEncodedBase64String:kp[@"jwtsig"]];
                                NSData *jwtSigData = [[NSData alloc] initWithBase64EncodedString:jwtSigEncoded options:0];
 
                                NSData* rData = [jwtSigData subdataWithRange:NSMakeRange(0, 32)];
                                NSData* sData = [jwtSigData subdataWithRange:NSMakeRange(32, 32)];
                                
                                NSString *rString = [rData base64EncodedStringWithOptions:0];
                                NSString *sString = [sData base64EncodedStringWithOptions:0];
                                XCTAssertNil(error);
                                XCTAssertEqualObjects(signature[@"r"], rString);
                                XCTAssertEqualObjects(signature[@"s"], sString);
//                                expect(error).to.beNil();
//                                expect(signature[@"r"]).to.equal(rString);
//                                expect(signature[@"s"]).to.equal(sString);
                                //expect(signature[@"v"]).to.equal(kp[@"jwtsig"][@"v"]);
                            }];
                        }
                    }];
                }
            }];
        }
    });
});


SpecEnd


