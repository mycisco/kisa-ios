# kisa-crypto-swift

[![CI Status](https://img.shields.io/travis/Marbean/kisa-crypto-swift.svg?style=flat)](https://travis-ci.org/Marbean/kisa-crypto-swift)
[![Version](https://img.shields.io/cocoapods/v/kisa-crypto-swift.svg?style=flat)](https://cocoapods.org/pods/kisa-crypto-swift)
[![License](https://img.shields.io/cocoapods/l/kisa-crypto-swift.svg?style=flat)](https://cocoapods.org/pods/kisa-crypto-swift)
[![Platform](https://img.shields.io/cocoapods/p/kisa-crypto-swift.svg?style=flat)](https://cocoapods.org/pods/kisa-crypto-swift)


# include algorithm
 - 블록암호 : SEED, HIGHT, ARIA(128/192/256) (CBC 운영모드)
 - 해시함수 : SHA-256
 - 키 유도 함수 : PBKDF2(with HMAC-SHA256)
 - 난수발생기 : CTR-DRBG(SEED/ARIA)
 - 전자서명 : KCDSA, EC-KCDSA
 
 
## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

## Requirements

## Installation

kisa-crypto-swift is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'kisa-crypto-swift'
```

## Author

Marbean, mycisco@me.com

## License

kisa-crypto-swift is available under the MIT license. See the LICENSE file for more info.
