//import KISACrypto

import Foundation
import CommonCrypto

public class KISACrypto {
    
    static func sha256(key: String) -> Data? {
        
        /* 초기화 */
        let sha256Pointer: UnsafeMutablePointer<KISA_SHA256> = UnsafeMutablePointer<KISA_SHA256>.allocate(capacity: 1)
        let initResult = KISA_SHA256_init(sha256Pointer)
        guard initResult == 1 else {
            DEBUG_LOG("KISA_SHA256_init 실패")
            sha256Pointer.deallocate()
            return nil
        }
        
        let updateResult = KISA_SHA256_update(sha256Pointer,
                                              key,
                                              UInt32(key.count))

        guard updateResult == 1 else {
            DEBUG_LOG("KISA_SHA256_update 실패")
            sha256Pointer.deallocate()
            return nil
        }
        
        let md = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
        let finalResult = KISA_SHA256_final(sha256Pointer, md)

        guard finalResult == 1 else {
            DEBUG_LOG("KISA_SHA256_final 실패")
            sha256Pointer.deallocate()
            md.deallocate()
            return nil
        }
        
        let data = Data(bytesNoCopy: md, count: 32, deallocator: .free)
        DEBUG_LOG(data.hexString)
        
        return data
    }
    


    static public func seedEncrypt(key: String) {
        
        guard let key = sha256(key: key) else {
            DEBUG_LOG("sha256 키 생성 실패")
            return
        }

        
    }
    
}

extension Data {
    var hexString: String {
        return self.reduce("", { $0 + String(format: "%02x", $1) })
    }
}
