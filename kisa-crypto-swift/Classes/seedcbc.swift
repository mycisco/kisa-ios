//import KISACrypto

public class KISACrypto {
    
    static func sha256(key: String) {
        let sha256Pointer: UnsafeMutablePointer<KISA_SHA256> = UnsafeMutablePointer<KISA_SHA256>.allocate(capacity: 1)
        KISA_SHA256_init(sha256Pointer)
        
        let data = key.data(using: .utf8, allowLossyConversion: false)
        
        KISA_SHA256_update(sha256Pointer,
                           UnsafeMutablePointer<UInt8>.allocate(capacity: data!.count),
                           UInt32(key.count))
        
        var md: UnsafeMutablePointer<UInt8> = UnsafeMutablePointer<UInt8>.allocate(capacity: 32)
        KISA_SHA256_final(sha256Pointer, md)
        debugPrint("Asd")
        debugPrint(md)
    }

    static public func seedEncrypt(key: String) {
        
        sha256(key: key)
//        let keyData = key.data(using: <#T##String.Encoding#>)
//        sha
        
    }
    
}
