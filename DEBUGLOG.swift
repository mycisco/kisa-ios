//
//  DEBUGLOG.swift
//  kisa-crypto-swift
//
//  Created by Marbran on 20/06/2019.
//

import Foundation

func DEBUG_LOG(_ msg: Any, file: String = #file, function: String = #function, line: Int = #line) {
    #if DEBUG
    let filename = file.split(separator: "/").last ?? ""
    let funcName = function.split(separator: "(").first ?? ""
    print("🥶 [\(filename) \(funcName)(\(line)) \(msg)]")
    #endif
}
