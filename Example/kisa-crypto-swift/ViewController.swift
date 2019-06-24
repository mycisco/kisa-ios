//
//  ViewController.swift
//  kisa-crypto-swift
//
//  Created by Marbean on 06/03/2018.
//  Copyright (c) 2018 Marbean. All rights reserved.
//

import UIKit
import kisa_crypto_swift


class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        
        /*
         사용자 키는 sha256 으로 해쉬 처리
         */
        let key = "1234"
        KISACrypto.seedEncrypt(key: "12345678901234567890123456789012")
//        Test().echoPrint()

    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

}

