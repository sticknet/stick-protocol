Pod::Spec.new do |spec|


  spec.name         = "StickProtocol"
  spec.version      = "1.1.57"
  spec.summary      = "End-to-End Encryption protocol for Social Networks based on the Signal Protocol"
  spec.swift_version = "5.0"

  spec.description  = <<-DESC
                  This is a ratcheting forward secrecy protocol that works in synchronous and asynchronous messaging environments.
                  https://github.com/WhisperSystems/libsignal-protocol-c
                   DESC

  spec.homepage     = "https://github.com/STiiiCK/stick-protocol"


  spec.license      = { :type => "MIT", :text => "The MIT License (MIT) \n Copyright (c) Omar Basem
     <founder@stiiick.com \n Permission is hereby granted, free fo charge, to any person obtaining a copy
     of this software and associated documentation files"}
 

  spec.author             = { "Omar Basem" => "founder@stiiick.com" }
 

  spec.ios.deployment_target = "12.0"
  spec.ios.vendored_frameworks = "StickProtocol.framework"


  spec.source       = { :http => "https://dl.dropboxusercontent.com/s/c6xiws1ans9u8v7/StickProtocol.zip?dl=0" }


  # spec.exclude_files = "Classes/Exclude"

  spec.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  spec.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }

  spec.dependency 'CryptoSwift'
  spec.dependency 'SignalArgon2'
  spec.dependency 'StickySignalProtocolC', '~> 1.0.0'

 

end
