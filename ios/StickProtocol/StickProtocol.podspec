Pod::Spec.new do |spec|


  spec.name         = "StickProtocol"
  spec.version      = "1.2.4"
  spec.summary      = "End-to-End Encryption Protocol Tailored For Social Network Platforms"
  spec.swift_version = "5.0"

  spec.description  = <<-DESC
                  End-to-End Encryption (E2EE) has become a de facto standard in messengers, especially after the development of the secure messaging protocol – Signal. However, the adoption of E2EE has been limited to messengers, and has not yet seen a noticeable trace in social networks, despite the increase in users’ privacy violations. The Stick protocol is an E2EE protocol, based on the Signal protocol, specifically designed for social networks. The Stick Protocol is the first of its kind to support re-establishable encryption sessions in an asynchronous and multi-device setting while preserving forward secrecy and introducing backward secrecy.
                   DESC

  spec.homepage     = "https://github.com/sticknet/stick-protocol"


  spec.license      = { :type => "GPLv3", :text => "Copyright © 2018-2023 StickNet"}


  spec.author             = { "Omar Basem" => "founder@stiiick.com" }


  spec.ios.deployment_target = "12.0"

  spec.source           = { :git => 'https://github.com/sticknet/stick-protocol.git', :tag => spec.version.to_s }


  spec.source_files = 'ios/StickProtocol/Classes/**/*'


  # spec.exclude_files = "Classes/Exclude"

  # spec.pod_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  # spec.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }

  spec.dependency 'CryptoSwift'
  spec.dependency 'SignalArgon2'
  spec.dependency 'StickySignalProtocolC', '~> 1.0.0'



end
