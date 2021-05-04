<h1 align="center">Stick Protocol</h1>

<p align="center">An End-to-End Encryption Protocol Tailored for Social Network Platforms.</p>


# Motivation

End-to-end encryption has become a de facto standard in messengers, especially after the outbreak of the highly secure messaging protocol – Signal. However, this high adoption of secure end-to-end communications has been limited to messengers, and has not yet seen a noticeable trace in social network platforms. The Stick protocol is an end-to-end encryption protocol, based on the Signal protocol, specifically designed for social networks, and will be the protocol powering STiiiCK. The Stick protocol supports re-establishable "many-to-many" encryption sessions in an asynchronous and multi-device setting while preserving forward secrecy and introducing backward secrecy. Evaluation 📈 <a target="_blank" href="pages/stickProtocolEvaluation.html">results</a>of the Stick protocol shows that it causes no noticeable compromise on usability or performance.A 📄 <a href="https://omarbasem.com/PDFs/StickProtocolPaper.pdf">Scientific Paper</a> is available for those interested in the project’s technical and research motivations. You can also checkout this <a href="https://www.youtube.com/watch?v=drNPWNQG1qA">🎥 demonstration video</a>.


# Installation

The Stick protocol was implemented to be a superset to the Signal protocol making the Stick protocol logic external to the Signal protocol. This allows the Signal protocol to be used in parallel with the Stick protocol, from just the Stick protocol library. The stick protocol was implemented to be a fully comprehensive Android and iOS library (rather than just a Java and C library) which can be simply dropped into a social network application, and provide E2EE using re-establishable "sticky sessions", with as low development overhead as possible. The Stick protocol implementation is composed of 4 libraries:


- Android Library (Gradle Package)
- iOS Library (CocoaPod Framework)
- Server Library (PIP Package)
- Client Handlers Library (NPM Package)

The Android library and the iOS library are the 2 main libraries of the Stick protocol. They have most of the logic needed on the client-side. There is also a server library for the Stick protocol in Python. In addition, there is a client handlers library in JavaScript which contains
common handler methods needed for the Stick protocol client-side.

## Android

Gradle:
```gradle
dependencies {
  implementation 'com.github.STiiiCK:stick-protocol:1.1.79'
}
```

The <a href="https://github.com/STiiiCK/stick-protocol/blob/main/android/app/src/main/java/com/stiiick/stickprotocol/main/StickProtocol.java">main StickProtocol java class file</a> has full usage documentation. It includes all the methods that you would need.


## iOS

CocoaPods:
```
pod 'StickProtocol', '1.1.62'
```
The <a href="https://github.com/STiiiCK/stick-protocol/blob/main/ios/StickProtocol/StickProtocol/Main/StickProtocol.swift">main StickProtocol Swift class file</a> has full usage documentation. It includes all the methods that you would need.

## Server

This is a server library for the Stick protocol in Python for Django. If you have a Django server you can use this library. If not, you can easily implement your own. The <a href="https://github.com/STiiiCK/stick-protocol/blob/main/server/stick_protocol/stick_protocol.py">main StickProtocol python class<a/> includes full usage documentation needed on the server.
  
```
pip3 install stick-protocol-server
```

## Client Handlers

The Stick protocol implementation features a client handlers library in JavaScript. It contains
common handler methods needed for the Stick protocol client-side. These handlers may differ
from one application to another. A developer is free to write their own handlers.  They can be implemented in any programming language. The <a href="https://github.com/STiiiCK/stick-protocol/blob/main/client-handlers/StickProtocolHandlers.js">main javascript class</a> contains full usage documentation.

```
npm install stick-protocol-handlers
```

# License

Copyright 2020-2021 STiiiCK

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
