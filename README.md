<h1 align="center">Stick Protocol</h1>
<p align="center">Re-Establishable Group End-to-End Encryption with Post-Compromise Security</p>

## Motivation

End-to-end encryption has become a de facto standard in messengers, especially after the outbreak of the highly secure
messaging protocol – Signal. However, this high adoption of secure end-to-end communications has been limited to
messengers, and has not yet seen a noticeable trace in social network platforms, despite the increase in users’ privacy
violations. The Stick protocol is an end-to-end encryption protocol, based on the Signal protocol, specifically designed
for social networks. The Stick protocol supports re-establishable "many-to-many" encryption sessions in an asynchronous
and multi-device setting while preserving forward secrecy and introducing backward secrecy. Performance evaluation of
the Stick protocol shows that it causes no noticeable compromise on usability or performance. The Stick protocol's
scientific foundation is 📄 <a href="https://www.sticknet.org/stick-protocol.pdf">published in IEEE</a> for those
interested in the
project’s technical and research motivations.

Stick is the protocol used in <a href="https://www.sticknet.org">Sticknet</a> - a secure social storage platform.

## Security Features

The Stick protocol benefits from the security features of the Signal protocol, and adds the following new features, or as summarized in <a target="_blank" href="https://omarbasem.com/PDFs/StickProtocolPoster.pdf">this diagram</a>:

1. <b>Re-establishable</b>: A user will be able to securely re-establish their encryption sessions when re-installing the application, or installing on a new device

2. <b>Multi Device</b>: Stick protocol provides end-to-end encryption for all of a user's devices.

3. <b>Perfect forward & backward secrecy for sharing sender keys</b>: provided by multiple pairwise sessions

4. <b>Many-to-many backward secrecy</b>: sticky sessions provides backward secrecy for group communications every a maximum of N Encryptions.

5. <b>Identity Keys self-healing</b>: A user's identity key refreshes every while to mitigate the effect of an identity key compromise

6. <b>Double-Hashing</b>: for complete hiding of the user's password, even from the service provider at login

## Technical Documentation

<a href="https://www.sticknet.org/stick-protocol">Click here<a/> for technical documentation of the Stick protocol.

## Usage Documentation

<a href="https://www.sticknet.org/stick-protocol/usage-documentation">Click here<a/> for usage documentation of the
Stick
protocol.

## Installation

The Stick protocol was implemented to be a superset to the Signal protocol making the Stick protocol logic external to
the Signal protocol. This allows the Signal protocol to be used in parallel with the Stick protocol, from just the Stick
protocol library. The stick protocol was implemented to be a fully comprehensive Android and iOS library (rather than
just a Java and C library) which can be simply dropped into a social network application, and provide E2EE using
re-establishable "sticky sessions", with as low development overhead as possible. The Stick protocol implementation is
composed of 4 libraries:

- Android Library (Gradle Package)
- iOS Library (CocoaPod Framework)
- Server Library (PIP Package)
- Client Handlers Library (NPM Package)

The Android library and the iOS library are the 2 main libraries of the Stick protocol. They have most of the logic
needed on the client-side. There is also a server library for the Stick protocol in Python. In addition, there is a
client handlers library in JavaScript which contains common handler methods needed for the Stick protocol client-side.

### Android

Gradle:

```gradle
dependencies {
   implementation 'com.github.sticknet:stick-protocol:+'
}
```

The <a href="https://github.com/sticknet/stick-protocol/blob/main/android/app/src/main/java/com/stiiick/stickprotocol/main/StickProtocol.java">
main StickProtocol java class file</a> has usage documentation as well. It includes all the methods that you would need.

### iOS

Check iOS installation [guide](./ios_installation.md).

The <a href="https://github.com/sticknet/stick-protocol/blob/main/ios/StickProtocol/StickProtocol/Main/StickProtocol.swift">
main StickProtocol Swift class file</a> has usage documentation. It includes all the methods that you would
need.

### Server

This is a server library for the Stick protocol in Python for Django. If you have a Django server you can use this
library. If not, you can easily implement your own.
The <a href="https://github.com/stickapp/stick-protocol/blob/main/server/stick_protocol/stick_protocol.py">main
StickProtocol python class<a/> includes full usage documentation needed on the server.

```
pip3 install stick-protocol-server
```

### Client Handlers

The Stick protocol implementation features a client handlers library in JavaScript. It contains common handler methods
needed for the Stick protocol client-side. These handlers may differ from one application to another. A developer is
free to write their own handlers. They can be implemented in any programming language.
The <a href="https://github.com/stickapp/stick-protocol/blob/main/client-handlers/StickProtocolHandlers.js">main
javascript class</a> contains full usage documentation.

```
yarn add stick-protocol-handlers@1.2.2
```

## Verification Tests

The Stick protocol has a set of verification tests that can be run to verify the correctness of the protocol.
These tests are written using <a href="https://verifpal.com/">Verifpal</a>, a formal verification tool for cryptographic
protocols. The tests are located under `FormalVerification` directory. After installing the Verifpal tool, the tests 
can be run as follows:
```
verifpal verify test_file.vp
```
Tests 01->04 are expected to pass, while test 05 is expected to fail.

## License

Copyright © 2018-2024 <a href="https://www.sticknet.org">Sticknet</a>

Licensed under the GPLv3: http://www.gnu.org/licenses/gpl-3.0.html
