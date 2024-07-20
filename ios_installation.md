# iOS installation guide

Xcode version 14 and above have problems compiling some of the internal libraries of the Stick Protocol when installed
as a pod framework. Instead, follow the below steps to add the Stick Protocol into your iOS project.

1. Clone the Stick Protocol repository (outside of your project directory):

```
git clone git@github.com:sticknet/stick-protocol.git
```

2. Drag and drop the directory `stick-protocol/ios/StickProtocol/StickProtocol` into your Xcode project.
   Check "Copy items if needed", and "Create groups", and yous app's main target and other necessary targets.

3. Add the following to your Podfile and then run `pod install`:

```
use_frameworks! :linkage => :static

pre_install do |installer|
  Pod::Installer::Xcode::TargetValidator.send(:define_method, :verify_no_static_framework_transitive_dependencies) {}
  installer.pod_targets.each do |pod|
    if pod.name.eql?('YapDatabase')
      def pod.build_type;
         Pod::BuildType.static_library # >= 1.9
      end
    end
  end
end

pod 'SimpleKeychain', '1.1.0'
pod 'StickySignalProtocolC', '1.0.2'
pod 'SignalArgon2'
pod 'CryptoSwift'
pod 'SQLCipher', ">= 4.0.1", :modular_headers => true
pod 'YapDatabase/SQLCipher', :git => 'https://github.com/signalapp/YapDatabase.git', branch: 'signal-release', :modular_headers => true
pod 'Mantle', :modular_headers => true
```

4. Copy the `stick-protocol/ios/StickProtocol/DatabaseSetup` directory into your project.

5. Add the following to your bridging header:

```
#import <YapDatabase/YapDatabase.h>
#import <CommonCrypto/CommonHMAC.h>
#import "DatabaseSetup.h"
#import "CommonCryptoProvider.h"
#import "SignalAddress.h"
#import "SignalCiphertext.h"
#import "IdentityKeyPair.h"
#import "KeyPair.h"
#import "PreKey.h"
#import "PreKeyBundle.h"
#import "PreKeyMessage.h"
#import "SignalMessage.h"
#import "Serializable.h"
#import "SPSignedPreKey.h"
#import "SignalContext.h"
#import "KeyHelper.h"
#import "SessionBuilder.h"
#import "SessionCipher.h"
#import "IdentityKeyStore.h"
#import "PreKeyStore.h"
#import "SenderKeyStore.h"
#import "SessionStore.h"
#import "SignedPreKeyStore.h"
#import "SignalStorage.h"
#import "SignalError.h"
#import "SPIdentity.h"
#import "SPIdentityKey.h"
#import "SPPreKey.h"
#import "SignedPreKey.h"
#import "SPSignalSession.h"
#import "SPSenderKey.h"
#import "SenderKeyDistributionMessage.h"
#import "SenderKeyName.h"
#import "GroupCipher.h"
#import "GroupSessionBuilder.h"
#import "SenderKeyRecord.h"
#import "FileCrypto.h"
#import "argon2.h"
```

6. Add the following to your AppDelegate.mm file:

```
#import "DatabaseSetup.h"
#import <YapDatabase/YapDatabase.h>
.
.
.
@synthesize database = database;

- (id)init
{
  if ((self = [super init]))
  {
    TheAppDelegate = self;
  }
  return self;
}

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
  database = [DatabaseSetup setupDatabaseWithBundleId:[[NSBundle mainBundle] bundleIdentifier]];
  .....
```

Now your app should compile and run successfully, and you should be able to follow
the <a href="https://www.sticknet.org/stick-protocol/usage-documentation">usage documentation</a>.,
