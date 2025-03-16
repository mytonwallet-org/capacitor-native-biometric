
  Pod::Spec.new do |s|
    s.name = 'CapgoCapacitorNativeBiometric'
    s.version = '0.0.1'
    s.summary = 'This plugin gives access to the native biometric apis for android and iOS'
    s.license = 'MIT'
    s.homepage = 'https://github.com/Cap-go/capacitor-native-biometric'
    s.author = 'Martin Donadieu'
    s.source = { :git => 'https://github.com/Cap-go/capacitor-native-biometric', :tag => s.version.to_s }
    s.source_files = 'ios/Plugin/**/*.{swift,h,m,c,cc,mm,cpp}'
    s.ios.deployment_target = '14.0'
    s.dependency 'Capacitor'
  end
