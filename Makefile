framework:
	#gomobile bind -target ios -o ./ios/frameworks/xtoolscrypto.framework github.com/prashanthbabu07/x-util-tools/lib/crypto
	gomobile bind -target ios -o ./ios/hookzcrypto.framework github.com/prashanthbabu07/hookzcrypto/crypto
	#GOOS=js GOARCH=wasm go build -o ./web/Productive.Tools.Solutions/Productive.Tools.Web.UI/wwwroot/wasm/crypto.wasm

	#gomobile bind -v  -o ./android/xtoolscrypto.aar -target=android github.com/prashanthbabu07/x-util-tools/lib/crypto
	#gomobile bind -target android -o ../../android/SuperApp.aar