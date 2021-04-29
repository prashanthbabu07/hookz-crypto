package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	web "github.com/prashanthbabu07/hookzcrypto/cryptoweb"
)

func main() {
	c := make(chan struct{}, 0)
	// fmt.Println("Hello, WebAssembly!")
	// js.Global().Set("newPrint", js.FuncOf(printMessage))
	// js.Global().Set("add", js.FuncOf(addFunction))
	// js.Global().Set("formatJSON", jsonWrapper())
	js.Global().Set("newIdentityKeyPair", web.NewIdentityKeyPair())
	js.Global().Set("newSigningKeyPair", web.NewSigningKeyPair())
	js.Global().Set("sharedSecret", web.SharedSecret())
	js.Global().Set("encrypt", web.Encrypt())
	js.Global().Set("decrypt", web.Decrypt())
	<-c
}

func printMessage(this js.Value, args []js.Value) interface{} {
	callback := args[len(args)-1:][0]
	var messages [2]string
	messages[0] = args[0].String()
	messages[1] = "more"
	return js.ValueOf(callback.Invoke(js.Null(), messages))
	// message := args[0].String()
	// return "hello" + message
}

func addFunction(this js.Value, p []js.Value) interface{} {
	sum := p[0].Int() + p[1].Int()
	return js.ValueOf(sum)
}

func jsonWrapper() js.Func {
	jsonFunc := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) != 1 {
			return "Invalid no of arguments passed"
		}
		inputJSON := args[0].String()
		fmt.Printf("input %s\n", inputJSON)
		pretty, err := prettyJson(inputJSON)
		if err != nil {
			fmt.Printf("unable to convert to json %s\n", err)
			return err.Error()
		}
		return pretty
	})
	return jsonFunc
}

func prettyJson(input string) (string, error) {
	var raw interface{}
	if err := json.Unmarshal([]byte(input), &raw); err != nil {
		return "", err
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return "", err
	}
	return string(pretty), nil
}
