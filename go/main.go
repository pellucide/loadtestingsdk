package main
import  (
    "transmitapi"
    "fmt"
)
func main() {
	transmit := transmitapi.NewTransmit()
	a, b, c, d := transmit.Bind()
	fmt.Printf("\n%v, \n%v, \n%v, \n%v\n", a,b,c,d)
}
