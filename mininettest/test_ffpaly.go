// package mini

import (
	"fmt"
	"io"
	"os/exec"
)

// ...
func play() {

	// # start ffmpeg
	fmt.Println("what")
	ffmpeg := exec.Command("ffplay", "-f", "mp4", "-i", "pipe:")
	inpipe, err := ffmpeg.StdinPipe()
	go func(inpipe io.WriteCloser) error {
		//...
		return nil
	}(inpipe)

	if err != nil {
		panic(err)
	}
	err = ffmpeg.Start()
	if err != nil {
		panic(err)
	}
}
