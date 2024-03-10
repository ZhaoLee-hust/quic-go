package wire

import (
	"bytes"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("RDrame", func() {
	Context("when parsing", func() {
		It("accepts sample frame", func() {
			// var frame *RDFrame
			values := []byte{0x14, 0, 10, 0, 20}
			b := bytes.NewReader(values)
			frame, err := ParseRDFrame(b, protocol.VersionWhatever)
			Expect(err).ToNot(HaveOccurred())
			Expect(b.Len()).To(BeZero())
			Expect(frame.TimeThresholdMS).To(Equal(uint16(10)))
			Expect(frame.PacketThreshold).To(Equal(uint16(20)))
		})

		It("errors on EOFs", func() {
			_, err := ParsePingFrame(bytes.NewReader(nil), protocol.VersionWhatever)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when writing", func() {
		It("writes a sample frame", func() {
			b := &bytes.Buffer{}
			frame := RDFrame{10, 20}
			frame.Write(b, protocol.VersionWhatever)
			Expect(b.Bytes()).To(Equal([]byte{0x14, 0, 10, 0, 20}))
		})

		It("has the correct min length", func() {
			frame := RDFrame{}
			Expect(frame.MinLength(0)).To(Equal(protocol.ByteCount(5)))
		})
	})
})
