package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"os"
	"time"

	"github.com/pion/interceptor"
	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v3"
	"github.com/pion/webrtc/v3/pkg/media"
)

var (
	mode    = flag.String("mode", "client", "Mode: client or server")
	addr    = flag.String("addr", "127.0.0.1:3000", "Address to listen on or connect to")
	restart = flag.Bool("restart", false, "Exercise remote-initiated ICE restart after connect")
	codec   = flag.String("codec", "VP8", "Video codec for the outgoing track (VP8 or VP9)")
)

// newAPIWithGCC builds an API whose media engine registers default codecs and
// whose interceptor registry mimics a Chrome-like TWCC peer: outgoing RTP is
// stamped with transport-cc sequence numbers and inbound streams get TWCC
// feedback generated back to the sender.
func newAPIWithGCC() (*webrtc.API, error) {
	m := &webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return nil, err
	}
	i := &interceptor.Registry{}

	// Official one-stop configuration: stamp outgoing RTP with transport-cc
	// sequence numbers and generate TWCC feedback for inbound streams.
	if err := webrtc.ConfigureTWCCHeaderExtensionSender(m, i); err != nil {
		return nil, err
	}
	if err := webrtc.ConfigureTWCCSender(m, i); err != nil {
		return nil, err
	}

	se := webrtc.SettingEngine{}
	if os.Getenv("PION_LOG") != "" {
		lf := logging.NewDefaultLoggerFactory()
		lf.DefaultLogLevel = logging.LogLevelDebug
		lf.ScopeLevels = map[string]logging.LogLevel{
			"interceptor": logging.LogLevelTrace,
		}
		se.LoggerFactory = lf
	}
	return webrtc.NewAPI(webrtc.WithMediaEngine(m), webrtc.WithInterceptorRegistry(i), webrtc.WithSettingEngine(se)), nil
}

type OfferRequest struct {
	Sdp  string `json:"sdp"`
	Type string `json:"type"`
}

type OfferResponse struct {
	Sdp  string `json:"sdp"`
	Type string `json:"type"`
}

func main() {
	flag.Parse()

	if *mode == "server" {
		runServer()
	} else {
		runClient()
	}
}

func runServer() {
	http.HandleFunc("/offer", func(w http.ResponseWriter, r *http.Request) {
		var req OfferRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		for _, line := range strings.Split(req.Sdp, "\n") {
			if strings.Contains(line, "extmap") || strings.Contains(line, "transport-cc") {
				log.Printf("OFFER-SDP: %s", strings.TrimSpace(line))
			}
		}

		api, err := newAPIWithGCC()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		pc, err := api.NewPeerConnection(webrtc.Configuration{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Handle DataChannel
		pc.OnDataChannel(func(d *webrtc.DataChannel) {
			log.Printf("New DataChannel %s %d\n", d.Label(), d.ID())
			d.OnOpen(func() {
				log.Printf("DataChannel %s open\n", d.Label())
			})
			d.OnMessage(func(msg webrtc.DataChannelMessage) {
				log.Printf("Message from DataChannel '%s': '%s'\n", d.Label(), string(msg.Data))
				// Echo
				d.Send(msg.Data)
			})
		})

		// Handle Track
		pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
			log.Printf("Track has started, of type %d: %s \n", track.PayloadType(), track.Codec().MimeType)
			buf := make([]byte, 1500)
			n := 0
			for {
				i, _, err := track.Read(buf)
				if err != nil {
					return
				}
				n++
				if n <= 2 {
					var h rtp.Header
					if _, uerr := h.Unmarshal(buf[:i]); uerr == nil && h.Extension {
						ids := h.GetExtensionIDs()
						exts := make([]string, 0, len(ids))
						for _, id := range ids {
							if p := h.GetExtension(id); p != nil {
								exts = append(exts, fmt.Sprintf("id=%d len=%d data=% x", id, len(p), p))
							} else {
								exts = append(exts, fmt.Sprintf("id=%d <unreadable>", id))
							}
						}
						log.Printf("GCC-RECV ext: %s", strings.Join(exts, "; "))
					} else if uerr != nil {
						log.Printf("GCC-RECV header unmarshal err: %v", uerr)
					}
				}
			}
		})

		// Set Remote Description
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  req.Sdp,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Create Answer
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Gather Candidates
		gatherComplete := webrtc.GatheringCompletePromise(pc)
		if err := pc.SetLocalDescription(answer); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		<-gatherComplete

		for _, line := range strings.Split(pc.LocalDescription().SDP, "\n") {
			if strings.Contains(line, "extmap") || strings.Contains(line, "sendrecv") || strings.Contains(line, "sendonly") || strings.Contains(line, "recvonly") || strings.HasPrefix(line, "m=") {
				log.Printf("ANSWER-SDP: %s", strings.TrimSpace(line))
			}
		}

		resp := OfferResponse{
			Sdp:  pc.LocalDescription().SDP,
			Type: "answer",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	log.Printf("Listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

// doIceRestart asks the rustrtc peer to restart ICE on the *established*
// session, applies the resulting restart offer (pion detects the changed
// ice-ufrag/ice-pwd and restarts its own side), and posts the answer back.
func doIceRestart(pc *webrtc.PeerConnection) error {
	resp, err := http.Post("http://"+*addr+"/restart", "application/json", bytes.NewBuffer(nil))
	if err != nil {
		return fmt.Errorf("POST /restart: %w", err)
	}
	defer resp.Body.Close()

	var offerResp OfferResponse
	if err := json.NewDecoder(resp.Body).Decode(&offerResp); err != nil {
		return fmt.Errorf("decode restart offer: %w", err)
	}

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer,
		SDP:  offerResp.Sdp,
	}); err != nil {
		return fmt.Errorf("set remote (restart offer): %w", err)
	}

	answer, err := pc.CreateAnswer(nil)
	if err != nil {
		return fmt.Errorf("create answer after restart: %w", err)
	}
	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(answer); err != nil {
		return fmt.Errorf("set local (restart answer): %w", err)
	}
	<-gatherComplete

	body, _ := json.Marshal(OfferRequest{Sdp: pc.LocalDescription().SDP, Type: "answer"})
	resp2, err := http.Post("http://"+*addr+"/answer", "application/json", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("POST /answer: %w", err)
	}
	defer resp2.Body.Close()
	return nil
}

func runClient() {
	api, err := newAPIWithGCC()
	if err != nil {
		log.Fatal(err)
	}
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		log.Fatal(err)
	}

	// Create DataChannel
	dc, err := pc.CreateDataChannel("data", nil)
	if err != nil {
		log.Fatal(err)
	}

	dc.OnOpen(func() {
		log.Printf("DataChannel %s open\n", dc.Label())
		ticker := time.NewTicker(time.Second)
		count := 0
		restartDone := false
		for range ticker.C {
			count++
			if count > 12 {
				log.Println("SUCCESS: Client finished")
				os.Exit(0)
			}
			if *restart && count == 4 && !restartDone {
				restartDone = true
				go func() {
					if err := doIceRestart(pc); err != nil {
						log.Printf("ICE restart failed: %v", err)
						os.Exit(1)
					}
					log.Println("ICE restart signal exchange complete")
				}()
			}
			msg := fmt.Sprintf("Ping from Pion %s", time.Now().Format(time.RFC3339))
			log.Printf("Sending '%s'\n", msg)
			if err := dc.SendText(msg); err != nil {
				log.Println("Send error:", err)
				os.Exit(1)
			}
		}
	})

	dc.OnMessage(func(msg webrtc.DataChannelMessage) {
		log.Printf("Received '%s'\n", string(msg.Data))
	})

	// Create Video Track
	mimeType := webrtc.MimeTypeVP8
	if *codec == "VP9" {
		mimeType = webrtc.MimeTypeVP9
	}
	videoTrack, err := webrtc.NewTrackLocalStaticSample(webrtc.RTPCodecCapability{MimeType: mimeType}, "video", "pion")
	if err != nil {
		log.Fatal(err)
	}
	if _, err = pc.AddTrack(videoTrack); err != nil {
		log.Fatal(err)
	}

	// Log inbound media so interop tests can verify the reverse direction.
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		log.Printf("GCC-RECV track started mime=%s pt=%d", track.Codec().MimeType, track.PayloadType())
		for _, ext := range receiver.GetParameters().HeaderExtensions {
			log.Printf("GCC-RECV negotiated ext id=%d uri=%s", ext.ID, ext.URI)
		}
		buf := make([]byte, 1500)
		n := 0
		for {
			i, _, err := track.Read(buf)
			if err != nil {
				return
			}
			n++
			if n == 50 {
				log.Printf("GCC-RECV-OK 50+ packets mime=%s", track.Codec().MimeType)
			}
			_ = i
		}
	})

	go func() {
		for {
			time.Sleep(time.Millisecond * 33)
			// Send dummy video packet
			if err := videoTrack.WriteSample(media.Sample{Data: []byte{0x00, 0x00, 0x00, 0x00}, Duration: time.Millisecond * 33}); err != nil {
				log.Printf("WriteSample error: %v", err)
				return
			}
		}
	}()

	// Create Offer
	offer, err := pc.CreateOffer(nil)
	if err != nil {
		log.Fatal(err)
	}

	gatherComplete := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		log.Fatal(err)
	}
	<-gatherComplete

	// Send Offer
	req := OfferRequest{
		Sdp:  pc.LocalDescription().SDP,
		Type: "offer",
	}
	body, _ := json.Marshal(req)

	resp, err := http.Post("http://"+*addr+"/offer", "application/json", bytes.NewBuffer(body))
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	var answerResp OfferResponse
	if err := json.NewDecoder(resp.Body).Decode(&answerResp); err != nil {
		log.Fatal(err)
	}

	if err := pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  answerResp.Sdp,
	}); err != nil {
		log.Fatal(err)
	}

	select {}
}
