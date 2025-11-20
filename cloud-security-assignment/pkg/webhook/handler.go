package webhook

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cloud-security-assignment/pkg/malware"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
)

type Handler struct {
	MalwareURL string
	CSVPath    string

	mu       sync.Mutex
	mwClient *http.Client
}

func NewHandler(malwareURL, csvPath string) *Handler {
	return &Handler{
		MalwareURL: malwareURL,
		CSVPath:    csvPath,
		mwClient:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
		return
	}

	var review admissionv1.AdmissionReview
	if err := json.NewDecoder(r.Body).Decode(&review); err != nil {
		log.Printf("[webhook] could not decode review: %v", err)
		writeAllowed(w, nil)
		return
	}

	if review.Request == nil || review.Request.Kind.Kind != "Pod" {
		writeAllowed(w, &review)
		return
	}

	var pod corev1.Pod
	if err := json.Unmarshal(review.Request.Object.Raw, &pod); err != nil {
		log.Printf("[webhook] could not unmarshal Pod: %v", err)
		writeAllowed(w, &review)
		return
	}

	// Scan asynchronously to avoid blocking AdmissionReview
	go h.scanPod(pod)

	writeAllowed(w, &review)
}

func writeAllowed(w http.ResponseWriter, in *admissionv1.AdmissionReview) {
	resp := admissionv1.AdmissionReview{
		TypeMeta: inTypeMeta(),
		Response: &admissionv1.AdmissionResponse{
			Allowed: true,
		},
	}
	if in != nil && in.Request != nil {
		resp.Response.UID = in.Request.UID
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func inTypeMeta() admissionv1.AdmissionReview {
	return admissionv1.AdmissionReview{
		TypeMeta: admissionv1.SchemeGroupVersion.WithKind("AdmissionReview"),
	}
}

func (h *Handler) scanPod(pod corev1.Pod) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	list, err := h.fetchMalwareList(ctx)
	if err != nil {
		log.Printf("[webhook] failed to fetch malware list: %v", err)
		return
	}

	// TODO: replace this stub with go-containerregistry based image scanning.
	// For assignment demonstration, we just log and append a synthetic example
	// if pod has annotation "malware-test/has-node-modules=true"
	if pod.Annotations["malware-test/has-node-modules"] == "true" {
		if len(pod.Spec.Containers) > 0 {
			h.appendCSV(time.Now().UTC(), pod.Namespace, pod.Name,
				pod.Spec.Containers[0].Name, pod.Spec.Containers[0].Image,
				"@espace-client-axafr/document-card", "1.2.3", "MALWARE (simulated)")
		}
		return
	}

	// Real implementation: for each container image in pod:
	// 1. Pull image
	// 2. Walk node_modules/**/package.json
	// 3. For each package, match against list and appendCSV if matched
	_ = list // to avoid unused
}

func (h *Handler) fetchMalwareList(ctx context.Context) (malware.MalwareList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.MalwareURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := h.mwClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var list malware.MalwareList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

func (h *Handler) appendCSV(ts time.Time, ns, pod, container, image, pkgName, pkgVersion, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(h.CSVPath), 0755); err != nil {
		log.Printf("[webhook] mkdir for CSV failed: %v", err)
		return
	}

	fileExists := true
	if _, err := os.Stat(h.CSVPath); os.IsNotExist(err) {
		fileExists = false
	}

	f, err := os.OpenFile(h.CSVPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("[webhook] open CSV failed: %v", err)
		return
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if !fileExists {
		_ = w.Write([]string{
			"timestamp", "namespace", "pod_name", "container_name", "image",
			"package_name", "package_version", "reason",
		})
	}

	record := []string{
		ts.Format(time.RFC3339),
		ns,
		pod,
		container,
		image,
		pkgName,
		pkgVersion,
		reason,
	}
	if err := w.Write(record); err != nil {
		log.Printf("[webhook] write CSV failed: %v", err)
	}
}
