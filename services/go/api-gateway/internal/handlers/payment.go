package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"api-gateway/internal/config"
	"api-gateway/internal/logger"
	"api-gateway/internal/metrics"
	"api-gateway/internal/redis"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// PaymentHandler handles payment routing to the Rust Payment Gateway
type PaymentHandler struct {
	config           *config.Config
	logger           *logger.FIPSLogger
	metricsCollector *metrics.FIPSMetrics
	redisClient      *redis.FIPSRedisClient
	httpClient       *http.Client
}

// PaymentRequest represents a generic payment request
type PaymentRequest struct {
	Amount      float64                `json:"amount"`
	Currency    string                 `json:"currency"`
	CustomerID  string                 `json:"customer_id"`
	Description string                 `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// PaymentResponse represents a payment response
type PaymentResponse struct {
	PaymentID     string                 `json:"payment_id"`
	Status        string                 `json:"status"`
	Provider      string                 `json:"provider"`
	Amount        float64                `json:"amount"`
	Currency      string                 `json:"currency"`
	CreatedAt     time.Time              `json:"created_at"`
	Metadata      map[string]interface{} `json:"metadata"`
	FIPSCompliant bool                   `json:"fips_compliant"`
}

// NewPaymentHandler creates a new payment handler
func NewPaymentHandler(
	cfg *config.Config,
	logger *logger.FIPSLogger,
	metricsCollector *metrics.FIPSMetrics,
	redisClient *redis.FIPSRedisClient,
) *PaymentHandler {
	return &PaymentHandler{
		config:           cfg,
		logger:           logger,
		metricsCollector: metricsCollector,
		redisClient:      redisClient,
		httpClient: &http.Client{
			Timeout: cfg.PaymentGW.Timeout,
		},
	}
}

// ProcessStripePayment processes a Stripe payment via the Rust Gateway
func (p *PaymentHandler) ProcessStripePayment(c *gin.Context) {
	var request PaymentRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"message": err.Error(),
		})
		return
	}

	response, err := p.forwardPaymentRequest("stripe", request, c)
	if err != nil {
		p.metricsCollector.RecordPaymentError("stripe", "processing_error", "HIGH")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "payment_processing_failed",
			"message": err.Error(),
		})
		return
	}

	p.metricsCollector.RecordPaymentRequest("stripe", response.Status, time.Since(time.Now()))
	c.JSON(http.StatusOK, response)
}

// ProcessPayPalPayment processes a PayPal payment via the Rust Gateway
func (p *PaymentHandler) ProcessPayPalPayment(c *gin.Context) {
	var request PaymentRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"message": err.Error(),
		})
		return
	}

	response, err := p.forwardPaymentRequest("paypal", request, c)
	if err != nil {
		p.metricsCollector.RecordPaymentError("paypal", "processing_error", "HIGH")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "payment_processing_failed",
			"message": err.Error(),
		})
		return
	}

	p.metricsCollector.RecordPaymentRequest("paypal", response.Status, time.Since(time.Now()))
	c.JSON(http.StatusOK, response)
}

// ProcessCoinbasePayment processes a Coinbase payment via the Rust Gateway
func (p *PaymentHandler) ProcessCoinbasePayment(c *gin.Context) {
	var request PaymentRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "invalid_request",
			"message": err.Error(),
		})
		return
	}

	response, err := p.forwardPaymentRequest("coinbase", request, c)
	if err != nil {
		p.metricsCollector.RecordPaymentError("coinbase", "processing_error", "HIGH")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "payment_processing_failed",
			"message": err.Error(),
		})
		return
	}

	p.metricsCollector.RecordPaymentRequest("coinbase", response.Status, time.Since(time.Now()))
	c.JSON(http.StatusOK, response)
}

// forwardPaymentRequest forwards a payment request to the Rust Payment Gateway
func (p *PaymentHandler) forwardPaymentRequest(provider string, request PaymentRequest, c *gin.Context) (*PaymentResponse, error) {
	start := time.Now()
	
	// Add payment ID
	request.Metadata = make(map[string]interface{})
	request.Metadata["payment_id"] = uuid.New().String()
	request.Metadata["source"] = "api_gateway"
	request.Metadata["fips_compliant"] = true

	// Marshal request
	requestBytes, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request to Rust Payment Gateway
	url := fmt.Sprintf("%s/payments/%s", p.config.PaymentGW.BaseURL, provider)
	req, err := http.NewRequestWithContext(c.Request.Context(), "POST", url, bytes.NewBuffer(requestBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", c.ClientIP())
	req.Header.Set("X-API-Gateway", "true")

	// Forward Authorization header if present
	if authHeader := c.GetHeader("Authorization"); authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	// Send request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("payment gateway returned status %d: %s", resp.StatusCode, string(responseBytes))
	}

	// Parse response
	var response PaymentResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	response.Provider = provider
	response.FIPSCompliant = true

	p.logger.Info("Payment request forwarded successfully",
		"provider", provider,
		"payment_id", request.Metadata["payment_id"],
		"status", response.Status,
		"duration", time.Since(start),
	)

	return &response, nil
}

// Webhook handlers (these forward to the Rust Payment Gateway)
func (p *PaymentHandler) HandleStripeWebhook(c *gin.Context) {
	p.forwardWebhook("stripe", c)
}

func (p *PaymentHandler) HandlePayPalWebhook(c *gin.Context) {
	p.forwardWebhook("paypal", c)
}

func (p *PaymentHandler) HandleCoinbaseWebhook(c *gin.Context) {
	p.forwardWebhook("coinbase", c)
}

// forwardWebhook forwards webhook requests to the Rust Payment Gateway
func (p *PaymentHandler) forwardWebhook(provider string, c *gin.Context) {
	// Read the request body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read body"})
		return
	}

	// Create request to Rust Payment Gateway
	url := fmt.Sprintf("%s/webhooks/%s", p.config.PaymentGW.BaseURL, provider)
	req, err := http.NewRequestWithContext(c.Request.Context(), "POST", url, bytes.NewBuffer(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create request"})
		return
	}

	// Forward all headers
	for name, values := range c.Request.Header {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}

	// Send request
	resp, err := p.httpClient.Do(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to forward webhook"})
		return
	}
	defer resp.Body.Close()

	// Forward response
	c.Status(resp.StatusCode)
}

// GetPaymentStatus retrieves payment status
func (p *PaymentHandler) GetPaymentStatus(c *gin.Context) {
	paymentID := c.Param("payment_id")
	
	url := fmt.Sprintf("%s/payments/status/%s", p.config.PaymentGW.BaseURL, paymentID)
	resp, err := p.httpClient.Get(url)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get status"})
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read response"})
		return
	}

	c.Data(resp.StatusCode, "application/json", body)
}

// GetPaymentHistory retrieves payment history
func (p *PaymentHandler) GetPaymentHistory(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": "payment history endpoint",
		"fips_compliant": true,
	})
}